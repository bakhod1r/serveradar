package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
	"github.com/bakhod1r/serveradar/internal/infrastructure/redact"
)

func init() {
	register(Collector{Name: "postgres", Title: "PostgreSQL Inspection", Profiles: everywhere,
		Depends: []string{"databases", "docker", "ports"}, Collect: collectPostgres})
}

// pgQuerier runs one fixed, read-only SQL statement returning a single JSON value.
type pgQuerier interface {
	QueryJSON(ctx context.Context, db, sql string) (string, error)
	Close()
}

// --- psql-based (local unix socket as OS user, or docker exec) ---

type psqlQuerier struct{ argv []string }

func (q psqlQuerier) QueryJSON(ctx context.Context, db, sql string) (string, error) {
	wrapped := "BEGIN READ ONLY; SET LOCAL statement_timeout = 5000; SET LOCAL lock_timeout = 1000; " + sql + "; COMMIT;"
	args := append(append([]string{}, q.argv[1:]...), "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", wrapped)
	out, err := execx.Run(ctx, 10*time.Second, q.argv[0], args...)
	if err != nil {
		return "", fmt.Errorf("%s", firstLine(redact.Text(err.Error())))
	}
	return strings.TrimSpace(out), nil
}
func (psqlQuerier) Close() {}

// --- pgx DSN-based ---

type pgxQuerier struct {
	dsn   string
	conns map[string]*pgx.Conn
}

func (q *pgxQuerier) conn(ctx context.Context, db string) (*pgx.Conn, error) {
	if c, ok := q.conns[db]; ok {
		return c, nil
	}
	cfg, err := pgx.ParseConfig(q.dsn)
	if err != nil {
		return nil, fmt.Errorf("bad DSN: %s", redact.Text(err.Error()))
	}
	if db != "" {
		cfg.Database = db
	}
	cfg.ConnectTimeout = 5 * time.Second
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.RuntimeParams["statement_timeout"] = "5000"
	cfg.RuntimeParams["lock_timeout"] = "1000"
	cfg.RuntimeParams["application_name"] = "serveradar"
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("%s", redact.Text(err.Error()))
	}
	q.conns[db] = c
	return c, nil
}

func (q *pgxQuerier) QueryJSON(ctx context.Context, db, sql string) (string, error) {
	c, err := q.conn(ctx, db)
	if err != nil {
		return "", err
	}
	var s *string
	if err := c.QueryRow(ctx, sql).Scan(&s); err != nil {
		return "", fmt.Errorf("%s", redact.Text(err.Error()))
	}
	if s == nil {
		return "", nil
	}
	return *s, nil
}

func (q *pgxQuerier) Close() {
	for _, c := range q.conns {
		c.Close(context.Background())
	}
}

// --- fixed queries (catalog metadata only; never table contents, never password hashes, never query text) ---

const (
	qVersion  = `SELECT json_build_object('version', version(), 'in_recovery', pg_is_in_recovery())::text`
	qSettings = `SELECT json_object_agg(name, setting)::text FROM pg_settings WHERE name IN
 ('listen_addresses','port','ssl','ssl_min_protocol_version','max_connections','superuser_reserved_connections','hba_file','config_file',
  'data_directory','wal_level','password_encryption','log_connections','shared_buffers','work_mem','effective_cache_size','archive_mode',
  'max_wal_senders','max_replication_slots','hot_standby','synchronous_standby_names','primary_slot_name','unix_socket_directories',
  'server_version','timezone','autovacuum')`
	qDatabases = `SELECT json_agg(json_build_object('name', d.datname, 'owner', pg_get_userbyid(d.datdba),
  'encoding', pg_encoding_to_char(d.encoding), 'collate', d.datcollate, 'conn_limit', d.datconnlimit,
  'allow_conn', d.datallowconn, 'is_template', d.datistemplate,
  'size_bytes', CASE WHEN has_database_privilege(d.datname, 'CONNECT') THEN pg_database_size(d.oid) ELSE -1 END,
  'connections', (SELECT count(*) FROM pg_stat_activity a WHERE a.datid = d.oid)))::text FROM pg_database d`
	qRoles = `SELECT json_agg(json_build_object('name', r.rolname, 'login', r.rolcanlogin, 'superuser', r.rolsuper,
  'createdb', r.rolcreatedb, 'createrole', r.rolcreaterole, 'replication', r.rolreplication, 'bypassrls', r.rolbypassrls,
  'conn_limit', r.rolconnlimit, 'valid_until', coalesce(r.rolvaliduntil::text, ''),
  'member_of', coalesce((SELECT json_agg(g.rolname) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid WHERE m.member = r.oid), '[]'::json)))::text
  FROM pg_roles r WHERE r.rolname !~ '^pg_'`
	qHBA = `SELECT json_agg(json_build_object('line', line_number, 'type', type, 'database', database, 'user_name', user_name,
  'address', coalesce(address, ''), 'netmask', coalesce(netmask, ''), 'auth_method', coalesce(auth_method, ''), 'error', coalesce(error, '')))::text
  FROM pg_hba_file_rules`
	qActivity = `SELECT json_agg(x)::text FROM (SELECT coalesce(datname, '') AS datname, coalesce(usename, '') AS usename,
  coalesce(state, '') AS state, coalesce(host(client_addr), 'local') AS client, count(*) AS n,
  coalesce(max(extract(epoch FROM now() - query_start))::int, 0) AS max_query_sec,
  coalesce(max(extract(epoch FROM now() - xact_start))::int, 0) AS max_xact_sec
  FROM pg_stat_activity WHERE backend_type = 'client backend' AND pid <> pg_backend_pid() GROUP BY 1, 2, 3, 4) x`
	qLocks    = `SELECT count(*)::text FROM pg_locks WHERE NOT granted`
	qReplicas = `SELECT json_agg(json_build_object('client', coalesce(host(client_addr), 'local'), 'app', application_name,
  'state', state, 'sync', sync_state, 'replay_lag', coalesce(replay_lag::text, '')))::text FROM pg_stat_replication`
	qSlots = `SELECT json_agg(json_build_object('name', slot_name, 'type', slot_type, 'active', active, 'database', coalesce(database, ''),
  'retained_wal', CASE WHEN pg_is_in_recovery() OR restart_lsn IS NULL THEN '' ELSE pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) END))::text
  FROM pg_replication_slots`
	qWalRecv  = `SELECT coalesce((SELECT sender_host || ':' || sender_port FROM pg_stat_wal_receiver LIMIT 1), '')`
	qDBDetail = `SELECT json_build_object(
  'schemas', coalesce((SELECT json_agg(nspname ORDER BY nspname) FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'), '[]'::json),
  'extensions', coalesce((SELECT json_agg(extname || ' ' || extversion ORDER BY extname) FROM pg_extension), '[]'::json),
  'object_counts', coalesce((SELECT json_object_agg(k, v) FROM (SELECT CASE c.relkind WHEN 'r' THEN 'tables' WHEN 'p' THEN 'partitioned_tables'
     WHEN 'v' THEN 'views' WHEN 'm' THEN 'materialized_views' WHEN 'S' THEN 'sequences' WHEN 'i' THEN 'indexes' WHEN 'f' THEN 'foreign_tables'
     ELSE c.relkind::text END AS k, count(*) AS v FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' GROUP BY 1) s), '{}'::json),
  'largest_tables', coalesce((SELECT json_agg(t) FROM (SELECT n.nspname || '.' || c.relname AS name, pg_total_relation_size(c.oid) AS total_bytes,
     pg_relation_size(c.oid) AS heap_bytes, greatest(c.reltuples, 0)::bigint AS est_rows, coalesce(s.n_dead_tup, 0) AS dead_tuples,
     coalesce(s.last_autovacuum::text, '') AS last_autovacuum, coalesce(s.last_autoanalyze::text, '') AS last_autoanalyze
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
     WHERE c.relkind IN ('r', 'p', 'm') AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
     ORDER BY 2 DESC LIMIT 25) t), '[]'::json))::text`
)

type pgTarget struct {
	label, via string
	q          pgQuerier
	defaultDB  string
	published  []string // docker host bindings
}

func collectPostgres(c Ctx) (any, error) {
	pol := c.Policy()
	if !pol.PGEnabled() {
		return nil, ErrUnavailable("authenticated inspection off: use --pg-local, --pg-docker, --pg DSN or --profile deep")
	}
	res := &inventory.Postgres{}
	var targets []pgTarget

	for _, dsn := range pol.PGDSNs {
		targets = append(targets, pgTarget{label: redact.URL(dsn), via: "dsn", q: &pgxQuerier{dsn: dsn, conns: map[string]*pgx.Conn{}}})
	}

	dbs, _ := c.Prior("databases").(*inventory.Databases)
	hostPG := false
	if dbs != nil {
		for _, s := range dbs.Services {
			if s.Kind == "postgresql" && len(s.PIDs) > 0 {
				hostPG = true
			}
		}
	}
	if (pol.PGLocal || pol.Profile == "deep") && hostPG && execx.Has("psql") {
		if argv := localPsqlArgv(); argv != nil {
			targets = append(targets, pgTarget{label: "local unix socket", via: "local-psql (" + argv[0] + ")", q: psqlQuerier{argv: argv}, defaultDB: "postgres"})
		} else {
			res.Skipped = append(res.Skipped, "local: no way to act as OS user postgres (need root or passwordless sudo)")
		}
	}

	if dk, ok := c.Prior("docker").(*inventory.Docker); ok && (pol.PGDocker || pol.Profile == "deep") {
		for _, ct := range dk.Containers {
			img := strings.ToLower(ct.Image)
			if ct.State != "running" || !(strings.Contains(img, "postgres") || strings.Contains(img, "postgis") || strings.Contains(img, "timescale")) ||
				strings.Contains(img, "exporter") || strings.Contains(img, "bouncer") {
				continue
			}
			u, db := containerPGUser(c, ct.Name)
			targets = append(targets, pgTarget{label: "container " + ct.Name, via: "docker-exec psql -U " + u,
				q: psqlQuerier{argv: []string{"docker", "exec", ct.Name, "psql", "-U", u}}, defaultDB: db, published: ct.Ports})
		}
	}
	if len(targets) == 0 {
		return nil, ErrUnavailable("no PostgreSQL targets reachable for inspection")
	}
	for _, t := range targets {
		if c.Err() != nil {
			c.Warn("postgres: time budget exhausted, %s skipped", t.label)
			break
		}
		inst := inspectPG(c, t)
		t.q.Close()
		res.Instances = append(res.Instances, inst)
		if len(inst.Errors) > 0 {
			c.Warn("%s: %s", t.label, inst.Errors[0])
		}
	}
	return res, nil
}

func localPsqlArgv() []string {
	if u, err := user.Current(); err == nil && u.Username == "postgres" {
		return []string{"psql"}
	}
	if _, err := user.Lookup("postgres"); err != nil {
		return nil
	}
	if os.Geteuid() == 0 && runtime.GOOS == "linux" && execx.Has("runuser") {
		return []string{"runuser", "-u", "postgres", "--", "psql"}
	}
	if execx.Has("sudo") {
		return []string{"sudo", "-n", "-u", "postgres", "psql"} // -n: never prompt
	}
	return nil
}

// containerPGUser reads only POSTGRES_USER / POSTGRES_DB names from the container env (never the password).
func containerPGUser(c Ctx, name string) (string, string) {
	out, _ := execx.Run(c, 5*time.Second, "docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", name)
	u, db := "postgres", ""
	for _, ln := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(ln, "POSTGRES_USER="); ok && v != "" {
			u = v
		}
		if v, ok := strings.CutPrefix(ln, "POSTGRES_DB="); ok && v != "" {
			db = v
		}
	}
	if db == "" {
		db = u
	}
	return u, db
}

func inspectPG(c Ctx, t pgTarget) inventory.PGInstance {
	inst := inventory.PGInstance{Target: t.label, Via: t.via, Settings: map[string]string{}}
	db := t.defaultDB
	run := func(name, sql string, into any) bool {
		s, err := t.q.QueryJSON(c, db, sql)
		if err != nil {
			inst.Errors = append(inst.Errors, name+": "+err.Error())
			return false
		}
		if s == "" {
			return true
		}
		if into != nil {
			if err := json.Unmarshal([]byte(s), into); err != nil {
				inst.Errors = append(inst.Errors, name+": decode: "+err.Error())
				return false
			}
		}
		return true
	}
	var v struct {
		Version    string `json:"version"`
		InRecovery bool   `json:"in_recovery"`
	}
	if !run("connect", qVersion, &v) {
		return inst
	}
	inst.Version, inst.InRecovery = v.Version, v.InRecovery
	run("settings", qSettings, &inst.Settings)
	run("databases", qDatabases, &inst.Databases)
	run("roles", qRoles, &inst.Roles)
	if !run("hba", qHBA, &inst.HBA) {
		inst.HBANote = "pg_hba_file_rules not readable (needs superuser or pg_read_all_settings); see config file " + inst.Settings["hba_file"]
		inst.Errors = inst.Errors[:len(inst.Errors)-1]
	}
	run("activity", qActivity, &inst.Activity)
	var locks string
	if s, err := t.q.QueryJSON(c, db, qLocks); err == nil {
		locks = s
		fmt.Sscan(locks, &inst.WaitingLocks)
	}
	run("replication", qReplicas, &inst.Replicas)
	run("slots", qSlots, &inst.Slots)
	if s, err := t.q.QueryJSON(c, db, qWalRecv); err == nil {
		inst.UpstreamHost = s
	}

	sort.Slice(inst.Databases, func(i, j int) bool { return inst.Databases[i].SizeBytes > inst.Databases[j].SizeBytes })
	n := 0
	for i := range inst.Databases {
		d := &inst.Databases[i]
		if d.IsTemplate || !d.AllowConn || d.SizeBytes < 0 || n >= c.Policy().PGMaxDBs || c.Err() != nil {
			continue
		}
		n++
		var det inventory.PGDBDetail
		s, err := t.q.QueryJSON(c, d.Name, qDBDetail)
		if err != nil {
			det.Error = err.Error()
		} else if s != "" {
			if err := json.Unmarshal([]byte(s), &det); err != nil {
				det.Error = err.Error()
			}
		}
		d.Detail = &det
	}
	for i := range inst.HBA {
		inst.HBA[i].Meaning = hbaMeaning(inst.HBA[i])
	}
	inst.Exposure = pgExposure(inst, t.published)
	return inst
}

func hbaMeaning(r inventory.PGHBARule) string {
	if r.Error != "" {
		return "invalid rule: " + r.Error
	}
	who := strings.Join(r.User, ",")
	if who == "all" {
		who = "any user"
	}
	dbs := strings.Join(r.Database, ",")
	if dbs == "all" {
		dbs = "any database"
	}
	from := "unix socket"
	if r.Type != "local" {
		from = r.Address
		if r.Netmask != "" {
			if ones, bits := net.IPMask(net.ParseIP(r.Netmask).To16()[16-maskLen(r.Netmask):]).Size(); bits > 0 {
				from += "/" + strconv.Itoa(ones)
			} else {
				from += "/" + r.Netmask
			}
		}
		switch r.Address {
		case "0.0.0.0", "::", "all", "":
			if r.Netmask == "0.0.0.0" || r.Netmask == "::" || r.Address == "all" || r.Address == "" {
				from = "ANY address"
			}
		}
		if r.Address == "samehost" || r.Address == "samenet" {
			from = r.Address
		}
		if strings.HasPrefix(r.Type, "hostssl") {
			from += " (TLS only)"
		}
	}
	auth := r.Auth
	switch r.Auth {
	case "trust":
		auth = "NO PASSWORD (trust)"
	case "reject":
		return fmt.Sprintf("BLOCK %s → %s from %s", who, dbs, from)
	case "md5":
		auth = "password (md5)"
	case "scram-sha-256":
		auth = "password (scram)"
	case "password":
		auth = "CLEARTEXT password"
	case "peer", "ident":
		auth = "OS user match (" + r.Auth + ")"
	}
	return fmt.Sprintf("%s → %s from %s via %s", who, dbs, from, auth)
}

func maskLen(m string) int {
	if strings.Contains(m, ":") {
		return 16
	}
	return 4
}

func pgExposure(inst inventory.PGInstance, published []string) []string {
	var out []string
	la := inst.Settings["listen_addresses"]
	switch la {
	case "", "localhost", "127.0.0.1", "::1":
		out = append(out, "listen_addresses='"+la+"': local connections only")
	case "*", "0.0.0.0", "::":
		out = append(out, "listen_addresses='"+la+"': ALL interfaces on port "+inst.Settings["port"])
	default:
		out = append(out, "listen_addresses='"+la+"' port "+inst.Settings["port"])
	}
	for _, p := range published {
		out = append(out, "docker publishes "+p+" (host side)")
	}
	if inst.Settings["ssl"] == "off" && la != "localhost" && la != "" {
		out = append(out, "ssl=off: network traffic unencrypted")
	}
	for _, r := range inst.HBA {
		if r.Type != "local" && r.Auth != "reject" {
			out = append(out, "pg_hba line "+fmt.Sprint(r.Line)+": "+r.Meaning)
		}
	}
	if inst.HBANote != "" {
		out = append(out, inst.HBANote)
	}
	return out
}
