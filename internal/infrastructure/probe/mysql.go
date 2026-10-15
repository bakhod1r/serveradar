package probe

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
	"github.com/bakhod1r/serveradar/internal/infrastructure/redact"
)

func init() {
	register(Collector{Name: "mysql", Title: "MySQL / MariaDB Inspection", Profiles: everywhere,
		Depends: []string{"databases", "docker", "ports"}, Collect: collectMySQL})
}

// myQuerier returns header + rows for one fixed read-only statement.
type myQuerier interface {
	Rows(ctx context.Context, q string) ([]string, [][]string, error)
	Close()
}

// --- CLI (local socket or docker exec) ---

type myCLI struct{ argv []string }

func (m myCLI) Rows(ctx context.Context, q string) ([]string, [][]string, error) {
	stmt := "SET SESSION TRANSACTION READ ONLY; " + q
	args := append(append([]string{}, m.argv[1:]...), "--batch", "--raw", "--connect-timeout=5", "-e", stmt)
	out, err := execx.Run(ctx, 20*time.Second, m.argv[0], args...)
	if err != nil {
		return nil, nil, fmt.Errorf("%s", firstLine(redact.Text(strings.TrimPrefix(err.Error(), m.argv[0]+": "))))
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, nil, nil
	}
	head := strings.Split(lines[0], "\t")
	var rows [][]string
	for _, ln := range lines[1:] {
		rows = append(rows, strings.Split(ln, "\t"))
	}
	return head, rows, nil
}
func (myCLI) Close() {}

// --- driver (explicit DSN) ---

type myDriver struct {
	db   *sql.DB
	conn *sql.Conn
	err  error
}

func newMyDriver(raw string) *myDriver {
	dsn := raw
	if u, err := url.Parse(raw); err == nil && (u.Scheme == "mysql" || u.Scheme == "mariadb") {
		cfg := mysql.NewConfig()
		cfg.Net, cfg.Addr = "tcp", u.Host
		if !strings.Contains(cfg.Addr, ":") {
			cfg.Addr += ":3306"
		}
		cfg.User = u.User.Username()
		cfg.Passwd, _ = u.User.Password()
		dsn = cfg.FormatDSN()
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return &myDriver{err: fmt.Errorf("bad DSN")}
	}
	cfg.Timeout, cfg.ReadTimeout = 5*time.Second, 20*time.Second
	cfg.Params = map[string]string{"transaction_read_only": "1"}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	return &myDriver{db: db, err: err}
}

func (m *myDriver) Rows(ctx context.Context, q string) ([]string, [][]string, error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	if m.conn == nil {
		c, err := m.db.Conn(ctx)
		if err != nil {
			m.err = fmt.Errorf("%s", redact.Text(err.Error()))
			return nil, nil, m.err
		}
		m.conn = c
	}
	rs, err := m.conn.QueryContext(ctx, q)
	if err != nil {
		return nil, nil, fmt.Errorf("%s", redact.Text(err.Error()))
	}
	defer rs.Close()
	head, _ := rs.Columns()
	var out [][]string
	for rs.Next() {
		vals := make([]sql.NullString, len(head))
		ptr := make([]any, len(head))
		for i := range vals {
			ptr[i] = &vals[i]
		}
		if err := rs.Scan(ptr...); err != nil {
			return head, out, err
		}
		row := make([]string, len(head))
		for i, v := range vals {
			row[i] = "NULL"
			if v.Valid {
				row[i] = v.String
			}
		}
		out = append(out, row)
	}
	return head, out, rs.Err()
}

func (m *myDriver) Close() {
	if m.conn != nil {
		m.conn.Close()
	}
	if m.db != nil {
		m.db.Close()
	}
}

// --- fixed queries: catalog/metadata only. Never row data, never password hashes, never query text. ---

const sysSchemas = "'mysql','sys','performance_schema','information_schema'"

var (
	myVars = `SHOW GLOBAL VARIABLES WHERE Variable_name IN ('version','version_comment','bind_address','port','skip_networking',
 'require_secure_transport','have_ssl','tls_version','max_connections','datadir','server_id','log_bin','gtid_mode','binlog_format',
 'read_only','super_read_only','innodb_buffer_pool_size','default_authentication_plugin','authentication_policy','wsrep_on',
 'wsrep_cluster_name','wsrep_cluster_address','group_replication_group_name','sql_mode','character_set_server','collation_server',
 'local_infile','secure_file_priv','skip_name_resolve','mysqlx_port','report_host','expire_logs_days','binlog_expire_logs_seconds',
 'innodb_file_per_table','slow_query_log','long_query_time','max_allowed_packet','time_zone','system_time_zone','lower_case_table_names')`
	myStatus = `SHOW GLOBAL STATUS WHERE Variable_name IN ('Uptime','Threads_connected','Threads_running','Max_used_connections',
 'Questions','Slow_queries','Aborted_connects','Aborted_clients','Connections','Innodb_buffer_pool_reads','Innodb_buffer_pool_read_requests',
 'Innodb_row_lock_waits','Innodb_row_lock_time_avg','Open_tables','Opened_tables','Created_tmp_disk_tables','Created_tmp_tables',
 'Select_full_join','Table_locks_waited','Bytes_received','Bytes_sent','wsrep_cluster_size','wsrep_cluster_status','wsrep_local_state_comment',
 'wsrep_ready','wsrep_connected')`
	mySchemas = `SELECT s.SCHEMA_NAME, s.DEFAULT_CHARACTER_SET_NAME, s.DEFAULT_COLLATION_NAME, COUNT(t.TABLE_NAME),
 COALESCE(SUM(t.DATA_LENGTH),0), COALESCE(SUM(t.INDEX_LENGTH),0), COALESCE(SUM(t.DATA_FREE),0), COALESCE(SUM(t.TABLE_ROWS),0)
 FROM information_schema.SCHEMATA s LEFT JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = s.SCHEMA_NAME AND t.TABLE_TYPE = 'BASE TABLE'
 GROUP BY s.SCHEMA_NAME, s.DEFAULT_CHARACTER_SET_NAME, s.DEFAULT_COLLATION_NAME`
	myEngines  = `SELECT TABLE_SCHEMA, COALESCE(ENGINE,'?'), COUNT(*) FROM information_schema.TABLES WHERE TABLE_TYPE = 'BASE TABLE' GROUP BY 1, 2`
	myViews    = `SELECT TABLE_SCHEMA, COUNT(*) FROM information_schema.VIEWS GROUP BY 1`
	myRoutines = `SELECT ROUTINE_SCHEMA, COUNT(*) FROM information_schema.ROUTINES GROUP BY 1`
	myTriggers = `SELECT TRIGGER_SCHEMA, COUNT(*) FROM information_schema.TRIGGERS GROUP BY 1`
	myEvents   = `SELECT EVENT_SCHEMA, COUNT(*) FROM information_schema.EVENTS GROUP BY 1`
	myLargest  = `SELECT TABLE_SCHEMA, TABLE_NAME, COALESCE(ENGINE,''), COALESCE(TABLE_ROWS,0), COALESCE(DATA_LENGTH,0), COALESCE(INDEX_LENGTH,0),
 COALESCE(DATA_FREE,0), COALESCE(UPDATE_TIME,'') FROM information_schema.TABLES WHERE TABLE_TYPE = 'BASE TABLE' AND TABLE_SCHEMA NOT IN (` + sysSchemas + `)
 ORDER BY COALESCE(DATA_LENGTH,0) + COALESCE(INDEX_LENGTH,0) DESC LIMIT 50`
	myNoPK = `SELECT t.TABLE_SCHEMA, t.TABLE_NAME FROM information_schema.TABLES t LEFT JOIN information_schema.TABLE_CONSTRAINTS c
 ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME AND c.CONSTRAINT_TYPE = 'PRIMARY KEY'
 WHERE t.TABLE_TYPE = 'BASE TABLE' AND c.CONSTRAINT_NAME IS NULL AND t.TABLE_SCHEMA NOT IN (` + sysSchemas + `) ORDER BY 1, 2 LIMIT 500`
	myUsers = `SELECT User, Host, COALESCE(plugin,''), IF(COALESCE(authentication_string,'') = '', 'EMPTY', 'set'),
 Super_priv, Grant_priv, File_priv, Shutdown_priv, Process_priv, Repl_slave_priv, Create_user_priv, Select_priv, Insert_priv, Drop_priv
 FROM mysql.user`
	mySchemaGrants = `SELECT GRANTEE, TABLE_SCHEMA, GROUP_CONCAT(PRIVILEGE_TYPE ORDER BY PRIVILEGE_TYPE) FROM information_schema.SCHEMA_PRIVILEGES GROUP BY 1, 2`
	myProcs        = `SELECT COALESCE(USER,''), COALESCE(SUBSTRING_INDEX(HOST, ':', 1),''), COALESCE(DB,''), COMMAND, COUNT(*), MAX(TIME)
 FROM information_schema.PROCESSLIST WHERE ID <> CONNECTION_ID() GROUP BY 1, 2, 3, 4`
	myGroup = `SELECT CONCAT(MEMBER_HOST, ':', MEMBER_PORT, ' ', MEMBER_STATE, ' ', COALESCE(MEMBER_ROLE,'')) FROM performance_schema.replication_group_members`
)

type myTarget struct {
	label, via string
	q          myQuerier
	published  []string
}

func collectMySQL(c Ctx) (any, error) {
	pol := c.Policy()
	if !pol.MySQLEnabled() {
		return nil, ErrUnavailable("authenticated inspection off: use --mysql-local, --mysql-docker, --mysql DSN or --profile deep")
	}
	res := &inventory.MySQL{}
	var targets []myTarget
	for _, d := range pol.MySQLDSNs {
		targets = append(targets, myTarget{label: redact.URL(d), via: "dsn", q: newMyDriver(d)})
	}
	if dbs, ok := c.Prior("databases").(*inventory.Databases); ok && (pol.MySQLLocal || pol.Profile == "deep") {
		host := false
		for _, s := range dbs.Services {
			host = host || (s.Kind == "mysql" || s.Kind == "mariadb") && len(s.PIDs) > 0
		}
		if host {
			cli := ""
			for _, b := range []string{"mariadb", "mysql"} {
				if execx.Has(b) {
					cli = b
					break
				}
			}
			switch {
			case cli == "":
				res.Skipped = append(res.Skipped, "local: mysql/mariadb client not installed")
			case os.Geteuid() == 0:
				targets = append(targets, myTarget{label: "local socket", via: cli + " as root (auth_socket / ~/.my.cnf)", q: myCLI{argv: []string{cli}}})
			default:
				targets = append(targets, myTarget{label: "local socket", via: cli + " (~/.my.cnf)", q: myCLI{argv: []string{cli}}})
			}
		}
	}
	if dk, ok := c.Prior("docker").(*inventory.Docker); ok && (pol.MySQLDocker || pol.Profile == "deep") {
		for _, ct := range dk.Containers {
			img := strings.ToLower(ct.Image)
			if ct.State != "running" || !(strings.Contains(img, "mysql") || strings.Contains(img, "mariadb") || strings.Contains(img, "percona")) ||
				strings.Contains(img, "exporter") || strings.Contains(img, "router") || strings.Contains(img, "proxysql") {
				continue
			}
			// Password is read from the container's own env inside the container; it never enters this process or its argv.
			inner := `B=$(command -v mariadb || command -v mysql); P="${MYSQL_ROOT_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}";` +
				` if [ -n "$P" ]; then export MYSQL_PWD="$P"; fi; exec "$B" -uroot "$@"`
			targets = append(targets, myTarget{label: "container " + ct.Name, via: "docker-exec (root, password from container env)",
				q: myCLI{argv: []string{"docker", "exec", ct.Name, "sh", "-c", inner, "sh"}}, published: ct.Ports})
		}
	}
	if len(targets) == 0 {
		return nil, ErrUnavailable("no MySQL/MariaDB targets to inspect")
	}
	for _, t := range targets {
		if c.Err() != nil {
			c.Warn("mysql: time budget exhausted, %s skipped", t.label)
			break
		}
		inst := inspectMySQL(c, t)
		t.q.Close()
		if len(inst.Errors) > 0 {
			c.Warn("%s: %s", t.label, inst.Errors[0])
		}
		res.Instances = append(res.Instances, inst)
	}
	return res, nil
}

func inspectMySQL(c Ctx, t myTarget) inventory.MySQLInstance {
	in := inventory.MySQLInstance{Target: t.label, Via: t.via, Variables: map[string]string{}, Status: map[string]string{}}
	q := func(name, s string) ([]string, [][]string, bool) {
		h, r, err := t.q.Rows(c, s)
		if err != nil {
			in.Errors = append(in.Errors, name+": "+err.Error())
			return nil, nil, false
		}
		return h, r, true
	}
	_, rows, ok := q("connect", myVars)
	if !ok {
		return in
	}
	for _, r := range rows {
		if len(r) == 2 {
			in.Variables[r[0]] = r[1]
		}
	}
	in.Flavor = "MySQL"
	if strings.Contains(strings.ToLower(in.Variables["version"]+in.Variables["version_comment"]), "mariadb") {
		in.Flavor = "MariaDB"
	} else if strings.Contains(strings.ToLower(in.Variables["version_comment"]), "percona") {
		in.Flavor = "Percona"
	}
	if _, rows, ok := q("status", myStatus); ok {
		for _, r := range rows {
			if len(r) == 2 {
				in.Status[r[0]] = r[1]
			}
		}
	}

	dbs := map[string]*inventory.MySQLDatabase{}
	if _, rows, ok := q("schemas", mySchemas); ok {
		for _, r := range rows {
			if len(r) < 8 {
				continue
			}
			d := &inventory.MySQLDatabase{Name: r[0], Charset: r[1], Collation: r[2], Tables: i64(r[3]), DataBytes: i64(r[4]),
				IndexBytes: i64(r[5]), FreeBytes: i64(r[6]), EstRows: i64(r[7]), Engines: map[string]int64{}}
			d.System = strings.Contains(sysSchemas, "'"+d.Name+"'")
			dbs[d.Name] = d
		}
	}
	perDB := func(name, s string, set func(d *inventory.MySQLDatabase, r []string)) {
		if _, rows, ok := q(name, s); ok {
			for _, r := range rows {
				if d := dbs[r[0]]; d != nil {
					set(d, r)
				}
			}
		}
	}
	perDB("engines", myEngines, func(d *inventory.MySQLDatabase, r []string) { d.Engines[r[1]] = i64(r[2]) })
	perDB("views", myViews, func(d *inventory.MySQLDatabase, r []string) { d.Views = i64(r[1]) })
	perDB("routines", myRoutines, func(d *inventory.MySQLDatabase, r []string) { d.Routines = i64(r[1]) })
	perDB("triggers", myTriggers, func(d *inventory.MySQLDatabase, r []string) { d.Triggers = i64(r[1]) })
	perDB("events", myEvents, func(d *inventory.MySQLDatabase, r []string) { d.Events = i64(r[1]) })
	if _, rows, ok := q("no-pk", myNoPK); ok {
		for _, r := range rows {
			in.NoPKTables = append(in.NoPKTables, r[0]+"."+r[1])
			if d := dbs[r[0]]; d != nil {
				d.NoPK++
			}
		}
	}
	for _, d := range dbs {
		in.Databases = append(in.Databases, *d)
	}
	sort.Slice(in.Databases, func(i, j int) bool {
		a, b := in.Databases[i], in.Databases[j]
		return a.DataBytes+a.IndexBytes > b.DataBytes+b.IndexBytes
	})
	if _, rows, ok := q("largest", myLargest); ok {
		for _, r := range rows {
			if len(r) >= 8 {
				in.Largest = append(in.Largest, inventory.MySQLTable{Schema: r[0], Name: r[1], Engine: r[2], EstRows: i64(r[3]),
					DataBytes: i64(r[4]), IndexBytes: i64(r[5]), FreeBytes: i64(r[6]), Updated: nullz(r[7])})
			}
		}
	}

	users := map[string]*inventory.MySQLUser{}
	if h, rows, ok := q("users", myUsers); ok {
		for _, r := range rows {
			if len(r) < 14 {
				continue
			}
			u := &inventory.MySQLUser{User: r[0], Host: r[1], Plugin: r[2], EmptyPassword: r[3] == "EMPTY"}
			for i := 4; i < len(r) && i < len(h); i++ {
				if r[i] == "Y" {
					u.Global = append(u.Global, strings.TrimSuffix(h[i], "_priv"))
				}
			}
			users["'"+u.User+"'@'"+u.Host+"'"] = u
		}
	}
	if _, rows, ok := q("schema-grants", mySchemaGrants); ok {
		for _, r := range rows {
			if u := users[r[0]]; u != nil && len(r) >= 3 {
				u.Schemas = append(u.Schemas, r[1]+": "+r[2])
			}
		}
	}
	for _, u := range users {
		in.Users = append(in.Users, *u)
	}
	sort.Slice(in.Users, func(i, j int) bool { return in.Users[i].User+in.Users[i].Host < in.Users[j].User+in.Users[j].Host })

	if _, rows, ok := q("processlist", myProcs); ok {
		for _, r := range rows {
			if len(r) >= 6 {
				in.Connections = append(in.Connections, inventory.MySQLConn{User: r[0], Host: r[1], DB: r[2], Command: r[3], N: int(i64(r[4])), MaxTime: int(i64(r[5]))})
			}
		}
	}
	// replication: newer syntax first, fall back to legacy
	for _, s := range []string{"SHOW REPLICA STATUS", "SHOW SLAVE STATUS"} {
		if h, rows, err := t.q.Rows(c, s); err == nil {
			if len(rows) > 0 {
				in.Replica = pickCols(h, rows[0], "Source_Host", "Master_Host", "Source_Port", "Master_Port", "Replica_IO_Running", "Slave_IO_Running",
					"Replica_SQL_Running", "Slave_SQL_Running", "Seconds_Behind_Source", "Seconds_Behind_Master", "Last_IO_Error", "Last_SQL_Error",
					"Retrieved_Gtid_Set", "Executed_Gtid_Set", "Auto_Position", "Using_Gtid")
			}
			break
		}
	}
	for _, s := range []string{"SHOW BINARY LOG STATUS", "SHOW MASTER STATUS"} {
		if h, rows, err := t.q.Rows(c, s); err == nil {
			if len(rows) > 0 {
				in.Binlog = pickCols(h, rows[0], "File", "Position", "Executed_Gtid_Set", "Binlog_Do_DB", "Binlog_Ignore_DB")
			}
			break
		}
	}
	if _, rows, err := t.q.Rows(c, myGroup); err == nil {
		for _, r := range rows {
			in.Group = append(in.Group, r[0])
		}
	}
	if in.Variables["wsrep_on"] == "ON" {
		in.Galera = map[string]string{}
		for k, v := range in.Status {
			if strings.HasPrefix(k, "wsrep_") {
				in.Galera[k] = v
			}
		}
	}
	in.Exposure = myExposure(in, t.published)
	in.Analysis = myAnalysis(in)
	return in
}

func myExposure(in inventory.MySQLInstance, published []string) []string {
	var out []string
	v := in.Variables
	if v["skip_networking"] == "ON" {
		out = append(out, "skip_networking=ON: unix socket only")
	} else {
		ba := v["bind_address"]
		switch ba {
		case "", "*", "0.0.0.0", "::":
			out = append(out, fmt.Sprintf("bind_address='%s': ALL interfaces, port %s", ba, v["port"]))
		case "127.0.0.1", "localhost", "::1":
			out = append(out, "bind_address='"+ba+"': local only")
		default:
			out = append(out, "bind_address='"+ba+"' port "+v["port"])
		}
	}
	if v["mysqlx_port"] != "" && v["mysqlx_port"] != "0" {
		out = append(out, "X protocol port "+v["mysqlx_port"])
	}
	for _, p := range published {
		out = append(out, "docker publishes "+p)
	}
	if v["require_secure_transport"] != "ON" {
		out = append(out, "TLS not enforced (require_secure_transport="+orDashS(v["require_secure_transport"])+")")
	}
	for _, u := range in.Users {
		remote := u.Host != "localhost" && u.Host != "127.0.0.1" && u.Host != "::1"
		if !remote {
			continue
		}
		who := fmt.Sprintf("'%s'@'%s'", u.User, u.Host)
		desc := "can connect from " + u.Host
		if u.Host == "%" {
			desc = "can connect from ANY host"
		}
		if u.EmptyPassword && !strings.Contains(u.Plugin, "socket") {
			desc += " WITHOUT PASSWORD"
		}
		if len(u.Global) > 0 {
			desc += " · global: " + strings.Join(u.Global, ",")
		}
		out = append(out, who+" "+desc)
	}
	return out
}

func myAnalysis(in inventory.MySQLInstance) []string {
	var a []string
	v, s := in.Variables, in.Status
	var total, free int64
	for _, d := range in.Databases {
		if !d.System {
			total += d.DataBytes + d.IndexBytes
			free += d.FreeBytes
		}
	}
	a = append(a, fmt.Sprintf("%s %s · %d user databases · %s data+index", in.Flavor, v["version"], countUser(in.Databases), hbI(total)))
	if total > 0 && free > total/5 && free > 100<<20 {
		a = append(a, fmt.Sprintf("Fragmentation: %s reclaimable (data_free) — consider OPTIMIZE on largest tables during maintenance", hbI(free)))
	}
	if n := len(in.NoPKTables); n > 0 {
		a = append(a, fmt.Sprintf("%d tables without PRIMARY KEY — bad for InnoDB clustering, replication and Group Replication", n))
	}
	myisam := int64(0)
	for _, d := range in.Databases {
		if !d.System {
			myisam += d.Engines["MyISAM"]
		}
	}
	if myisam > 0 {
		a = append(a, fmt.Sprintf("%d MyISAM tables in user schemas — no transactions, table locks, crash-unsafe", myisam))
	}
	if mc, mu := i64(v["max_connections"]), i64(s["Max_used_connections"]); mc > 0 && mu*100/mc >= 80 {
		a = append(a, fmt.Sprintf("Connections peaked at %d/%d (%d%%)", mu, mc, mu*100/mc))
	}
	if req, rd := i64(s["Innodb_buffer_pool_read_requests"]), i64(s["Innodb_buffer_pool_reads"]); req > 10000 {
		hit := 100 - float64(rd)*100/float64(req)
		note := ""
		if hit < 99 {
			note = " — buffer pool may be too small (" + hbI(i64(v["innodb_buffer_pool_size"])) + ")"
		}
		a = append(a, fmt.Sprintf("InnoDB buffer pool hit ratio %.2f%%%s", hit, note))
	}
	if q, sl := i64(s["Questions"]), i64(s["Slow_queries"]); sl > 0 {
		a = append(a, fmt.Sprintf("Slow queries: %d of %d (slow_query_log=%s, long_query_time=%s)", sl, q, v["slow_query_log"], v["long_query_time"]))
	}
	if t, d := i64(s["Created_tmp_tables"]), i64(s["Created_tmp_disk_tables"]); t > 1000 && d*100/t > 25 {
		a = append(a, fmt.Sprintf("%d%% of temp tables go to disk", d*100/t))
	}
	if i64(s["Aborted_connects"]) > 100 {
		a = append(a, "Aborted_connects="+s["Aborted_connects"]+" — failed logins or network issues")
	}
	if v["local_infile"] == "ON" {
		a = append(a, "local_infile=ON — client can read files via LOAD DATA LOCAL")
	}
	if v["log_bin"] != "ON" {
		a = append(a, "Binary log OFF — no point-in-time recovery, no replication")
	}
	for _, u := range in.Users {
		switch {
		case u.User == "":
			a = append(a, fmt.Sprintf("Anonymous user ''@'%s' exists", u.Host))
		case u.User == "root" && u.Host == "%":
			a = append(a, "root@'%' — root reachable from any host")
		case u.EmptyPassword && !strings.Contains(u.Plugin, "socket") && !strings.Contains(u.Plugin, "unix") && u.Plugin != "":
			a = append(a, fmt.Sprintf("'%s'@'%s' has EMPTY password", u.User, u.Host))
		}
		if strings.Contains(u.Plugin, "mysql_native_password") && in.Flavor == "MySQL" {
			a = append(a, fmt.Sprintf("'%s'@'%s' uses deprecated mysql_native_password", u.User, u.Host))
		}
	}
	if r := in.Replica; r != nil {
		io, sq := firstNonEmpty(r["Replica_IO_Running"], r["Slave_IO_Running"]), firstNonEmpty(r["Replica_SQL_Running"], r["Slave_SQL_Running"])
		lag := firstNonEmpty(r["Seconds_Behind_Source"], r["Seconds_Behind_Master"])
		a = append(a, fmt.Sprintf("Replica of %s: IO=%s SQL=%s lag=%ss", firstNonEmpty(r["Source_Host"], r["Master_Host"]), io, sq, lag))
		if e := firstNonEmpty(r["Last_IO_Error"], r["Last_SQL_Error"]); e != "" {
			a = append(a, "Replication error: "+e)
		}
	}
	if len(in.Group) > 0 {
		a = append(a, "Group Replication members: "+strings.Join(in.Group, "; "))
	}
	if in.Galera != nil {
		a = append(a, fmt.Sprintf("Galera cluster %s size=%s status=%s", v["wsrep_cluster_name"], in.Galera["wsrep_cluster_size"], in.Galera["wsrep_cluster_status"]))
	}
	return a
}

func pickCols(h []string, row []string, cols ...string) map[string]string {
	m := map[string]string{}
	for i, name := range h {
		for _, c := range cols {
			if name == c && i < len(row) && row[i] != "" && row[i] != "NULL" {
				v := row[i]
				if strings.HasSuffix(name, "Error") {
					v = redact.Text(v)
				}
				m[name] = v
			}
		}
	}
	return m
}

func countUser(d []inventory.MySQLDatabase) (n int) {
	for _, x := range d {
		if !x.System {
			n++
		}
	}
	return
}

func i64(s string) int64 { n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64); return n }

func nullz(s string) string {
	if s == "NULL" {
		return ""
	}
	return s
}

func orDashS(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func hbI(b int64) string {
	if b < 0 {
		return "n/a"
	}
	const u = 1024
	if b < u {
		return fmt.Sprintf("%d B", b)
	}
	d, e := int64(u), 0
	for n := b / u; n >= u; n /= u {
		d *= u
		e++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(d), "KMGTPE"[e])
}
