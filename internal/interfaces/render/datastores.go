package render

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
)

func hbi(b int64) string {
	if b < 0 {
		return "no access"
	}
	return hb(uint64(b))
}

func bullets(m md, title string, items []string) {
	if len(items) == 0 {
		return
	}
	if title != "" {
		m.p("\n**%s**\n", title)
	}
	for _, x := range items {
		m.p("- %s", x)
	}
}

func pgMD(m md, d *inventory.Postgres) {
	for _, s := range d.Skipped {
		m.p("> skipped: %s", s)
	}
	for _, in := range d.Instances {
		m.h(3, "PostgreSQL — "+in.Target)
		m.p("via `%s`", in.Via)
		if in.Version == "" {
			m.p("> could not connect: %s", strings.Join(in.Errors, "; "))
			continue
		}
		role := "primary"
		if in.InRecovery {
			role = "standby (replica) of " + orDashStr(in.UpstreamHost)
		}
		var total int64
		for _, db := range in.Databases {
			if db.SizeBytes > 0 {
				total += db.SizeBytes
			}
		}
		m.kv("Version", in.Version, "Role", role, "Total size", hbi(total), "Waiting locks", strconv.Itoa(in.WaitingLocks))
		bullets(m, "Who can connect (exposure)", in.Exposure)

		m.h(4, "Databases")
		var rows [][]string
		for _, db := range in.Databases {
			cnt := ""
			if db.Detail != nil {
				cnt = fmt.Sprintf("%d tables, %d views, %d schemas", db.Detail.Counts["tables"]+db.Detail.Counts["partitioned_tables"], db.Detail.Counts["views"], len(db.Detail.Schemas))
			}
			rows = append(rows, []string{db.Name, hbi(db.SizeBytes), db.Owner, db.Encoding, db.Collate, strconv.Itoa(db.Connections), limitStr(db.ConnLimit), yn(db.IsTemplate), cnt})
		}
		m.table([]string{"Database", "Size", "Owner", "Encoding", "Collate", "Conns", "Conn limit", "Template", "Objects"}, rows)

		for _, db := range in.Databases {
			if db.Detail == nil {
				continue
			}
			dt := db.Detail
			m.h(4, "Database `"+db.Name+"` — "+hbi(db.SizeBytes))
			if dt.Error != "" {
				m.p("> %s", dt.Error)
				continue
			}
			var counts []string
			for k, v := range dt.Counts {
				counts = append(counts, fmt.Sprintf("%s=%d", k, v))
			}
			sort.Strings(counts)
			m.kv("Schemas", strings.Join(dt.Schemas, ", "), "Extensions", strings.Join(dt.Extensions, ", "), "Objects", strings.Join(counts, " "))
			rows = nil
			for _, t := range dt.Tables {
				rows = append(rows, []string{t.Name, hbi(t.TotalBytes), hbi(t.HeapBytes), strconv.FormatInt(t.EstRows, 10), strconv.FormatInt(t.DeadTuples, 10), short(t.LastAutovac), short(t.LastAutoanaly)})
			}
			m.table([]string{"Table", "Total", "Heap", "Est. rows", "Dead tuples", "Last autovacuum", "Last autoanalyze"}, rows)
		}

		m.h(4, "Roles / users")
		rows = nil
		for _, r := range in.Roles {
			var attrs []string
			for _, a := range []struct {
				on   bool
				name string
			}{{r.Superuser, "SUPERUSER"}, {r.CreateDB, "CREATEDB"}, {r.CreateRole, "CREATEROLE"}, {r.Replication, "REPLICATION"}, {r.BypassRLS, "BYPASSRLS"}} {
				if a.on {
					attrs = append(attrs, a.name)
				}
			}
			rows = append(rows, []string{r.Name, yn(r.Login), strings.Join(attrs, " "), strings.Join(r.MemberOf, ", "), limitStr(r.ConnLimit), r.ValidUntil})
		}
		m.table([]string{"Role", "Login", "Attributes", "Member of", "Conn limit", "Valid until"}, rows)

		m.h(4, "pg_hba.conf — access rules")
		if in.HBANote != "" {
			m.p("> %s", in.HBANote)
		}
		rows = nil
		for _, h := range in.HBA {
			rows = append(rows, []string{strconv.Itoa(h.Line), h.Type, strings.Join(h.Database, ","), strings.Join(h.User, ","), strings.TrimSpace(h.Address + " " + h.Netmask), h.Auth, h.Meaning})
		}
		if len(rows) > 0 {
			m.table([]string{"Line", "Type", "Database", "User", "Address", "Method", "Meaning"}, rows)
		}

		m.h(4, "Settings")
		var pairs []string
		keys := make([]string, 0, len(in.Settings))
		for k := range in.Settings {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			pairs = append(pairs, k, in.Settings[k])
		}
		m.kv(pairs...)

		m.h(4, "Connections")
		rows = nil
		for _, a := range in.Activity {
			rows = append(rows, []string{a.Database, a.User, a.Client, a.State, strconv.Itoa(a.N), strconv.Itoa(a.MaxQuerySec) + "s", strconv.Itoa(a.MaxXactSec) + "s"})
		}
		m.table([]string{"DB", "User", "Client", "State", "Count", "Oldest query", "Oldest xact"}, rows)

		if len(in.Replicas) > 0 || len(in.Slots) > 0 {
			m.h(4, "Replication")
			rows = nil
			for _, r := range in.Replicas {
				rows = append(rows, []string{r.Client, r.App, r.State, r.Sync, r.ReplayLag})
			}
			m.table([]string{"Replica", "App", "State", "Sync", "Replay lag"}, rows)
			rows = nil
			for _, s := range in.Slots {
				rows = append(rows, []string{s.Name, s.Type, yn(s.Active), s.Database, s.Retained})
			}
			m.table([]string{"Slot", "Type", "Active", "DB", "Retained WAL"}, rows)
		}
		if len(in.Errors) > 0 {
			bullets(m, "Partial (permissions)", in.Errors)
		}
		cfgFor(m, cfgFamilies["postgres"], in.Target)
	}
}

func mysqlMD(m md, d *inventory.MySQL) {
	for _, s := range d.Skipped {
		m.p("> skipped: %s", s)
	}
	for _, in := range d.Instances {
		m.h(3, in.Flavor+" — "+in.Target)
		m.p("via `%s`", in.Via)
		if len(in.Variables) == 0 {
			m.p("> could not connect: %s", strings.Join(in.Errors, "; "))
			continue
		}
		v, s := in.Variables, in.Status
		up, _ := strconv.ParseInt(s["Uptime"], 10, 64)
		m.kv("Version", v["version"]+" ("+v["version_comment"]+")", "Uptime", Dur(up), "Server ID", v["server_id"], "Read only", v["read_only"],
			"Connections now / peak / max", s["Threads_connected"]+" / "+s["Max_used_connections"]+" / "+v["max_connections"],
			"Buffer pool", hbi(i64s(v["innodb_buffer_pool_size"])), "Binlog", v["log_bin"]+" "+v["binlog_format"]+" gtid="+v["gtid_mode"],
			"Charset", v["character_set_server"]+" / "+v["collation_server"], "Data dir", v["datadir"])
		bullets(m, "Analysis", in.Analysis)
		bullets(m, "Who can connect (exposure)", in.Exposure)

		m.h(4, "Databases")
		var rows [][]string
		for _, db := range in.Databases {
			var eng []string
			for k, n := range db.Engines {
				eng = append(eng, fmt.Sprintf("%s:%d", k, n))
			}
			sort.Strings(eng)
			name := db.Name
			if db.System {
				name += " (system)"
			}
			rows = append(rows, []string{name, hbi(db.DataBytes + db.IndexBytes), hbi(db.DataBytes), hbi(db.IndexBytes), hbi(db.FreeBytes),
				strconv.FormatInt(db.Tables, 10), strconv.FormatInt(db.EstRows, 10), strings.Join(eng, " "),
				fmt.Sprintf("%d/%d/%d/%d", db.Views, db.Routines, db.Triggers, db.Events), strconv.FormatInt(db.NoPK, 10), db.Charset + "/" + db.Collation})
		}
		m.table([]string{"Database", "Total", "Data", "Index", "Free", "Tables", "Est. rows", "Engines", "Views/Routines/Triggers/Events", "No PK", "Charset"}, rows)

		m.h(4, "Largest tables")
		rows = nil
		for _, t := range in.Largest {
			rows = append(rows, []string{t.Schema + "." + t.Name, t.Engine, hbi(t.DataBytes + t.IndexBytes), hbi(t.DataBytes), hbi(t.IndexBytes), hbi(t.FreeBytes), strconv.FormatInt(t.EstRows, 10), t.Updated})
		}
		m.table([]string{"Table", "Engine", "Total", "Data", "Index", "Free", "Est. rows", "Updated"}, rows)
		if len(in.NoPKTables) > 0 {
			m.p("\n**Tables without primary key (%d):** %s", len(in.NoPKTables), strings.Join(limitS(in.NoPKTables, 60), ", "))
		}

		m.h(4, "Users & privileges")
		rows = nil
		for _, u := range in.Users {
			pw := "set"
			if u.EmptyPassword {
				pw = "EMPTY"
			}
			rows = append(rows, []string{u.User, u.Host, u.Plugin, pw, strings.Join(u.Global, ","), strings.Join(u.Schemas, "; ")})
		}
		m.table([]string{"User", "Host", "Auth plugin", "Password", "Global privileges", "Schema grants"}, rows)

		m.h(4, "Connections")
		rows = nil
		for _, c := range in.Connections {
			rows = append(rows, []string{c.User, c.Host, c.DB, c.Command, strconv.Itoa(c.N), strconv.Itoa(c.MaxTime) + "s"})
		}
		m.table([]string{"User", "Client", "DB", "Command", "Count", "Longest"}, rows)

		if in.Replica != nil || in.Binlog != nil || len(in.Group) > 0 || in.Galera != nil {
			m.h(4, "Replication / cluster")
			for _, kv := range []map[string]string{in.Replica, in.Binlog, in.Galera} {
				if kv == nil {
					continue
				}
				var pairs []string
				for k, val := range kv {
					pairs = append(pairs, k, val)
				}
				m.kv(pairs...)
			}
			bullets(m, "Group Replication", in.Group)
		}
		m.h(4, "Key variables")
		var pairs []string
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			pairs = append(pairs, k, v[k])
		}
		m.kv(pairs...)
		if len(in.Errors) > 0 {
			bullets(m, "Partial (permissions)", in.Errors)
		}
		cfgFor(m, cfgFamilies["mysql"], in.Target)
	}
}

func redisMD(m md, d *inventory.Redis) {
	for _, s := range d.Skipped {
		m.p("> skipped: %s", s)
	}
	for _, in := range d.Instances {
		m.h(3, "Redis — "+in.Target)
		m.p("via `%s` · auth required: %s", in.Via, yn(in.AuthNeeded))
		if in.Error != "" {
			m.p("> %s", in.Error)
			continue
		}
		i := in.Info
		m.kv("Version", firstOf(i["redis_version"], i["valkey_version"]), "Mode", i["redis_mode"], "Role", i["role"], "Uptime (days)", i["uptime_in_days"],
			"Memory used / RSS / peak / max", i["used_memory_human"]+" / "+i["used_memory_rss_human"]+" / "+i["used_memory_peak_human"]+" / "+i["maxmemory_human"],
			"Eviction policy", i["maxmemory_policy"], "Fragmentation", i["mem_fragmentation_ratio"],
			"Clients", i["connected_clients"]+" (max "+in.Config["maxclients"]+")", "Ops/sec", i["instantaneous_ops_per_sec"],
			"Hits / misses", i["keyspace_hits"]+" / "+i["keyspace_misses"], "Evicted / expired keys", i["evicted_keys"]+" / "+i["expired_keys"],
			"RDB last save", i["rdb_last_bgsave_status"]+" ("+i["rdb_changes_since_last_save"]+" changes since)", "AOF", i["aof_enabled"]+" "+i["aof_last_write_status"],
			"Master", strings.TrimSpace(i["master_host"]+" "+i["master_port"]+" "+i["master_link_status"]), "Connected replicas", i["connected_slaves"], "Config file", i["config_file"])
		bullets(m, "Who can connect (exposure)", in.Exposure)
		m.h(4, "Keyspace")
		var rows [][]string
		for db, val := range in.Keyspace {
			rows = append(rows, []string{db, val})
		}
		sort.Slice(rows, func(a, b int) bool { return rows[a][0] < rows[b][0] })
		m.table([]string{"DB", "keys / expires / avg_ttl"}, rows)
		m.h(4, "Connected clients (by IP)")
		rows = nil
		for _, c := range in.Clients {
			rows = append(rows, []string{c.Addr, c.User, strconv.Itoa(c.Count), c.DBs})
		}
		m.table([]string{"Client IP", "User", "Connections", "DBs"}, rows)
		bullets(m, "ACL users (secrets stripped)", in.Users)
		bullets(m, "Replicas", in.Replicas)
		var pairs []string
		for k, v := range in.Config {
			pairs = append(pairs, k, v)
		}
		m.h(4, "Config")
		m.kv(pairs...)
		if in.Cluster != nil {
			var cp []string
			for k, v := range in.Cluster {
				cp = append(cp, k, v)
			}
			m.h(4, "Cluster")
			m.kv(cp...)
		}
		cfgFor(m, cfgFamilies["redis"], in.Target)
	}
}

func cronMD(m md, d *inventory.Cron) {
	bullets(m, "", d.Summary)
	var rows [][]string
	for _, j := range d.Jobs {
		rows = append(rows, []string{j.User, "`" + j.Schedule + "`", j.Description, j.NextRun, strconv.FormatFloat(j.PerDay, 'f', -1, 64),
			"`" + trunc(j.Command, 140) + "`", strings.Join(j.Risks, "; "), j.Source})
	}
	m.h(3, "Cron jobs")
	m.table([]string{"User", "Schedule", "Meaning", "Next run", "Runs/day", "Command (redacted)", "Risks", "Source"}, rows)
	if len(d.Timers) > 0 {
		m.h(3, "systemd timers")
		rows = nil
		for _, t := range d.Timers {
			rows = append(rows, []string{t.Unit, t.Activates, t.Schedule, t.Next, t.Last})
		}
		m.table([]string{"Timer", "Runs", "OnCalendar", "Next", "Last"}, rows)
	}
	m.kv("Unreadable (need sudo)", strings.Join(d.Unreadable, ", "), "Process supervisors", strings.Join(d.Supervisors, ", "))
	if len(d.LaunchAgents) > 0 {
		m.h(3, "launchd jobs")
		m.p("```\n%s\n```", strings.Join(d.LaunchAgents, "\n"))
	}
}

// ExposureMD renders the open-port matrix.
func ExposureMD(r *inventory.Report) string {
	var b strings.Builder
	exposureBody(md{&b, nil}, r)
	return b.String()
}

func exposureBody(m md, r *inventory.Report) {
	hi := 0
	for _, e := range r.Exposure {
		if e.Risk == "high" {
			hi++
		}
	}
	m.h(2, fmt.Sprintf("Open Ports — Exposure Matrix (%d, %d high)", len(r.Exposure), hi))
	counts := map[string]int{}
	for _, e := range r.Exposure {
		counts[e.Scope]++
	}
	m.p("%d listening: %d all interfaces · %d public IP · %d private network · %d local only",
		len(r.Exposure), counts["all interfaces"], counts["public IP"], counts["private network"], counts["local only"])
	var rows [][]string
	for _, e := range r.Exposure {
		rows = append(rows, []string{strings.ToUpper(e.Risk), fmt.Sprintf("%d/%s", e.Port, e.Proto), e.Bind, e.Scope, firstOf(e.Service, "?"), e.Category,
			strings.TrimSpace(e.Process + " " + pid(e.PID)), e.Container, e.Firewall, e.Note})
	}
	m.table([]string{"Risk", "Port", "Bind", "Reachable from", "Service", "Category", "Process", "Container", "Firewall", "Note"}, rows)
	m.p("\nScope is from the host's view. NAT, cloud security groups, and upstream firewalls can further restrict reachability; verify with an authorized external scan.")
}

func i64s(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }

func limitStr(n int) string {
	if n < 0 {
		return "∞"
	}
	return strconv.Itoa(n)
}

func short(ts string) string {
	if len(ts) > 16 {
		return ts[:16]
	}
	return ts
}

func orDashStr(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func firstOf(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func limitS(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], fmt.Sprintf("… +%d more", len(s)-n))
	}
	return s
}

// cfgFamilies: which config-file engines belong to which report section.
var cfgFamilies = map[string][]string{
	"postgres":  {"postgresql", "pgbouncer", "patroni"},
	"mysql":     {"mysql", "mariadb", "proxysql"},
	"redis":     {"redis", "valkey", "redis-sentinel", "keydb", "dragonfly"},
	"services":  {"kafka", "rabbitmq", "vault", "consul", "etcd", "nats", "elasticsearch", "opensearch", "clickhouse", "minio", "influxdb", "zookeeper", "pulsar", "activemq", "mosquitto", "emqx", "redpanda"},
	"databases": {"*"}, // everything not claimed above (mongodb, cassandra, neo4j, ...)
}

func cfgFiles(m md) []inventory.DBConfigFile {
	if m.st == nil || m.st.report == nil {
		return nil
	}
	c := m.st.report.Collectors["dbconfig"]
	if c == nil {
		return nil
	}
	d, ok := c.Data.(*inventory.DBConfigs)
	if !ok {
		return nil
	}
	return d.Files
}

func inFamily(engine string, fam []string) bool {
	for _, f := range fam {
		if f == engine {
			return true
		}
		if f == "*" {
			for k, v := range cfgFamilies {
				if k == "databases" {
					continue
				}
				for _, e := range v {
					if e == engine {
						return false
					}
				}
			}
			return true
		}
	}
	return false
}

// whereOf maps an instance target ("container mx-pg", "container x via 127.0.0.1:1", "local unix socket") to a config location.
func whereOf(target string) string {
	if rest, ok := strings.CutPrefix(target, "container "); ok {
		name, _, _ := strings.Cut(rest, " ")
		return "container:" + name
	}
	if strings.HasPrefix(target, "local") {
		return "host"
	}
	return ""
}

func cfgKey(f inventory.DBConfigFile) string { return f.Where + "|" + f.Path }

func renderCfg(m md, files []inventory.DBConfigFile, title string) {
	if len(files) == 0 {
		return
	}
	m.h(4, title)
	for _, f := range files {
		m.st.shownCfg[cfgKey(f)] = true
		head := fmt.Sprintf("<b>%s</b> · <code>%s</code> · %s", html(f.Engine), html(f.Path), html(f.Where))
		if f.Error != "" {
			m.p("\n<div class=\"cfgline\">%s</div>\n\n> %s", head, f.Error)
			continue
		}
		m.p("\n<details class=\"cfg\">\n<summary>%s · %d active of %d lines</summary>\n\n```\n%s\n```\n\n</details>", head, len(f.Lines), f.Total, strings.Join(f.Lines, "\n"))
	}
}

// cfgFor renders the config files of one instance (matched by container/host) inside its section.
func cfgFor(m md, fam []string, target string) {
	where := whereOf(target)
	if where == "" || m.st == nil || m.st.shownCfg == nil {
		return
	}
	var fs []inventory.DBConfigFile
	for _, f := range cfgFiles(m) {
		if f.Where == where && inFamily(f.Engine, fam) && !m.st.shownCfg[cfgKey(f)] {
			fs = append(fs, f)
		}
	}
	renderCfg(m, fs, "Config files (active lines, secrets masked)")
}

// cfgLeftovers renders family config files not already shown with an instance.
func cfgLeftovers(m md, fam []string, title string) {
	if m.st == nil || m.st.shownCfg == nil {
		return
	}
	var fs []inventory.DBConfigFile
	for _, f := range cfgFiles(m) {
		if inFamily(f.Engine, fam) && !m.st.shownCfg[cfgKey(f)] {
			fs = append(fs, f)
		}
	}
	if len(fs) == 0 {
		return
	}
	m.h(3, title+" (active lines, secrets masked)")
	var cur string
	var batch []inventory.DBConfigFile
	flush := func() {
		renderCfg(m, batch, cur)
		batch = nil
	}
	for _, f := range fs {
		if f.Where != cur && len(batch) > 0 {
			flush()
		}
		cur = f.Where
		batch = append(batch, f)
	}
	flush()
}
