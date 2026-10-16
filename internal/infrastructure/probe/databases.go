package probe

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
)

func init() {
	register(Collector{Name: "databases", Title: "Databases & Data Services", Profiles: std,
		Depends: []string{"processes", "ports", "docker"}, Collect: collectDatabases})
}

type dbSig struct {
	kind    string
	procs   []string // matched against comm / first arg basename
	ports   []int
	images  []string
	configs []string // globs
}

var dbSigs = []dbSig{
	{"postgresql", []string{"postgres", "postmaster"}, []int{5432}, []string{"postgres", "postgis", "timescale"}, []string{"/etc/postgresql/*/*/postgresql.conf", "/var/lib/pgsql/*/data/postgresql.conf", "/var/lib/pgsql/data/postgresql.conf", "/opt/homebrew/var/postgres*/postgresql.conf"}},
	{"pgbouncer", []string{"pgbouncer"}, []int{6432}, []string{"pgbouncer"}, []string{"/etc/pgbouncer/pgbouncer.ini"}},
	{"patroni", []string{"patroni"}, []int{8008}, []string{"patroni"}, []string{"/etc/patroni/*.yml", "/etc/patroni.yml"}},
	{"mysql", []string{"mysqld"}, []int{3306, 33060}, []string{"mysql", "percona"}, []string{"/etc/mysql/my.cnf", "/etc/mysql/mysql.conf.d/*.cnf", "/etc/my.cnf"}},
	{"mariadb", []string{"mariadbd"}, []int{3306}, []string{"mariadb"}, []string{"/etc/mysql/mariadb.conf.d/*.cnf"}},
	{"proxysql", []string{"proxysql"}, []int{6033, 6032}, []string{"proxysql"}, []string{"/etc/proxysql.cnf"}},
	{"redis", []string{"redis-server"}, []int{6379}, []string{"redis"}, []string{"/etc/redis/redis.conf", "/etc/redis.conf", "/opt/homebrew/etc/redis.conf"}},
	{"redis-sentinel", []string{"redis-sentinel"}, []int{26379}, nil, []string{"/etc/redis/sentinel.conf"}},
	{"valkey", []string{"valkey-server"}, []int{6379}, []string{"valkey"}, []string{"/etc/valkey/valkey.conf"}},
	{"mongodb", []string{"mongod"}, []int{27017, 27018, 27019}, []string{"mongo"}, []string{"/etc/mongod.conf", "/etc/mongodb.conf", "/opt/homebrew/etc/mongod.conf", "/usr/local/etc/mongod.conf"}},
	{"mongos", []string{"mongos"}, nil, nil, []string{"/etc/mongos.conf"}},
	{"clickhouse", []string{"clickhouse-server", "clickhouse"}, []int{8123, 9000}, []string{"clickhouse"}, []string{"/etc/clickhouse-server/config.xml"}},
	{"elasticsearch", []string{"elasticsearch"}, []int{9200, 9300}, []string{"elasticsearch"}, []string{"/etc/elasticsearch/elasticsearch.yml"}},
	{"opensearch", []string{"opensearch"}, []int{9200}, []string{"opensearch"}, []string{"/etc/opensearch/opensearch.yml"}},
	{"rabbitmq", []string{"beam.smp", "rabbitmq-server"}, []int{5672, 15672}, []string{"rabbitmq"}, []string{"/etc/rabbitmq/rabbitmq.conf"}},
	{"kafka", []string{"kafka"}, []int{9092}, []string{"kafka", "redpanda"}, []string{"/etc/kafka/server.properties", "/opt/kafka/config/server.properties"}},
	{"zookeeper", []string{"zookeeper"}, []int{2181}, []string{"zookeeper"}, nil},
	{"etcd", []string{"etcd"}, []int{2379, 2380}, []string{"etcd"}, nil},
	{"memcached", []string{"memcached"}, []int{11211}, []string{"memcached"}, nil},
	{"nats", []string{"nats-server"}, []int{4222}, []string{"nats"}, nil},
	{"cassandra", []string{"cassandra"}, []int{9042}, []string{"cassandra", "scylla"}, []string{"/etc/cassandra/cassandra.yaml"}},
	{"influxdb", []string{"influxd"}, []int{8086}, []string{"influxdb"}, nil},
	{"minio", []string{"minio"}, []int{9000}, []string{"minio"}, nil},
	{"vault", []string{"vault"}, []int{8200}, []string{"vault", "openbao"}, []string{"/etc/vault.d/*.hcl", "/etc/vault/*.hcl"}},
	{"consul", []string{"consul"}, []int{8500}, []string{"consul"}, []string{"/etc/consul.d/*.hcl", "/etc/consul.d/*.json"}},
}

func collectDatabases(c Ctx) (any, error) {
	db := &inventory.Databases{}
	pl, _ := c.Prior("processes").(*inventory.ProcessList)
	ports, _ := c.Prior("ports").(*inventory.Ports)
	dk, _ := c.Prior("docker").(*inventory.Docker)

	for si, sig := range dbSigs {
		s := inventory.Service{Kind: sig.kind}
		jvmName := sig.kind == "elasticsearch" || sig.kind == "opensearch" || sig.kind == "kafka" || sig.kind == "zookeeper" || sig.kind == "cassandra"
		pids := map[int]bool{}
		if pl != nil {
			for _, p := range pl.All {
				hit := false
				for _, n := range sig.procs {
					if p.Comm == n || jvmName && (p.Comm == "java") && strings.Contains(strings.ToLower(p.Cmdline), n) {
						hit = true
					}
				}
				if sig.kind == "rabbitmq" && p.Comm == "beam.smp" && !strings.Contains(p.Cmdline, "rabbit") {
					hit = false
				}
				if hit {
					s.PIDs = append(s.PIDs, p.PID)
					pids[p.PID] = true
					if sig.kind == "mongodb" {
						if rs := flagVal(p.Cmdline, "--replSet"); rs != "" {
							s.Cluster = "replicaSet=" + rs
						}
					}
				}
			}
			if len(s.PIDs) > 0 {
				s.Source = append(s.Source, "process")
			}
		}
		if ports != nil {
			for _, so := range ports.Sockets {
				if pids[so.PID] || so.PID == 0 && si < baseDBSigs && containsInt(sig.ports, so.Port) && sig.kind != "minio" {
					if !containsInt(s.Ports, so.Port) {
						s.Ports = append(s.Ports, so.Port)
					}
				}
			}
			if len(s.Ports) > 0 && len(s.PIDs) == 0 {
				s.Source = append(s.Source, "well-known port (possible)")
			}
		}
		if dk != nil {
			for _, ct := range dk.Containers {
				img := strings.ToLower(ct.Image)
				for _, im := range sig.images {
					if strings.Contains(img, im) && !strings.Contains(img, "exporter") && !strings.Contains(ct.Name, "exporter") && !(sig.kind == "postgresql" && strings.Contains(img, "bouncer")) {
						s.Container = appendCSV(s.Container, ct.Name+"("+ct.State+")")
						for _, pm := range ct.Ports {
							if hp, _, ok := strings.Cut(pm[strings.LastIndex(pm[:strings.Index(pm, "->")], ":")+1:], "->"); ok {
								if n, err := strconv.Atoi(hp); err == nil && !containsInt(s.Ports, n) {
									s.Ports = append(s.Ports, n)
								}
							}
						}
						s.Source = appendUniq(s.Source, "docker image")
					}
				}
			}
		}
		for _, g := range sig.configs {
			m, _ := filepath.Glob(g)
			for _, f := range m {
				s.Configs = append(s.Configs, f)
			}
		}
		if len(s.Configs) > 0 {
			s.Source = append(s.Source, "config file")
		}
		if len(s.Source) == 0 {
			continue
		}
		for _, f := range s.Configs {
			facts := configFacts(c, sig.kind, f)
			if sig.kind == "mongodb" || sig.kind == "mongos" {
				md := mongoConf(f)
				db.Mongo = append(db.Mongo, md)
				if md.ReplSet != "" {
					s.Cluster = "replicaSet=" + md.ReplSet
				}
				if md.ShardRole != "" {
					s.Cluster = appendCSV(s.Cluster, "sharding="+md.ShardRole)
				}
				continue
			}
			if facts != nil {
				db.Configs = append(db.Configs, inventory.DBConfigFacts{Kind: sig.kind, Path: f, Facts: facts})
				if h := clusterHint(sig.kind, facts); h != "" {
					s.Cluster = appendCSV(s.Cluster, h)
				}
			}
		}
		db.Services = append(db.Services, s)
	}
	return db, nil
}

// configFacts: whitelisted keys only. Secrets like requirepass become "set"/"unset".
func configFacts(c Ctx, kind, path string) map[string]string {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsPermission(err) {
			c.Warn("%s: permission denied", path)
		}
		return nil
	}
	keys := map[string][]string{
		"postgresql":     {"listen_addresses", "port", "ssl", "wal_level", "max_connections", "data_directory", "hba_file", "archive_mode", "hot_standby", "primary_conninfo", "shared_buffers"},
		"mysql":          {"bind-address", "port", "server-id", "gtid_mode", "log_bin", "require_secure_transport", "datadir", "group_replication_group_name", "wsrep_on", "wsrep_cluster_name"},
		"mariadb":        {"bind-address", "port", "server-id", "log_bin", "datadir", "wsrep_on", "wsrep_cluster_name"},
		"redis":          {"bind", "port", "protected-mode", "requirepass", "replicaof", "slaveof", "cluster-enabled", "appendonly", "maxmemory", "save", "tls-port"},
		"valkey":         {"bind", "port", "protected-mode", "requirepass", "replicaof", "cluster-enabled", "appendonly", "maxmemory"},
		"redis-sentinel": {"port", "sentinel monitor"},
		"pgbouncer":      {"listen_addr", "listen_port", "pool_mode", "max_client_conn", "auth_type"},
		"elasticsearch":  {"cluster.name", "network.host", "http.port", "discovery.seed_hosts", "xpack.security.enabled"},
		"opensearch":     {"cluster.name", "network.host", "http.port", "discovery.seed_hosts"},
		"kafka":          {"broker.id", "node.id", "listeners", "advertised.listeners", "process.roles", "zookeeper.connect", "log.dirs"},
		"cassandra":      {"cluster_name", "listen_address", "rpc_address", "seeds"},
	}[kind]
	if keys == nil {
		return map[string]string{"present": "yes"}
	}
	secret := map[string]bool{"requirepass": true, "primary_conninfo": true}
	f := map[string]string{}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln[0] == '#' || ln[0] == ';' || ln[0] == '[' {
			continue
		}
		for _, k := range keys {
			rest, ok := strings.CutPrefix(ln, k)
			if !ok || rest != "" && !strings.ContainsAny(rest[:1], " \t=:") {
				continue
			}
			v := strings.Trim(strings.TrimSpace(strings.TrimLeft(rest, " \t=:")), `"'`)
			if i := strings.Index(v, " #"); i >= 0 {
				v = strings.TrimSpace(v[:i])
			}
			if secret[k] {
				v = "set"
			}
			if old, ok := f[k]; ok && k == "save" {
				v = old + "; " + v
			}
			f[k] = v
		}
	}
	if kind == "postgresql" {
		hba := f["hba_file"]
		if hba == "" {
			hba = filepath.Join(filepath.Dir(path), "pg_hba.conf")
		}
		if rules := broadHBA(hba); rules != "" {
			f["pg_hba_broad_rules"] = rules
		}
	}
	return f
}

func broadHBA(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		x := strings.Fields(ln)
		if len(x) < 5 || strings.HasPrefix(x[0], "#") || x[0] == "local" {
			continue
		}
		addr, method := x[3], x[len(x)-1]
		if addr == "0.0.0.0/0" || addr == "::/0" || addr == "all" || method == "trust" {
			out = append(out, strings.Join(x, " "))
		}
	}
	return strings.Join(out, " | ")
}

func clusterHint(kind string, f map[string]string) string {
	switch kind {
	case "postgresql":
		if f["primary_conninfo"] == "set" {
			return "standby (primary_conninfo set)"
		}
		if f["wal_level"] == "replica" || f["wal_level"] == "logical" {
			return "wal_level=" + f["wal_level"]
		}
	case "mysql", "mariadb":
		if f["wsrep_on"] == "ON" || f["wsrep_on"] == "1" {
			return "galera:" + f["wsrep_cluster_name"]
		}
		if f["group_replication_group_name"] != "" {
			return "group-replication"
		}
		if f["server-id"] != "" && f["log_bin"] != "" {
			return "binlog replication capable"
		}
	case "redis", "valkey":
		if f["cluster-enabled"] == "yes" {
			return "redis-cluster"
		}
		if f["replicaof"] != "" || f["slaveof"] != "" {
			return "replica"
		}
	case "elasticsearch", "opensearch", "cassandra":
		for _, k := range []string{"cluster.name", "cluster_name"} {
			if f[k] != "" {
				return "cluster=" + f[k]
			}
		}
	case "kafka":
		if f["process.roles"] != "" {
			return "kraft:" + f["process.roles"]
		}
	}
	return ""
}

// mongoConf: minimal indentation-aware YAML reader for mongod.conf keys.
func mongoConf(path string) inventory.MongoDetail {
	md := inventory.MongoDetail{ConfigPath: path}
	b, err := os.ReadFile(path)
	if err != nil {
		return md
	}
	var stack []struct {
		indent int
		key    string
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if i := strings.Index(ln, "#"); i >= 0 {
			ln = ln[:i]
		}
		if strings.TrimSpace(ln) == "" {
			continue
		}
		indent := len(ln) - len(strings.TrimLeft(ln, " "))
		k, v, ok := strings.Cut(strings.TrimSpace(ln), ":")
		if !ok {
			continue
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		var parts []string
		for _, s := range stack {
			parts = append(parts, s.key)
		}
		full := strings.Join(append(parts, k), ".")
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if v == "" {
			stack = append(stack, struct {
				indent int
				key    string
			}{indent, k})
			continue
		}
		switch full {
		case "net.bindIp":
			md.BindIP = v
		case "net.bindIpAll":
			if v == "true" {
				md.BindIP = "0.0.0.0 (bindIpAll)"
			}
		case "net.port":
			md.Port, _ = strconv.Atoi(v)
		case "replication.replSetName":
			md.ReplSet = v
		case "security.authorization":
			md.Authorization = v
		case "net.tls.mode", "net.ssl.mode":
			md.TLSMode = v
		case "storage.dbPath":
			md.DBPath = v
		case "sharding.clusterRole":
			md.ShardRole = v
		}
	}
	if md.Authorization == "" {
		md.Authorization = "disabled (default)"
	}
	if md.BindIP == "" {
		md.BindIP = "127.0.0.1 (default)"
	}
	return md
}

func flagVal(cmd, flag string) string {
	f := strings.Fields(cmd)
	for i, x := range f {
		if x == flag && i+1 < len(f) {
			return f[i+1]
		}
		if v, ok := strings.CutPrefix(x, flag+"="); ok {
			return v
		}
	}
	return ""
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func appendCSV(s, v string) string {
	if s == "" {
		return v
	}
	return s + ", " + v
}
