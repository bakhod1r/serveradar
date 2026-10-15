package probe

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
	"github.com/bakhod1r/serveradar/internal/infrastructure/redact"
)

func init() {
	register(Collector{Name: "dbconfig", Title: "DB Config Files", Profiles: std,
		Depends: []string{"databases", "docker", "postgres", "redis"}, Collect: collectDBConfig})
}

var hostConfigGlobs = map[string][]string{
	"postgresql": {"/etc/postgresql/*/*/postgresql.conf", "/etc/postgresql/*/*/pg_hba.conf", "/etc/postgresql/*/*/conf.d/*.conf",
		"/var/lib/pgsql/*/data/postgresql.conf", "/var/lib/pgsql/*/data/pg_hba.conf", "/var/lib/pgsql/data/postgresql.conf", "/var/lib/pgsql/data/pg_hba.conf",
		"/opt/homebrew/var/postgres*/postgresql.conf", "/opt/homebrew/var/postgres*/pg_hba.conf"},
	"pgbouncer": {"/etc/pgbouncer/pgbouncer.ini"},
	"mysql":     {"/etc/mysql/my.cnf", "/etc/mysql/conf.d/*.cnf", "/etc/mysql/mysql.conf.d/*.cnf", "/etc/my.cnf", "/etc/my.cnf.d/*.cnf"},
	"mariadb":   {"/etc/mysql/mariadb.conf.d/*.cnf", "/etc/mysql/mariadb.cnf"},
	"redis":     {"/etc/redis/redis.conf", "/etc/redis.conf", "/opt/homebrew/etc/redis.conf", "/usr/local/etc/redis.conf"},
	"valkey":    {"/etc/valkey/valkey.conf"},
	"mongodb":   {"/etc/mongod.conf", "/etc/mongodb.conf", "/opt/homebrew/etc/mongod.conf", "/usr/local/etc/mongod.conf"},
	"clickhouse": {"/etc/clickhouse-server/config.d/*.xml", "/etc/clickhouse-server/users.d/*.xml"},
	"elasticsearch": {"/etc/elasticsearch/elasticsearch.yml"},
	"rabbitmq":  {"/etc/rabbitmq/rabbitmq.conf"},
	"kafka":     {"/etc/kafka/server.properties", "/opt/kafka/config/server.properties", "/opt/kafka/config/kraft/server.properties"},
	"vault":     {"/etc/vault.d/*.hcl", "/etc/vault/*.hcl"},
	"consul":    {"/etc/consul.d/*.hcl", "/etc/consul.d/*.json"},
	"nats":      {"/etc/nats/*.conf", "/etc/nats-server.conf"},
	"etcd":      {"/etc/etcd/etcd.conf", "/etc/etcd/etcd.conf.yml", "/etc/default/etcd"},
	"opensearch": {"/etc/opensearch/opensearch.yml"},
}

// container paths read with `cat` via docker exec (opt-in); $PGDATA resolved inside the container
var containerConfigScript = map[string]string{
	"postgresql": `for f in "${PGDATA:-/var/lib/postgresql/data}/postgresql.conf" "${PGDATA:-/var/lib/postgresql/data}/postgresql.auto.conf" "${PGDATA:-/var/lib/postgresql/data}/pg_hba.conf"; do [ -f "$f" ] && echo "### FILE $f" && cat "$f"; done`,
	"mysql":      `for f in /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/conf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf /etc/mysql/mariadb.conf.d/*.cnf /etc/my.cnf.d/*.cnf; do [ -f "$f" ] && echo "### FILE $f" && cat "$f"; done`,
	"redis":      `for f in /usr/local/etc/redis/redis.conf /etc/redis/redis.conf /data/redis.conf /etc/redis.conf; do [ -f "$f" ] && echo "### FILE $f" && cat "$f"; done`,
	"rabbitmq":   `for f in /etc/rabbitmq/rabbitmq.conf /etc/rabbitmq/conf.d/*.conf /etc/rabbitmq/advanced.config; do [ -f "$f" ] && echo "### FILE $f" && cat "$f"; done`,
	"kafka":      `for f in /opt/kafka/config/server.properties /opt/kafka/config/kraft/server.properties /etc/kafka/server.properties /opt/bitnami/kafka/config/server.properties; do [ -f "$f" ] && echo "### FILE $f" && cat "$f"; done`,
	"vault":      `for f in /vault/config/*.hcl /vault/config/*.json /etc/vault.d/*.hcl; do [ -f "$f" ] && echo "### FILE $f" && cat "$f"; done`,
	"elasticsearch": `for f in /usr/share/elasticsearch/config/elasticsearch.yml; do [ -f "$f" ] && echo "### FILE $f" && cat "$f"; done`,
	"clickhouse": `for f in /etc/clickhouse-server/config.d/*.xml /etc/clickhouse-server/users.d/*.xml; do [ -f "$f" ] && echo "### FILE $f" && cat "$f"; done`,
	"mongodb":    `for f in /etc/mongod.conf /etc/mongod.conf.orig /etc/mongo/mongod.conf; do [ -f "$f" ] && echo "### FILE $f" && cat "$f"; done`,
}

var secretKeyRe = regexp.MustCompile(`(?i)(pass(word|wd)?|requirepass|masterauth|secret|token|api[_-]?key|credential|primary_conninfo|auth_pass|admin_pass|private)`)

func collectDBConfig(c Ctx) (any, error) {
	res := &inventory.DBConfigs{}
	dbs, _ := c.Prior("databases").(*inventory.Databases)
	if dbs == nil {
		return nil, ErrUnavailable("no database inventory")
	}
	kinds := map[string]bool{}
	containers := map[string][]string{} // kind -> container names
	for _, s := range dbs.Services {
		kinds[s.Kind] = true
		if s.Container != "" {
			for _, part := range strings.Split(s.Container, ", ") {
				if name, state, ok := strings.Cut(part, "("); ok && strings.HasPrefix(state, "running") {
					containers[s.Kind] = append(containers[s.Kind], name)
				}
			}
		}
	}
	for kind := range kinds {
		for _, g := range hostConfigGlobs[kind] {
			m, _ := filepath.Glob(g)
			for _, f := range m {
				b, err := os.ReadFile(f)
				cf := inventory.DBConfigFile{Engine: kind, Where: "host", Path: f}
				if err != nil {
					cf.Error = err.Error()
					if os.IsPermission(err) {
						cf.Error = "permission denied (run with sudo)"
					}
				} else {
					cf.Lines, cf.Total = activeLines(kind, string(b))
				}
				res.Files = append(res.Files, cf)
			}
		}
	}
	pol := c.Policy()
	inContainers := pol.PGDocker || pol.MySQLDocker || pol.RedisLocal || pol.Profile == "deep"
	if !inContainers {
		if len(containers) > 0 {
			res.Notes = append(res.Notes, "container config files skipped: use --db (docker exec cat, read-only) or --profile deep")
		}
	} else {
		for kind, names := range containers {
			script := containerConfigScript[kind]
			if kind == "mariadb" {
				script = containerConfigScript["mysql"]
			}
			if script == "" {
				continue
			}
			for _, name := range names {
				out, err := execx.Run(c, 8*time.Second, "docker", "exec", name, "sh", "-c", script)
				if out == "" {
					cf := inventory.DBConfigFile{Engine: kind, Where: "container:" + name, Path: "(none)", Error: "no config file in container — running on image defaults + command-line flags"}
					if err != nil && !strings.Contains(err.Error(), "exit status 1") {
						cf.Error = firstLine(err.Error())
					}
					res.Files = append(res.Files, cf)
					continue
				}
				for _, chunk := range strings.Split(out, "### FILE ")[1:] {
					path, body, _ := strings.Cut(chunk, "\n")
					cf := inventory.DBConfigFile{Engine: kind, Where: "container:" + name, Path: path}
					cf.Lines, cf.Total = activeLines(kind, body)
					res.Files = append(res.Files, cf)
				}
			}
		}
	}
	if dk, ok := c.Prior("docker").(*inventory.Docker); ok {
		for _, ct := range dk.Containers {
			for kind, names := range containers {
				for _, n := range names {
					if n == ct.Name && ct.Cmd != "" {
						res.Files = append(res.Files, inventory.DBConfigFile{Engine: kind, Where: "container:" + n, Path: "(command line)", Lines: []string{ct.Cmd}, Total: 1})
					}
				}
			}
		}
	}
	sortBy(res.Files, func(a, b inventory.DBConfigFile) bool {
		if a.Engine != b.Engine {
			return a.Engine < b.Engine
		}
		return a.Where+a.Path < b.Where+b.Path
	})
	return res, nil
}

// activeLines returns non-comment, non-empty directives with secrets masked.
func activeLines(kind, text string) ([]string, int) {
	var out []string
	all := strings.Split(text, "\n")
	xml := kind == "clickhouse"
	for _, ln := range all {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") || xml && strings.HasPrefix(t, "<!--") {
			continue
		}
		if i := strings.Index(t, " #"); i > 0 && kind != "redis" {
			t = strings.TrimSpace(t[:i])
		}
		if i := strings.Index(t, "\t#"); i > 0 {
			t = strings.TrimSpace(t[:i])
		}
		if secretKeyRe.MatchString(t) {
			if k, _, ok := cutKey(t); ok {
				t = k + " = " + redact.Mask
			} else {
				t = redact.Text(t)
			}
		}
		out = append(out, redact.Text(t))
		if len(out) >= 400 {
			out = append(out, "… truncated")
			break
		}
	}
	return out, len(all)
}

func cutKey(t string) (string, string, bool) {
	for _, sep := range []string{"=", ":", " ", "\t"} {
		if k, v, ok := strings.Cut(t, sep); ok && strings.TrimSpace(k) != "" {
			return strings.TrimSpace(k), v, true
		}
	}
	return "", "", false
}
