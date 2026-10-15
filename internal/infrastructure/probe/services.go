package probe

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
	"github.com/bakhod1r/serveradar/internal/infrastructure/redact"
)

func init() {
	register(Collector{Name: "services", Title: "Brokers, Vault & Other Services", Profiles: std,
		Depends: []string{"databases", "ports", "docker"}, Collect: collectServices})
}

// Only documented health/status endpoints that the services expose for monitoring are requested.
// No credentials are guessed; authenticated detail requires operator-supplied URLs (e.g. --rabbitmq).
var healthPaths = map[string][]string{
	"vault":         {"/v1/sys/health?standbyok=true&perfstandbyok=true&sealedcode=200&uninitcode=200"},
	"consul":        {"/v1/status/leader"},
	"elasticsearch": {"/"},
	"opensearch":    {"/"},
	"clickhouse":    {"/ping"},
	"minio":         {"/minio/health/live"},
	"rabbitmq":      {"/api/overview"},
	"etcd":          {"/health", "/version"},
	"nats":          {"/varz"},
	"influxdb":      {"/health"},
}

var kafkaEnvKeys = []string{"LISTENERS", "ADVERTISED_LISTENERS", "LISTENER_SECURITY_PROTOCOL_MAP", "INTER_BROKER_LISTENER_NAME",
	"SASL_ENABLED_MECHANISMS", "PROCESS_ROLES", "NODE_ID", "BROKER_ID", "CONTROLLER_QUORUM_VOTERS", "ZOOKEEPER_CONNECT",
	"AUTO_CREATE_TOPICS_ENABLE", "LOG_RETENTION_HOURS", "NUM_PARTITIONS", "DEFAULT_REPLICATION_FACTOR", "LOG_DIRS", "CLUSTER_ID"}

func httpClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // status metadata only; local endpoints often self-signed
		Proxy:           nil,
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func collectServices(c Ctx) (any, error) {
	dbs, _ := c.Prior("databases").(*inventory.Databases)
	if dbs == nil {
		return nil, ErrUnavailable("no service inventory")
	}
	res := &inventory.Services{}
	hc := httpClient()
	lan := lanIP(c)
	dk, _ := c.Prior("docker").(*inventory.Docker)
	for _, s := range dbs.Services {
		paths, http := healthPaths[s.Kind]
		if !http && s.Kind != "kafka" {
			continue
		}
		ck := inventory.ServiceCheck{Kind: s.Kind, Owner: firstNonEmpty(s.Container, pidsStr(s.PIDs)), Facts: map[string]string{}}
		if s.Kind == "kafka" {
			kafkaFacts(c, &ck, s, dk)
			res.Checks = append(res.Checks, ck)
			continue
		}
		done := false
		for _, port := range s.Ports {
			for _, host := range []string{"127.0.0.1", lan} {
				if host == "" || done {
					continue
				}
				for _, scheme := range []string{"http", "https"} {
					if done {
						break
					}
					for _, p := range paths {
						u := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + p
						code, body, err := get(hc, u)
						if err != nil {
							continue
						}
						ck.Endpoint = scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
						interpret(&ck, p, code, body)
						done = true
					}
				}
			}
		}
		if !done {
			ck.Auth = "no HTTP status endpoint reachable"
		}
		if s.Kind == "rabbitmq" {
			rabbitAuthed(c, hc, &ck)
		}
		res.Checks = append(res.Checks, ck)
	}
	if len(res.Checks) == 0 {
		return nil, ErrUnavailable("no brokers / secret stores / search services found")
	}
	return res, nil
}

func get(hc *http.Client, u string) (int, map[string]any, error) {
	resp, err := hc.Get(u)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	m := map[string]any{}
	if json.Unmarshal(b, &m) != nil {
		m["_text"] = truncate(strings.TrimSpace(string(b)), 120)
	}
	return resp.StatusCode, m, nil
}

func interpret(ck *inventory.ServiceCheck, path string, code int, body map[string]any) {
	f := ck.Facts
	str := func(k string) string {
		if v, ok := body[k]; ok && v != nil {
			return fmt.Sprint(v)
		}
		return ""
	}
	switch {
	case code == 401 || code == 403:
		ck.Auth = "authentication required (HTTP " + strconv.Itoa(code) + ")"
		return
	case code >= 200 && code < 300:
		ck.Auth = "anonymous access to status endpoint"
	default:
		ck.Auth = "HTTP " + strconv.Itoa(code)
	}
	switch ck.Kind {
	case "vault":
		for _, k := range []string{"version", "initialized", "sealed", "standby", "performance_standby", "cluster_name", "replication_dr_mode", "replication_performance_mode"} {
			if v := str(k); v != "" {
				f[k] = v
			}
		}
		ck.Auth = "health endpoint is public by design; secrets need a token"
		if f["sealed"] == "true" {
			ck.Notes = append(ck.Notes, "Vault is SEALED — secrets unavailable to apps")
		}
		if f["initialized"] == "false" {
			ck.Notes = append(ck.Notes, "Vault NOT initialized — anyone reaching it could initialize it")
		}
		if strings.HasPrefix(ck.Endpoint, "http://") {
			ck.Notes = append(ck.Notes, "Vault served over plain HTTP — tokens/secrets unencrypted in transit")
		}
	case "consul":
		f["leader"] = strings.Trim(str("_text"), `"`)
	case "elasticsearch", "opensearch":
		f["cluster_name"] = str("cluster_name")
		if v, ok := body["version"].(map[string]any); ok {
			f["version"] = fmt.Sprint(v["number"])
			f["distribution"] = fmt.Sprint(v["distribution"])
		}
		if code == 200 {
			ck.Notes = append(ck.Notes, "cluster answers without authentication — security plugin/xpack disabled")
		}
	case "clickhouse":
		f["ping"] = str("_text")
		ck.Auth = "ping endpoint public; queries need a user"
	case "minio":
		f["live"] = strconv.Itoa(code)
		ck.Auth = "health endpoint public; API needs access keys"
	case "rabbitmq":
		f["management_api"] = "reachable"
	case "etcd":
		if path == "/health" {
			f["health"] = str("health")
		} else {
			f["version"] = str("etcdserver")
			f["cluster_version"] = str("etcdcluster")
		}
		if code == 200 && strings.HasPrefix(ck.Endpoint, "http://") {
			ck.Notes = append(ck.Notes, "etcd client port over plain HTTP — if no client cert auth, keys (incl. Kubernetes secrets) readable")
		}
	case "nats":
		for _, k := range []string{"version", "server_name", "connections", "auth_required", "tls_required", "jetstream", "max_payload"} {
			if v := str(k); v != "" {
				f[k] = truncate(v, 80)
			}
		}
		if f["auth_required"] != "true" {
			ck.Notes = append(ck.Notes, "NATS clients connect without auth")
		}
	case "influxdb":
		f["status"] = str("status")
		f["version"] = str("version")
	}
}

// rabbitAuthed: detailed overview only with operator-supplied URL in SERVERADAR_RABBITMQ_URL (http://user:pass@host:15672).
func rabbitAuthed(c Ctx, hc *http.Client, ck *inventory.ServiceCheck) {
	raw := os.Getenv("SERVERADAR_RABBITMQ_URL")
	if raw == "" {
		ck.Notes = append(ck.Notes, "set SERVERADAR_RABBITMQ_URL=http://user:pass@host:15672 for queues/vhosts/connections")
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	call := func(path string) ([]byte, int) {
		req, _ := http.NewRequestWithContext(c, "GET", strings.TrimRight(u.Scheme+"://"+u.Host, "/")+path, nil)
		if u.User != nil {
			p, _ := u.User.Password()
			req.SetBasicAuth(u.User.Username(), p)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, 0
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return b, resp.StatusCode
	}
	ck.Endpoint = redact.URL(raw)
	if b, code := call("/api/overview"); code == 200 {
		var o map[string]any
		_ = json.Unmarshal(b, &o)
		ck.Facts["rabbitmq_version"] = fmt.Sprint(o["rabbitmq_version"])
		ck.Facts["cluster_name"] = fmt.Sprint(o["cluster_name"])
		if t, ok := o["object_totals"].(map[string]any); ok {
			for k, v := range t {
				ck.Facts["total_"+k] = fmt.Sprint(v)
			}
		}
		if q, ok := o["queue_totals"].(map[string]any); ok {
			ck.Facts["messages_ready"] = fmt.Sprint(q["messages_ready"])
			ck.Facts["messages_unacked"] = fmt.Sprint(q["messages_unacknowledged"])
		}
	} else {
		ck.Notes = append(ck.Notes, "overview with supplied credentials: HTTP "+strconv.Itoa(code))
		return
	}
	if b, code := call("/api/queues?columns=name,vhost,messages,consumers,state"); code == 200 {
		var qs []map[string]any
		_ = json.Unmarshal(b, &qs)
		noCons := 0
		for _, q := range qs {
			if fmt.Sprint(q["consumers"]) == "0" && fmt.Sprint(q["messages"]) != "0" {
				noCons++
				if noCons <= 10 {
					ck.Notes = append(ck.Notes, fmt.Sprintf("queue %s/%s has %v messages and no consumers", q["vhost"], q["name"], q["messages"]))
				}
			}
		}
		ck.Facts["queues"] = strconv.Itoa(len(qs))
	}
	if b, code := call("/api/vhosts"); code == 200 {
		var vs []map[string]any
		_ = json.Unmarshal(b, &vs)
		var names []string
		for _, v := range vs {
			names = append(names, fmt.Sprint(v["name"]))
		}
		ck.Facts["vhosts"] = strings.Join(names, ", ")
	}
}

// kafkaFacts: listener/security layout from server.properties or container env (non-secret keys only).
func kafkaFacts(c Ctx, ck *inventory.ServiceCheck, s inventory.Service, dk *inventory.Docker) {
	for _, f := range s.Configs {
		if facts := configFacts(c, "kafka", f); facts != nil {
			for k, v := range facts {
				ck.Facts[k] = v
			}
		}
	}
	if dk != nil {
		for _, ct := range dk.Containers {
			if !strings.Contains(s.Container, ct.Name) || ct.State != "running" {
				continue
			}
			out, _ := execx.Run(c, 5*time.Second, "docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", ct.Name)
			for _, ln := range strings.Split(out, "\n") {
				k, v, ok := strings.Cut(ln, "=")
				if !ok || sensitiveKey(k) {
					continue
				}
				for _, want := range kafkaEnvKeys {
					if strings.HasSuffix(k, "_"+want) && strings.HasPrefix(k, "KAFKA") {
						ck.Facts[strings.ToLower(want)] = v
					}
				}
			}
			ck.Owner = "container " + ct.Name
		}
	}
	ck.Auth = "per listener (see security_protocol_map)"
	pm := strings.ToUpper(ck.Facts["listener_security_protocol_map"] + " " + ck.Facts["listeners"])
	if pm == " " {
		ck.Auth = "unknown (no config visible)"
		return
	}
	if strings.Contains(pm, "PLAINTEXT") && !strings.Contains(pm, "SASL_PLAINTEXT") {
		ck.Notes = append(ck.Notes, "PLAINTEXT listener: no authentication, no encryption on that listener")
	}
	if strings.Contains(pm, "SASL_PLAINTEXT") {
		ck.Notes = append(ck.Notes, "SASL_PLAINTEXT: credentials sent without TLS")
	}
	if adv := ck.Facts["advertised_listeners"]; strings.Contains(adv, "0.0.0.0") {
		ck.Notes = append(ck.Notes, "advertised.listeners contains 0.0.0.0 — clients cannot connect correctly")
	}
	if ck.Facts["auto_create_topics_enable"] == "true" {
		ck.Notes = append(ck.Notes, "auto.create.topics.enable=true — typos create topics")
	}
	if rf := ck.Facts["default_replication_factor"]; rf == "1" {
		ck.Notes = append(ck.Notes, "default replication factor 1 — no redundancy")
	}
}

func pidsStr(p []int) string {
	if len(p) == 0 {
		return ""
	}
	return "pid " + ints2(p)
}

func ints2(s []int) string {
	var o []string
	for _, x := range s {
		o = append(o, strconv.Itoa(x))
	}
	return strings.Join(o, ",")
}
