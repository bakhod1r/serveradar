// Package exposure classifies every listening port: who can reach it, what it is, how risky. Pure domain logic.
package exposure

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
)

type category string

const (
	catData  category = "database/cache"
	catAdmin category = "admin/control-plane"
	catWeb   category = "web"
	catRemote category = "remote access"
	catDev   category = "dev/debug"
	catMail  category = "mail"
	catInfra category = "infra"
	catOther category = "other"
)

type known struct {
	name string
	cat  category
}

var wellKnown = map[int]known{
	22: {"SSH", catRemote}, 23: {"Telnet", catRemote}, 3389: {"RDP", catRemote}, 5900: {"VNC", catRemote},
	80: {"HTTP", catWeb}, 443: {"HTTPS", catWeb}, 8443: {"HTTPS-alt", catWeb}, 8080: {"HTTP-alt", catWeb},
	25: {"SMTP", catMail}, 465: {"SMTPS", catMail}, 587: {"Submission", catMail}, 993: {"IMAPS", catMail}, 143: {"IMAP", catMail}, 110: {"POP3", catMail},
	53: {"DNS", catInfra}, 123: {"NTP", catInfra}, 111: {"rpcbind", catAdmin}, 2049: {"NFS", catAdmin}, 445: {"SMB", catAdmin}, 139: {"NetBIOS", catAdmin},
	5432: {"PostgreSQL", catData}, 6432: {"PgBouncer", catData}, 3306: {"MySQL", catData}, 33060: {"MySQL X", catData},
	6379: {"Redis", catData}, 26379: {"Redis Sentinel", catData}, 27017: {"MongoDB", catData}, 9042: {"Cassandra", catData},
	9200: {"Elasticsearch", catData}, 9300: {"Elasticsearch transport", catData}, 11211: {"Memcached", catData},
	8123: {"ClickHouse HTTP", catData}, 9000: {"ClickHouse/MinIO", catData}, 5672: {"RabbitMQ", catData}, 15672: {"RabbitMQ UI", catAdmin},
	9092: {"Kafka", catData}, 2181: {"ZooKeeper", catData}, 4222: {"NATS", catData}, 8086: {"InfluxDB", catData},
	2375: {"Docker API (plain!)", catAdmin}, 2376: {"Docker API TLS", catAdmin}, 2377: {"Swarm", catAdmin},
	2379: {"etcd", catAdmin}, 2380: {"etcd peer", catAdmin}, 6443: {"Kubernetes API", catAdmin}, 10250: {"kubelet", catAdmin},
	10255: {"kubelet RO", catAdmin}, 8500: {"Consul", catAdmin}, 8200: {"Vault", catAdmin}, 9090: {"Prometheus", catAdmin},
	9100: {"node_exporter", catAdmin}, 3000: {"Grafana/dev", catDev}, 5000: {"dev server", catDev}, 8000: {"dev server", catDev},
	4200: {"Angular dev", catDev}, 5173: {"Vite dev", catDev}, 9229: {"Node inspector", catDev}, 5005: {"JVM debug", catDev},
	6060: {"Go pprof", catDev}, 8888: {"Jupyter", catDev}, 10000: {"Webmin", catAdmin}, 9001: {"MinIO console", catAdmin},
}

// Analyze builds the exposure matrix.
func Analyze(r *inventory.Report, ports *inventory.Ports, dk *inventory.Docker, fw *inventory.Firewall) []inventory.PortExposure {
	if ports == nil {
		return nil
	}
	pub := map[int]string{}
	if dk != nil {
		for _, c := range dk.Containers {
			for _, p := range c.Ports {
				i := strings.Index(p, "->")
				if i < 0 {
					continue
				}
				if hp, err := strconv.Atoi(p[strings.LastIndex(p[:i], ":")+1 : i]); err == nil {
					pub[hp] = c.Name + " (" + p[i+2:] + ")"
				}
			}
		}
	}
	ufw := parseUFW(fw)
	var out []inventory.PortExposure
	seen := map[string]bool{}
	for _, s := range ports.Sockets {
		scope := scopeOf(s.Address)
		key := s.Proto + strconv.Itoa(s.Port) + scope
		if seen[key] {
			continue
		}
		seen[key] = true
		k, ok := wellKnown[s.Port]
		if !ok {
			k = known{"", catOther}
		}
		e := inventory.PortExposure{Proto: s.Proto, Port: s.Port, Bind: s.Address, Scope: scope, Process: s.Process, PID: s.PID,
			Service: k.name, Category: string(k.cat), Container: pub[s.Port]}
		e.Firewall = ufw.verdict(s.Port, s.Proto, e.Container != "")
		e.Risk, e.Note = risk(e, k.cat)
		out = append(out, e)
	}
	order := map[string]int{"high": 0, "medium": 1, "low": 2, "info": 3}
	sort.SliceStable(out, func(i, j int) bool {
		if order[out[i].Risk] != order[out[j].Risk] {
			return order[out[i].Risk] < order[out[j].Risk]
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func scopeOf(addr string) string {
	switch addr {
	case "0.0.0.0", "::", "", "*":
		return "all interfaces"
	}
	ip := net.ParseIP(addr)
	switch {
	case ip == nil:
		return "unknown"
	case ip.IsLoopback():
		return "local only"
	case ip.IsPrivate() || ip.IsLinkLocalUnicast() || inCGNAT(ip):
		return "private network"
	default:
		return "public IP"
	}
}

func inCGNAT(ip net.IP) bool {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n.Contains(ip)
}

func risk(e inventory.PortExposure, cat category) (string, string) {
	if e.Scope == "local only" {
		return "info", "not reachable from network"
	}
	blocked := strings.HasPrefix(e.Firewall, "blocked")
	wide := e.Scope == "all interfaces" || e.Scope == "public IP"
	switch {
	case blocked && e.Container == "":
		return "low", "listening broadly but host firewall blocks it"
	case cat == catAdmin && wide:
		return "high", "control-plane port reachable from network — restrict to VPN/allowlist"
	case cat == catData && wide:
		return "high", "database/cache reachable from network — bind to localhost/private or firewall it"
	case cat == catRemote && e.Port != 22 && wide:
		return "high", "legacy remote access exposed"
	case cat == catDev && wide:
		return "medium", "dev/debug service exposed — should not face the network"
	case cat == catData || cat == catAdmin:
		return "medium", "reachable on private network — confirm only trusted hosts can reach it"
	case cat == catRemote:
		return "low", "SSH exposed — ensure keys only, fail2ban/rate limits"
	case cat == catWeb:
		return "low", "expected public web port"
	case wide:
		return "medium", "unknown service on all interfaces — identify owner"
	}
	return "low", ""
}

type ufwRules struct {
	active      bool
	defaultDeny bool
	allow       map[string]bool
	deny        map[string]bool
}

func parseUFW(fw *inventory.Firewall) ufwRules {
	u := ufwRules{allow: map[string]bool{}, deny: map[string]bool{}}
	if fw == nil || !strings.Contains(fw.UFW, "active") || strings.Contains(fw.UFW, "inactive") {
		return u
	}
	u.active = true
	for _, ln := range fw.Rules {
		f := strings.Fields(ln)
		if strings.HasPrefix(ln, "Default:") {
			u.defaultDeny = strings.Contains(ln, "deny (incoming)") || strings.Contains(ln, "reject (incoming)")
			continue
		}
		if len(f) < 2 {
			continue
		}
		target := f[0]
		switch {
		case strings.HasPrefix(f[1], "ALLOW"):
			u.allow[target] = true
		case strings.HasPrefix(f[1], "DENY"), strings.HasPrefix(f[1], "REJECT"):
			u.deny[target] = true
		}
	}
	return u
}

func (u ufwRules) verdict(port int, proto string, docker bool) string {
	if !u.active {
		return "unknown (no ufw data; run with sudo / check nft/iptables)"
	}
	p := strconv.Itoa(port)
	note := ""
	if docker {
		note = " — NOTE: Docker-published ports bypass ufw (DOCKER chain)"
	}
	switch {
	case u.deny[p] || u.deny[p+"/"+proto]:
		return "blocked by ufw rule" + note
	case u.allow[p] || u.allow[p+"/"+proto]:
		return "allowed by ufw" + note
	case u.defaultDeny:
		if docker {
			return "NOT blocked: ufw default deny, but Docker bypasses ufw"
		}
		return "blocked by ufw default policy"
	}
	return "allowed (ufw default allow)" + note
}
