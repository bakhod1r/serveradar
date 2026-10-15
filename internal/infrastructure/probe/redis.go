package probe

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/redact"
)

func init() {
	register(Collector{Name: "redis", Title: "Redis Inspection", Profiles: everywhere,
		Depends: []string{"databases", "docker", "ports"}, Collect: collectRedis})
}

// Only these commands are ever sent. All read-only.
var redisAllowed = map[string]bool{"PING": true, "AUTH": true, "HELLO": true, "INFO": true, "CONFIG": true, "CLIENT": true, "ACL": true, "CLUSTER": true, "ROLE": true}

// Non-secret config keys. requirepass/masterauth are never requested.
var redisConfigKeys = []string{"bind", "port", "protected-mode", "maxmemory", "maxmemory-policy", "appendonly", "appendfsync", "save",
	"dir", "dbfilename", "tls-port", "cluster-enabled", "replica-read-only", "rename-command", "maxclients", "timeout", "databases", "io-threads"}

var redisInfoKeys = []string{"redis_version", "valkey_version", "redis_mode", "os", "uptime_in_days", "tcp_port", "executable", "config_file",
	"connected_clients", "blocked_clients", "maxclients", "used_memory_human", "used_memory_rss_human", "used_memory_peak_human", "maxmemory_human",
	"maxmemory_policy", "mem_fragmentation_ratio", "evicted_keys", "expired_keys", "rejected_connections", "total_connections_received",
	"instantaneous_ops_per_sec", "keyspace_hits", "keyspace_misses", "rdb_last_save_time", "rdb_last_bgsave_status", "rdb_changes_since_last_save",
	"aof_enabled", "aof_last_write_status", "role", "connected_slaves", "master_host", "master_port", "master_link_status",
	"master_last_io_seconds_ago", "master_repl_offset", "cluster_enabled", "used_cpu_sys", "used_cpu_user"}

type respConn struct {
	c net.Conn
	r *bufio.Reader
}

func dialRedis(addr string, timeout time.Duration) (*respConn, error) {
	network := "tcp"
	if strings.HasPrefix(addr, "/") {
		network = "unix"
	}
	c, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	return &respConn{c: c, r: bufio.NewReader(c)}, nil
}

func (rc *respConn) do(args ...string) (any, error) {
	if !redisAllowed[strings.ToUpper(args[0])] {
		return nil, fmt.Errorf("command %s not allowed", args[0])
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := rc.c.Write([]byte(b.String())); err != nil {
		return nil, err
	}
	return rc.read()
}

type redisErr string

func (e redisErr) Error() string { return string(e) }

func (rc *respConn) read() (any, error) {
	line, err := rc.r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, errors.New("empty reply")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, redisErr(line[1:])
	case ':':
		n, _ := strconv.ParseInt(line[1:], 10, 64)
		return n, nil
	case '$':
		n, _ := strconv.Atoi(line[1:])
		if n < 0 {
			return nil, nil
		}
		if n > 8<<20 {
			return nil, errors.New("reply too large")
		}
		buf := make([]byte, n+2)
		if _, err := ioReadFull(rc.r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, _ := strconv.Atoi(line[1:])
		if n > 100000 {
			return nil, errors.New("reply too large")
		}
		out := make([]any, 0, max(n, 0))
		for i := 0; i < n; i++ {
			v, err := rc.read()
			if err != nil {
				if _, isRE := err.(redisErr); !isRE {
					return nil, err
				}
			}
			out = append(out, v)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unexpected reply %q", truncate(line, 40))
}

func ioReadFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

type redisTarget struct {
	label, addr, user, pass, via string
	published                    []string
}

func collectRedis(c Ctx) (any, error) {
	pol := c.Policy()
	if !pol.RedisEnabled() {
		return nil, ErrUnavailable("authenticated inspection off: use --redis-local, --redis URL or --profile deep")
	}
	res := &inventory.Redis{}
	var targets []redisTarget
	seen := map[string]bool{}
	add := func(t redisTarget) {
		if !seen[t.addr] {
			seen[t.addr] = true
			targets = append(targets, t)
		}
	}
	for _, raw := range pol.RedisURLs {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			res.Skipped = append(res.Skipped, "bad URL "+redact.URL(raw))
			continue
		}
		t := redisTarget{label: redact.URL(raw), addr: u.Host, via: "url"}
		if u.User != nil {
			t.user = u.User.Username()
			t.pass, _ = u.User.Password()
			if t.pass == "" { // redis://:pass@ form puts password in username slot? no: Username()=="" and Password()==pass
				t.pass, t.user = t.user, ""
			}
		}
		if !strings.Contains(t.addr, ":") {
			t.addr += ":6379"
		}
		add(t)
	}
	if pol.RedisLocal || pol.Profile == "deep" {
		if ports, ok := c.Prior("ports").(*inventory.Ports); ok {
			for _, s := range ports.Sockets {
				if s.Proto == "tcp" && (strings.Contains(s.Process, "redis") || strings.Contains(s.Process, "valkey")) {
					host := s.Address
					if s.Public || host == "" {
						host = "127.0.0.1"
					}
					if host == "::1" || host == "::" {
						host = "127.0.0.1"
					}
					add(redisTarget{label: fmt.Sprintf("local %s:%d (%s)", host, s.Port, s.Process), addr: net.JoinHostPort(host, strconv.Itoa(s.Port)), via: "tcp"})
				}
			}
		}
		if dk, ok := c.Prior("docker").(*inventory.Docker); ok {
			for _, ct := range dk.Containers {
				img := strings.ToLower(ct.Image)
				if ct.State != "running" || !(strings.Contains(img, "redis") || strings.Contains(img, "valkey")) || strings.Contains(img, "exporter") {
					continue
				}
				// published host port mapped to 6379
				for _, p := range ct.Ports {
					if strings.HasSuffix(p, "->6379/tcp") && !strings.HasPrefix(p, ":::") {
						hp := p[strings.LastIndex(p[:strings.Index(p, "->")], ":")+1 : strings.Index(p, "->")]
						addr := "127.0.0.1:" + hp
						if seen[addr] { // loopback port owned by another (host) redis; reach docker via a LAN address
							if ip := lanIP(c); ip != "" {
								addr = net.JoinHostPort(ip, hp)
							}
						}
						add(redisTarget{label: "container " + ct.Name + " via " + addr, addr: addr, via: "published port", published: ct.Ports})
					}
				}
			}
		}
	}
	if len(targets) == 0 {
		return nil, ErrUnavailable("no Redis endpoints to inspect")
	}
	for _, t := range targets {
		if c.Err() != nil {
			break
		}
		inst := inspectRedis(t)
		if inst.Error != "" {
			c.Warn("%s: %s", t.label, inst.Error)
		}
		res.Instances = append(res.Instances, inst)
	}
	return res, nil
}

func inspectRedis(t redisTarget) inventory.RedisInstance {
	inst := inventory.RedisInstance{Target: t.label, Via: t.via, Info: map[string]string{}, Config: map[string]string{}, Keyspace: map[string]string{}}
	rc, err := dialRedis(t.addr, 3*time.Second)
	if err != nil {
		inst.Error = "connect: " + err.Error()
		return inst
	}
	defer rc.c.Close()
	if t.pass != "" {
		args := []string{"AUTH", t.pass}
		if t.user != "" {
			args = []string{"AUTH", t.user, t.pass}
		}
		if _, err := rc.do(args...); err != nil {
			inst.Error = "auth failed: " + err.Error()
			return inst
		}
	}
	info, err := rc.do("INFO", "everything")
	if err != nil {
		if strings.HasPrefix(err.Error(), "NOAUTH") || strings.Contains(err.Error(), "NOPERM") {
			inst.AuthNeeded = true
			inst.Error = "password required (good). Pass --redis redis://:PASS@host:port to inspect"
		} else {
			inst.Error = err.Error()
		}
		return inst
	}
	inst.AuthNeeded = t.pass != ""
	want := map[string]bool{}
	for _, k := range redisInfoKeys {
		want[k] = true
	}
	section := ""
	for _, ln := range strings.Split(fmt.Sprint(info), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "# ") {
			section = strings.ToLower(ln[2:])
			continue
		}
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		switch {
		case section == "keyspace":
			inst.Keyspace[k] = v
		case section == "replication" && strings.HasPrefix(k, "slave") && k != "slave_read_only" && strings.Contains(v, "ip="):
			inst.Replicas = append(inst.Replicas, v)
		case want[k]:
			inst.Info[k] = v
		}
	}
	for _, key := range redisConfigKeys {
		v, err := rc.do("CONFIG", "GET", key)
		if err != nil {
			if key == "bind" {
				inst.Config["_note"] = "CONFIG not permitted: " + err.Error()
				break
			}
			continue
		}
		if arr, ok := v.([]any); ok && len(arr) == 2 {
			inst.Config[key] = fmt.Sprint(arr[1])
		}
	}
	if v, err := rc.do("ACL", "LIST"); err == nil {
		if arr, ok := v.([]any); ok {
			for _, x := range arr {
				inst.Users = append(inst.Users, stripACLSecrets(fmt.Sprint(x)))
			}
		}
	}
	if v, err := rc.do("CLIENT", "LIST"); err == nil {
		inst.Clients = groupClients(fmt.Sprint(v))
	}
	if inst.Info["cluster_enabled"] == "1" {
		if v, err := rc.do("CLUSTER", "INFO"); err == nil {
			inst.Cluster = map[string]string{}
			for _, ln := range strings.Split(fmt.Sprint(v), "\n") {
				if k, val, ok := strings.Cut(strings.TrimSpace(ln), ":"); ok {
					inst.Cluster[k] = val
				}
			}
		}
	}
	inst.Exposure = redisExposure(inst, t.published)
	return inst
}

// stripACLSecrets removes >password, #hash, <password and !hash tokens from an ACL rule.
func stripACLSecrets(rule string) string {
	var keep []string
	for _, tok := range strings.Fields(rule) {
		if tok == "" || strings.ContainsAny(tok[:1], "><#!") {
			continue
		}
		keep = append(keep, tok)
	}
	s := strings.Join(keep, " ")
	if strings.Contains(rule, " nopass") {
		s += "  [NO PASSWORD]"
	}
	return s
}

func groupClients(list string) []inventory.RedisClientGroup {
	g := map[string]*inventory.RedisClientGroup{}
	for _, ln := range strings.Split(list, "\n") {
		kv := map[string]string{}
		for _, f := range strings.Fields(ln) {
			if k, v, ok := strings.Cut(f, "="); ok {
				kv[k] = v
			}
		}
		addr := kv["addr"]
		if addr == "" {
			continue
		}
		if h, _, err := net.SplitHostPort(addr); err == nil {
			addr = h
		}
		key := addr + "|" + kv["user"]
		x := g[key]
		if x == nil {
			x = &inventory.RedisClientGroup{Addr: addr, User: kv["user"]}
			g[key] = x
		}
		x.Count++
		if !strings.Contains(","+x.DBs+",", ","+kv["db"]+",") {
			x.DBs = appendCSV(x.DBs, kv["db"])
		}
	}
	var out []inventory.RedisClientGroup
	for _, x := range g {
		out = append(out, *x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func redisExposure(inst inventory.RedisInstance, published []string) []string {
	var out []string
	bind := inst.Config["bind"]
	switch {
	case bind == "":
		if _, ok := inst.Config["_note"]; ok {
			out = append(out, "bind unknown (CONFIG blocked)")
		} else {
			out = append(out, "bind empty: ALL interfaces")
		}
	case anyTok(bind, "0.0.0.0", "*", "::", "-::*", "*:*"):
		out = append(out, "bind '"+bind+"': ALL interfaces")
	case allLoopback(bind):
		out = append(out, "bind '"+bind+"': local only")
	default:
		out = append(out, "bind '"+bind+"': specific addresses")
	}
	for _, p := range published {
		out = append(out, "docker publishes "+p)
	}
	if inst.Config["protected-mode"] == "no" && !inst.AuthNeeded {
		out = append(out, "protected-mode no + no password: anyone reaching the port has full access")
	} else if !inst.AuthNeeded {
		out = append(out, "no password required for this endpoint")
	}
	for _, u := range inst.Users {
		if strings.Contains(u, "[NO PASSWORD]") && strings.Contains(u, " on ") {
			out = append(out, "ACL user without password: "+strings.Fields(u)[1])
		}
	}
	if inst.Config["tls-port"] == "0" || inst.Config["tls-port"] == "" {
		out = append(out, "TLS disabled")
	}
	return out
}

func anyTok(s string, toks ...string) bool {
	for _, f := range strings.Fields(s) {
		for _, t := range toks {
			if f == t {
				return true
			}
		}
	}
	return false
}

func allLoopback(s string) bool {
	for _, f := range strings.Fields(s) {
		ip := net.ParseIP(strings.TrimPrefix(f, "-"))
		if f != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return false
		}
	}
	return true
}

func lanIP(c Ctx) string {
	if p, ok := c.Prior("ports").(*inventory.Ports); ok {
		for _, a := range p.LocalIPs {
			ip, _, err := net.ParseCIDR(a)
			if err == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip.String()
			}
		}
	}
	return ""
}
