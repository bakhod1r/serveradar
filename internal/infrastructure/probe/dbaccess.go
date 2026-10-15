package probe

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
)

func init() {
	register(Collector{Name: "dbaccess", Title: "DB Open/Closed Check", Profiles: everywhere,
		Depends: []string{"databases", "ports", "docker"}, Collect: collectDBAccess})
}

// collectDBAccess dials every DB port found on this host via loopback and the LAN address, then performs
// an anonymous protocol handshake to learn whether the server demands credentials. No password is ever sent.
func collectDBAccess(c Ctx) (any, error) {
	dbs, _ := c.Prior("databases").(*inventory.Databases)
	if dbs == nil {
		return nil, ErrUnavailable("no database inventory")
	}
	res := &inventory.DBAccess{Note: "Tested from this host only. NAT, cloud security groups and upstream firewalls are not visible from here; run from another host for external reachability."}
	lan := lanIP(c)
	ports, _ := c.Prior("ports").(*inventory.Ports)
	owner := map[int]string{}
	if ports != nil {
		for _, s := range ports.Sockets {
			if s.Process != "" {
				owner[s.Port] = s.Process
			}
		}
	}
	type ep struct {
		kind, owner string
		port        int
	}
	var eps []ep
	seen := map[string]bool{}
	for _, s := range dbs.Services {
		for _, p := range s.Ports {
			k := s.Kind + strconv.Itoa(p)
			if seen[k] {
				continue
			}
			seen[k] = true
			o := owner[p]
			if dk, ok := c.Prior("docker").(*inventory.Docker); ok {
				for _, ct := range dk.Containers {
					for _, m := range ct.Ports {
						if strings.Contains(m, ":"+strconv.Itoa(p)+"->") {
							o = "container " + ct.Name
						}
					}
				}
			}
			eps = append(eps, ep{s.Kind, o, p})
		}
		if len(s.Ports) == 0 && s.Container != "" {
			res.Checks = append(res.Checks, inventory.DBAccessCheck{Engine: s.Kind, Owner: s.Container, Path: "not published",
				TCP: "n/a", Verdict: "CLOSED to host network (container-internal only)"})
		}
	}
	for _, e := range eps {
		targets := []struct{ addr, path string }{{"127.0.0.1", "loopback"}}
		if lan != "" {
			targets = append(targets, struct{ addr, path string }{lan, "LAN " + lan})
		}
		for _, t := range targets {
			if c.Err() != nil {
				break
			}
			chk := inventory.DBAccessCheck{Engine: e.kind, Owner: e.owner, Address: t.addr, Port: e.port, Path: t.path}
			if ports != nil { // a host process bound to this exact address wins over a docker wildcard publish
				for _, s := range ports.Sockets {
					if s.Port == e.port && s.Proto == "tcp" && s.Address == t.addr && s.Process != "" && !isDockerProxy(s.Process) {
						chk.Owner = "host process " + s.Process
					}
				}
			}
			addr := net.JoinHostPort(t.addr, strconv.Itoa(e.port))
			conn, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond)
			if err != nil {
				chk.TCP = "closed"
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					chk.TCP = "timeout"
				}
				chk.Verdict = "CLOSED via " + t.path
				res.Checks = append(res.Checks, chk)
				continue
			}
			chk.TCP = "open"
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			switch e.kind {
			case "postgresql", "pgbouncer", "patroni":
				chk.Auth, chk.Detail = pgHandshake(conn)
			case "mysql", "mariadb", "proxysql":
				chk.Auth, chk.Detail = mysqlHandshake(conn)
			case "redis", "valkey", "redis-sentinel":
				chk.Auth, chk.Detail = redisHandshake(conn)
			default:
				chk.Auth = "not probed (TCP only)"
			}
			conn.Close()
			chk.Verdict = accessVerdict(chk)
			res.Checks = append(res.Checks, chk)
		}
	}
	sortBy(res.Checks, func(a, b inventory.DBAccessCheck) bool {
		if a.Engine != b.Engine {
			return a.Engine < b.Engine
		}
		return a.Port < b.Port
	})
	return res, nil
}

func accessVerdict(c inventory.DBAccessCheck) string {
	a := strings.ToLower(c.Auth)
	switch {
	case strings.HasPrefix(a, "no auth"):
		return "OPEN WITHOUT PASSWORD via " + c.Path
	case strings.HasPrefix(a, "rejected"):
		return "TCP open, but server rejects this source (" + c.Path + ")"
	case strings.Contains(a, "password"), strings.Contains(a, "scram"), strings.Contains(a, "md5"), strings.Contains(a, "sha"), strings.Contains(a, "plugin"):
		return "OPEN, password required via " + c.Path
	}
	return "OPEN via " + c.Path
}

// pgHandshake sends a StartupMessage (user postgres) and reports which auth the server requests, then terminates.
func pgHandshake(conn net.Conn) (string, string) {
	var body []byte
	body = binary.BigEndian.AppendUint32(body, 196608) // protocol 3.0
	for _, kv := range [][2]string{{"user", "postgres"}, {"database", "postgres"}, {"application_name", "serveradar-probe"}} {
		body = append(append(append(append(body, kv[0]...), 0), kv[1]...), 0)
	}
	body = append(body, 0)
	msg := binary.BigEndian.AppendUint32(nil, uint32(len(body)+4))
	if _, err := conn.Write(append(msg, body...)); err != nil {
		return "unknown", err.Error()
	}
	defer conn.Write([]byte{'X', 0, 0, 0, 4}) // Terminate
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "unknown", "no response: " + err.Error()
	}
	n := int(binary.BigEndian.Uint32(hdr[1:])) - 4
	if n < 0 || n > 1<<16 {
		return "unknown", "bad length"
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return "unknown", err.Error()
	}
	switch hdr[0] {
	case 'R':
		if len(payload) < 4 {
			return "unknown", ""
		}
		switch binary.BigEndian.Uint32(payload) {
		case 0:
			return "NO AUTH (trust)", "server accepted user postgres without password"
		case 3:
			return "cleartext password", "AuthenticationCleartextPassword"
		case 5:
			return "md5 password", "AuthenticationMD5Password"
		case 10:
			return "scram-sha-256 password", strings.TrimRight(strings.ReplaceAll(string(payload[4:]), "\x00", " "), " ")
		case 7:
			return "GSSAPI", ""
		default:
			return "auth code " + strconv.Itoa(int(binary.BigEndian.Uint32(payload))), ""
		}
	case 'E':
		f := pgFields(payload)
		msg := f['M']
		if strings.Contains(msg, "pg_hba.conf") {
			return "rejected by pg_hba.conf", msg
		}
		return "error", f['C'] + " " + msg
	}
	return "unknown", fmt.Sprintf("message type %q", hdr[0])
}

func pgFields(p []byte) map[byte]string {
	m := map[byte]string{}
	for len(p) > 1 {
		k := p[0]
		i := 1
		for i < len(p) && p[i] != 0 {
			i++
		}
		m[k] = string(p[1:i])
		if i+1 > len(p) {
			break
		}
		p = p[i+1:]
	}
	return m
}

// mysqlHandshake reads the server greeting (sent before any credentials) or the host-rejection error.
func mysqlHandshake(conn net.Conn) (string, string) {
	r := bufio.NewReader(conn)
	h := make([]byte, 4)
	if _, err := io.ReadFull(r, h); err != nil {
		return "unknown", "no greeting: " + err.Error()
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	if n > 1<<16 {
		return "unknown", "bad length"
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return "unknown", err.Error()
	}
	if len(p) > 3 && p[0] == 0xff {
		msg := string(p[3:])
		if strings.HasPrefix(msg, "#") && len(msg) > 6 {
			msg = msg[6:]
		}
		if strings.Contains(msg, "not allowed") {
			return "rejected (host not allowed)", msg
		}
		return "error", msg
	}
	if len(p) < 2 || p[0] != 10 {
		return "unknown", "unexpected protocol"
	}
	end := 1
	for end < len(p) && p[end] != 0 {
		end++
	}
	version := string(p[1:end])
	plugin := ""
	if j := strings.LastIndexByte(string(p[:len(p)-1]), 0); j > 0 {
		plugin = strings.TrimRight(string(p[j+1:]), "\x00")
	}
	if plugin == "" || strings.ContainsAny(plugin, " \x01") {
		plugin = "?"
	}
	return "password (plugin " + plugin + ")", "server " + version + "; MySQL checks user@host at login"
}

func redisHandshake(conn net.Conn) (string, string) {
	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		return "unknown", err.Error()
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "unknown", err.Error()
	}
	line = strings.TrimSpace(line)
	switch {
	case line == "+PONG":
		return "NO AUTH", "PING answered without credentials"
	case strings.HasPrefix(line, "-NOAUTH"), strings.HasPrefix(line, "-WRONGPASS"):
		return "password required", line
	case strings.HasPrefix(line, "-DENIED"):
		return "rejected (protected-mode)", line
	}
	return "unknown", truncate(line, 80)
}


func isDockerProxy(p string) bool {
	return strings.HasPrefix(p, "com.docke") || strings.HasPrefix(p, "docker") || strings.HasPrefix(p, "vpnkit") || strings.HasPrefix(p, "rootlessk")
}
