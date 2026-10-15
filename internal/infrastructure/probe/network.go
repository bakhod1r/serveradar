package probe

import (
	"fmt"
	"net"
	"slices"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
	"github.com/bakhod1r/serveradar/internal/domain/inventory"
)

func init() {
	register(Collector{Name: "network", Title: "Network", Profiles: everywhere, Collect: collectNetwork})
	register(Collector{Name: "ports", Title: "Listening Ports", Profiles: everywhere, Collect: collectPorts})
}

func collectNetwork(c Ctx) (any, error) {
	n := &inventory.Network{ConnStates: map[string]int{}}
	ifs, err := net.Interfaces()
	if err != nil {
		c.Warn("interfaces: %v", err)
	}
	for _, i := range ifs {
		it := inventory.Interface{Name: i.Name, MAC: i.HardwareAddr.String(), MTU: i.MTU, Up: i.Flags&net.FlagUp != 0}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			it.Addrs = append(it.Addrs, a.String())
		}
		if len(it.Addrs) == 0 && !it.Up {
			continue
		}
		n.Interfaces = append(n.Interfaces, it)
	}
	if runtime.GOOS == "linux" {
		for _, fam := range []string{"-4", "-6"} {
			out, err := execx.Run(c, 5*time.Second, "ip", fam, "route", "show")
			if err != nil {
				c.Warn("ip route: %v", err)
				continue
			}
			n.Routes = append(n.Routes, nonEmpty(strings.Split(out, "\n"))...)
		}
		if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
			n.IPForward = strings.TrimSpace(string(b))
		}
		if out, err := execx.Run(c, 5*time.Second, "ss", "-Htan"); err == nil {
			for _, ln := range strings.Split(out, "\n") {
				if f := strings.Fields(ln); len(f) > 0 {
					n.ConnStates[f[0]]++
				}
			}
		}
	} else {
		if out, err := execx.Run(c, 5*time.Second, "netstat", "-rn"); err == nil {
			for _, ln := range strings.Split(out, "\n") {
				if strings.HasPrefix(ln, "default") {
					n.Routes = append(n.Routes, strings.Join(strings.Fields(ln), " "))
				}
			}
		}
		if out, err := execx.Run(c, 5*time.Second, "netstat", "-an", "-p", "tcp"); err == nil {
			for _, ln := range strings.Split(out, "\n") {
				if f := strings.Fields(ln); len(f) >= 6 && strings.HasPrefix(f[0], "tcp") {
					n.ConnStates[f[5]]++
				}
			}
		}
	}
	if kv, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, ln := range strings.Split(string(kv), "\n") {
			if f := strings.Fields(ln); len(f) >= 2 && f[0] == "nameserver" {
				n.Nameservers = append(n.Nameservers, f[1])
			}
		}
	}
	return n, nil
}

var ssProc = regexp.MustCompile(`\("([^"]+)",pid=(\d+)`)

func collectPorts(c Ctx) (any, error) {
	p := &inventory.Ports{}
	if runtime.GOOS == "linux" && !execx.Has("ss") {
		p.Method = "/proc/net"
		var unknown int
		p.Sockets, unknown = procSockets()
		if unknown > 0 && os.Geteuid() != 0 {
			c.Warn("not root: owner of %d sockets hidden", unknown)
		}
	} else if runtime.GOOS == "linux" {
		p.Method = "ss -tulpn"
		out, err := execx.Run(c, 10*time.Second, "ss", "-Htulpn")
		if err != nil && out == "" {
			return nil, err
		}
		for _, ln := range strings.Split(out, "\n") {
			f := strings.Fields(ln)
			if len(f) < 5 {
				continue
			}
			if f[0] == "udp" && f[1] != "UNCONN" || f[0] == "tcp" && f[1] != "LISTEN" {
				continue
			}
			s := sockFrom(f[0], f[4])
			if m := ssProc.FindStringSubmatch(ln); m != nil {
				s.Process = m[1]
				s.PID, _ = strconv.Atoi(m[2])
			}
			p.Sockets = append(p.Sockets, s)
		}
		if os.Geteuid() != 0 {
			c.Warn("not root: owning process for other users' sockets hidden")
		}
	} else if execx.Has("lsof") {
		p.Method = "lsof"
		for _, q := range [][]string{{"-nP", "-iTCP", "-sTCP:LISTEN"}, {"-nP", "-iUDP"}} {
			out, _ := execx.Run(c, 15*time.Second, "lsof", q...)
			for _, ln := range strings.Split(out, "\n")[1:] {
				f := strings.Fields(ln)
				if len(f) < 9 {
					continue
				}
				proto := strings.ToLower(f[7])
				addr := f[8]
				if strings.Contains(addr, "->") {
					continue
				}
				s := sockFrom(proto, addr)
				s.Process = strings.ReplaceAll(f[0], `\x20`, " ")
				s.PID, _ = strconv.Atoi(f[1])
				p.Sockets = append(p.Sockets, s)
			}
		}
		if os.Geteuid() != 0 {
			c.Warn("not root: only current user's sockets visible")
		}
	} else {
		return nil, ErrUnavailable("no ss/lsof")
	}
	p.Sockets = dedupeSockets(p.Sockets)
	ipLists(c, p)
	sortBy(p.Sockets, func(a, b inventory.Socket) bool {
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Proto < b.Proto
	})
	return p, nil
}

// ipLists: local addresses + remote peers of established TCP connections (metadata only, no payload).
func ipLists(c Ctx, p *inventory.Ports) {
	if ifs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifs {
			p.LocalIPs = append(p.LocalIPs, a.String())
		}
	}
	type pair struct{ local, remote string }
	var pairs []pair
	if runtime.GOOS == "linux" && execx.Has("ss") {
		out, _ := execx.Run(c, 10*time.Second, "ss", "-Htn", "state", "established")
		for _, ln := range strings.Split(out, "\n") {
			if f := strings.Fields(ln); len(f) >= 4 {
				pairs = append(pairs, pair{f[2], f[3]})
			}
		}
	} else {
		out, _ := execx.Run(c, 10*time.Second, "netstat", "-an", "-p", "tcp")
		for _, ln := range strings.Split(out, "\n") {
			if f := strings.Fields(ln); len(f) >= 6 && f[5] == "ESTABLISHED" {
				pairs = append(pairs, pair{f[3], f[4]})
			}
		}
	}
	if len(pairs) == 0 && execx.Has("lsof") { // fallback: own processes only unless root
		out, _ := execx.Run(c, 10*time.Second, "lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED")
		for _, ln := range strings.Split(out, "\n") {
			f := strings.Fields(ln)
			if len(f) >= 9 {
				if l, r, ok := strings.Cut(f[8], "->"); ok {
					pairs = append(pairs, pair{l, r})
				}
			}
		}
		if len(pairs) > 0 && os.Geteuid() != 0 {
			p.PeerNote = "lsof fallback: only current user's connections"
		}
	}
	peers := map[string]*inventory.Peer{}
	for _, pr := range pairs {
		r, l := sockFrom("tcp", pr.remote), sockFrom("tcp", pr.local)
		if r.Address == "127.0.0.1" || r.Address == "::1" {
			continue
		}
		x := peers[r.Address]
		if x == nil {
			x = &inventory.Peer{Address: r.Address}
			peers[r.Address] = x
		}
		x.Count++
		if len(x.Ports) < 10 && !slices.Contains(x.Ports, l.Port) {
			x.Ports = append(x.Ports, l.Port)
		}
	}
	for _, x := range peers {
		p.Peers = append(p.Peers, *x)
	}
	sortBy(p.Peers, func(a, b inventory.Peer) bool { return a.Count > b.Count })
	if len(p.Peers) > 200 {
		p.PeerNote = fmt.Sprintf("%d peers, showing top 200", len(p.Peers))
		p.Peers = p.Peers[:200]
	}
}

func sockFrom(proto, local string) inventory.Socket {
	i := strings.LastIndexAny(local, ":.")
	host, port := local, ""
	if i >= 0 {
		host, port = local[:i], local[i+1:]
	}
	host = strings.Trim(host, "[]")
	if j := strings.Index(host, "%"); j >= 0 {
		host = host[:j]
	}
	if host == "*" {
		host = "0.0.0.0"
	}
	s := inventory.Socket{Proto: strings.TrimRight(proto, "46"), Address: host}
	s.Port, _ = strconv.Atoi(port)
	s.Public = host == "0.0.0.0" || host == "::" || host == ""
	return s
}

func dedupeSockets(in []inventory.Socket) []inventory.Socket {
	seen := map[string]bool{}
	var out []inventory.Socket
	for _, s := range in {
		k := s.Proto + s.Address + strconv.Itoa(s.Port) + strconv.Itoa(s.PID)
		if !seen[k] && s.Port > 0 {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

func nonEmpty(s []string) []string {
	var o []string
	for _, x := range s {
		if x = strings.TrimSpace(x); x != "" {
			o = append(o, x)
		}
	}
	return o
}
