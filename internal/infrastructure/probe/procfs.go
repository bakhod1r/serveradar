package probe

import (
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/redact"
)

// Linux /proc readers: no dependency on ps/ss (BusyBox, minimal images, distroless hosts).

const clkTck = 100.0 // USER_HZ on all mainstream Linux builds

func uidNames() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return m
	}
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Split(ln, ":")
		if len(f) > 2 {
			m[f[2]] = f[0]
		}
	}
	return m
}

func procList() (*inventory.ProcessList, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	up := 0.0
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		up, _ = strconv.ParseFloat(strings.Fields(string(b))[0], 64)
	}
	page := uint64(os.Getpagesize())
	users := uidNames()
	pl := &inventory.ProcessList{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := "/proc/" + e.Name()
		stat, err := os.ReadFile(dir + "/stat")
		if err != nil {
			continue
		}
		s := string(stat)
		lp, rp := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if lp < 0 || rp < lp {
			continue
		}
		comm := s[lp+1 : rp]
		f := strings.Fields(s[rp+1:]) // f[0]=state, f[1]=ppid, f[11]=utime, f[12]=stime, f[19]=starttime
		if len(f) < 22 {
			continue
		}
		p := inventory.Process{PID: pid, Comm: comm}
		p.PPID, _ = strconv.Atoi(f[1])
		ut, _ := strconv.ParseFloat(f[11], 64)
		st, _ := strconv.ParseFloat(f[12], 64)
		start, _ := strconv.ParseFloat(f[19], 64)
		if el := up - start/clkTck; el > 0 {
			p.CPU = float64(int((ut+st)/clkTck/el*1000)) / 10
			p.Start = durShort(el)
		}
		if b, err := os.ReadFile(dir + "/statm"); err == nil {
			if x := strings.Fields(string(b)); len(x) > 1 {
				r, _ := strconv.ParseUint(x[1], 10, 64)
				p.MemRSS = r * page
			}
		}
		if b, err := os.ReadFile(dir + "/status"); err == nil {
			for _, ln := range strings.Split(string(b), "\n") {
				if v, ok := strings.CutPrefix(ln, "Uid:"); ok {
					if u := strings.Fields(v); len(u) > 0 {
						p.User = users[u[0]]
						if p.User == "" {
							p.User = u[0]
						}
					}
					break
				}
			}
		}
		if b, err := os.ReadFile(dir + "/cmdline"); err == nil && len(b) > 0 {
			args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
			p.Cmdline = redact.Text(truncate(strings.Join(args, " "), 400))
			if base := filepath.Base(args[0]); base != "" && !strings.ContainsAny(args[0], " :") {
				p.Comm = base
			}
		} else {
			p.Cmdline = "[" + comm + "]"
		}
		pl.All = append(pl.All, p)
	}
	pl.Total = len(pl.All)
	return pl, nil
}

func durShort(sec float64) string {
	s := int64(sec)
	switch {
	case s >= 86400:
		return strconv.FormatInt(s/86400, 10) + "-" + pad2(s%86400/3600) + ":" + pad2(s%3600/60) + ":" + pad2(s%60)
	case s >= 3600:
		return pad2(s/3600) + ":" + pad2(s%3600/60) + ":" + pad2(s%60)
	}
	return pad2(s/60) + ":" + pad2(s%60)
}

func pad2(n int64) string {
	if n < 10 {
		return "0" + strconv.FormatInt(n, 10)
	}
	return strconv.FormatInt(n, 10)
}

// procSockets parses /proc/net/{tcp,tcp6,udp,udp6} for listening sockets and maps inodes to PIDs (own processes, or all as root).
func procSockets() ([]inventory.Socket, int) {
	inodePID := map[string]int{}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir("/proc/" + e.Name() + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if l, err := os.Readlink("/proc/" + e.Name() + "/fd/" + fd.Name()); err == nil && strings.HasPrefix(l, "socket:[") {
				inodePID[l[8:len(l)-1]] = pid
			}
		}
	}
	comm := func(pid int) string {
		b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
		return strings.TrimSpace(string(b))
	}
	var out []inventory.Socket
	unknown := 0
	for _, src := range []struct{ file, proto string }{{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"}} {
		b, err := os.ReadFile("/proc/net/" + src.file)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(ln)
			if len(f) < 10 {
				continue
			}
			state := f[3]
			if src.proto == "tcp" && state != "0A" || src.proto == "udp" && state != "07" { // LISTEN / UNCONN
				continue
			}
			if src.proto == "udp" && !strings.HasSuffix(f[2], ":0000") {
				continue
			}
			host, port := parseHexAddr(f[1])
			if port == 0 {
				continue
			}
			s := sockFrom(src.proto, net.JoinHostPort(host, strconv.Itoa(port)))
			if pid, ok := inodePID[f[9]]; ok {
				s.PID, s.Process = pid, comm(pid)
			} else {
				unknown++
			}
			out = append(out, s)
		}
	}
	return out, unknown
}

func parseHexAddr(s string) (string, int) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0
	}
	port, _ := strconv.ParseInt(p, 16, 32)
	raw, err := hex.DecodeString(h)
	if err != nil {
		return "", 0
	}
	// /proc stores addresses as host-endian 32-bit words
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	ip := net.IP(raw)
	if v4 := ip.To4(); v4 != nil && len(raw) == 16 && ip.IsUnspecified() {
		return "::", int(port)
	}
	return ip.String(), int(port)
}
