package probe

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
	"github.com/bakhod1r/serveradar/internal/infrastructure/redact"
)

func init() {
	register(Collector{Name: "processes", Title: "Processes", Profiles: everywhere, Collect: collectProcesses})
	register(Collector{Name: "resources", Title: "Resource Usage", Profiles: everywhere, Depends: []string{"processes", "host"}, Collect: collectResources})
}

func collectProcesses(c Ctx) (any, error) {
	if runtime.GOOS == "linux" {
		if pl, err := procList(); err == nil && pl.Total > 0 {
			return pl, nil
		}
	}
	out, err := execx.Run(c, 10*time.Second, "ps", "-axww", "-o", "pid=,ppid=,user=,pcpu=,rss=,etime=,args=")
	if err != nil && out == "" {
		return nil, err
	}
	pl := &inventory.ProcessList{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 7 {
			continue
		}
		p := inventory.Process{User: f[2], Start: f[5]}
		p.PID, _ = strconv.Atoi(f[0])
		p.PPID, _ = strconv.Atoi(f[1])
		p.CPU, _ = strconv.ParseFloat(f[3], 64)
		rss, _ := strconv.ParseUint(f[4], 10, 64)
		p.MemRSS = rss * 1024
		args := f[6:]
		p.Comm = filepath.Base(args[0])
		if strings.HasPrefix(args[0], "[") { // kernel thread
			p.Comm = strings.Trim(strings.Join(args, " "), "[]")
		}
		p.Cmdline = redact.Text(truncate(strings.Join(args, " "), 400))
		pl.All = append(pl.All, p)
	}
	pl.Total = len(pl.All)
	return pl, nil
}

// ---- resources: who eats what ----

func collectResources(c Ctx) (any, error) {
	pl, _ := c.Prior("processes").(*inventory.ProcessList)
	if pl == nil {
		return nil, ErrUnavailable("process list unavailable")
	}
	r := &inventory.Resources{CPUs: runtime.NumCPU()}
	if h, ok := c.Prior("host").(*inventory.Host); ok {
		r.MemTotal = h.MemTotal
	}
	memPct := func(b uint64) float64 { return pct(float64(b), float64(r.MemTotal)) }

	io := map[int][2]uint64{}
	units := map[int]string{}
	if runtime.GOOS == "linux" {
		denied := 0
		for _, p := range pl.All {
			if rb, wb, ok := procIO(p.PID); ok {
				io[p.PID] = [2]uint64{rb, wb}
			} else {
				denied++
			}
			if u := procUnit(p.PID); u != "" {
				units[p.PID] = u
			}
		}
		if denied > 0 {
			r.IONote = strconv.Itoa(denied) + " processes: IO counters not readable (run with sudo for full IO data)"
		}
	} else {
		r.IONote = "per-process IO counters only on Linux"
	}

	per := make([]inventory.Usage, 0, len(pl.All))
	apps, users, byUnit := map[string]*inventory.Usage{}, map[string]*inventory.Usage{}, map[string]*inventory.Usage{}
	acc := func(m map[string]*inventory.Usage, k string, p inventory.Process) {
		u := m[k]
		if u == nil {
			u = &inventory.Usage{Key: k}
			m[k] = u
		}
		u.Count++
		u.CPU += p.CPU
		u.RSS += p.MemRSS
		u.ReadB += io[p.PID][0]
		u.WriteB += io[p.PID][1]
	}
	for _, p := range pl.All {
		per = append(per, inventory.Usage{Key: strconv.Itoa(p.PID) + " " + p.Comm + " (" + p.User + ")", Count: 1, CPU: p.CPU,
			RSS: p.MemRSS, ReadB: io[p.PID][0], WriteB: io[p.PID][1]})
		acc(apps, p.Comm, p)
		acc(users, p.User, p)
		if u, ok := units[p.PID]; ok {
			acc(byUnit, u, p)
		}
	}
	flat := func(m map[string]*inventory.Usage) []inventory.Usage {
		var s []inventory.Usage
		for _, u := range m {
			u.MemPct = memPct(u.RSS)
			u.CPU = float64(int(u.CPU*10)) / 10
			s = append(s, *u)
		}
		sortBy(s, func(a, b inventory.Usage) bool { return a.RSS+uint64(a.CPU*1e8) > b.RSS+uint64(b.CPU*1e8) })
		return s
	}
	for i := range per {
		per[i].MemPct = memPct(per[i].RSS)
	}
	top := func(less func(a, b inventory.Usage) bool, n int) []inventory.Usage {
		s := append([]inventory.Usage(nil), per...)
		sortBy(s, less)
		if len(s) > n {
			s = s[:n]
		}
		return s
	}
	r.TopCPU = top(func(a, b inventory.Usage) bool { return a.CPU > b.CPU }, 25)
	r.TopMem = top(func(a, b inventory.Usage) bool { return a.RSS > b.RSS }, 25)
	if len(io) > 0 {
		r.TopIO = top(func(a, b inventory.Usage) bool { return a.ReadB+a.WriteB > b.ReadB+b.WriteB }, 15)
	}
	r.ByApp = limit(flat(apps), 40)
	r.ByUser = flat(users)
	r.ByUnit = limit(flat(byUnit), 40)
	if c.Policy().Profile != "quick" {
		r.BigDirs = bigDirs(c)
	}
	return r, nil
}

func procIO(pid int) (r, w uint64, ok bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/io")
	if err != nil {
		return 0, 0, false
	}
	kv := map[string]uint64{}
	for _, ln := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(ln, ":"); ok {
			kv[k], _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		}
	}
	return kv["read_bytes"], kv["write_bytes"], true
}

// procUnit maps a PID to its systemd unit or container via cgroup path.
func procUnit(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(ln, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, seg := range strings.Split(parts[2], "/") {
			switch {
			case strings.HasPrefix(seg, "docker-") && strings.HasSuffix(seg, ".scope"):
				return "container:" + strings.TrimSuffix(strings.TrimPrefix(seg, "docker-"), ".scope")[:12]
			case strings.HasSuffix(seg, ".service"):
				return seg
			}
		}
	}
	return ""
}

// bigDirs: disk usage of top-level data dirs, one level deep, bounded by timeout.
func bigDirs(c Ctx) []inventory.DirUsage {
	var out []inventory.DirUsage
	roots := []string{"/var", "/home", "/opt", "/srv", "/root", "/usr", "/tmp"}
	if runtime.GOOS == "darwin" {
		if h, err := os.UserHomeDir(); err == nil {
			roots = []string{h, "/opt", "/usr/local", "/Applications"}
		}
	}
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		args := []string{"-x", "-k", "-d", "1", root}
		if runtime.GOOS == "linux" {
			args = []string{"-x", "-k", "--max-depth=1", root}
		}
		budget := 10 * time.Second
		if dl, ok := c.Deadline(); ok {
			budget = min(budget, time.Until(dl)-2*time.Second)
		}
		if budget < time.Second {
			c.Warn("du skipped for %s: collector time budget used", root)
			continue
		}
		s, err := execx.Run(c, budget, "du", args...)
		if s == "" && err != nil {
			c.Warn("du %s: %v", root, err)
			continue
		}
		for _, ln := range strings.Split(s, "\n") {
			kb, p, ok := strings.Cut(ln, "\t")
			if !ok {
				continue
			}
			n, _ := strconv.ParseUint(kb, 10, 64)
			out = append(out, inventory.DirUsage{Path: p, Bytes: n * 1024})
		}
		if err != nil {
			c.Warn("du %s partial (permissions/timeout)", root)
		}
	}
	sortBy(out, func(a, b inventory.DirUsage) bool { return a.Bytes > b.Bytes })
	return limit(out, 30)
}

func limit[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
