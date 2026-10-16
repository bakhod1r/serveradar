package probe

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
)

func init() {
	register(Collector{Name: "host", Title: "Host & OS", Profiles: everywhere, Collect: collectHost})
}

var pseudoFS = map[string]bool{"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "cgroup": true, "cgroup2": true,
	"securityfs": true, "pstore": true, "bpf": true, "tracefs": true, "debugfs": true, "mqueue": true, "hugetlbfs": true,
	"configfs": true, "fusectl": true, "autofs": true, "binfmt_misc": true, "nsfs": true, "devfs": true, "overlay": true,
	"squashfs": true, "efivarfs": true, "rpc_pipefs": true, "tmpfs": false}

func collectHost(c Ctx) (any, error) {
	h := &inventory.Host{OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU()}
	h.Hostname, _ = os.Hostname()
	h.Timezone, _ = time.Now().Zone()
	if tz, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(tz, "zoneinfo/"); i >= 0 {
			h.Timezone = tz[i+9:]
		}
	}
	if runtime.GOOS == "linux" {
		hostLinux(c, h)
	} else {
		hostDarwin(c, h)
	}
	h.Mounts = mounts(c)
	return h, nil
}

func hostLinux(c Ctx, h *inventory.Host) {
	if kv := readKV("/etc/os-release", "="); kv != nil {
		h.Distro = strings.Trim(kv["PRETTY_NAME"], `"`)
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		h.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		sum := sha256.Sum256([]byte("serveradar:" + strings.TrimSpace(string(b))))
		h.MachineIDHash = hex.EncodeToString(sum[:8])
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			up, _ := strconv.ParseFloat(f[0], 64)
			h.UptimeSec = int64(up)
			h.BootTime = time.Now().Add(-time.Duration(up) * time.Second).UTC().Truncate(time.Second)
		}
	}
	h.Load = loadavg()
	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			if k, v, ok := strings.Cut(s.Text(), ":"); ok && strings.TrimSpace(k) == "model name" {
				h.CPUModel = strings.TrimSpace(v)
				break
			}
		}
		f.Close()
	}
	mi := meminfo()
	h.MemTotal, h.MemAvailable, h.MemCached = mi["MemTotal"], mi["MemAvailable"], mi["Cached"]
	h.SwapTotal, h.SwapFree = mi["SwapTotal"], mi["SwapFree"]
	if out, err := execx.Run(c, 3*time.Second, "systemd-detect-virt"); err == nil {
		h.Virtualization = strings.TrimSpace(out)
	} else if strings.TrimSpace(out) == "none" {
		h.Virtualization = "none"
	}
	_, err := os.Stat("/var/run/reboot-required")
	h.RebootRequired = err == nil
}

func hostDarwin(c Ctx, h *inventory.Host) {
	if out, err := execx.Run(c, 3*time.Second, "sw_vers", "-productVersion"); err == nil {
		h.Distro = "macOS " + strings.TrimSpace(out)
	}
	sys := func(k string) string {
		out, _ := execx.Run(c, 3*time.Second, "sysctl", "-n", k)
		return strings.TrimSpace(out)
	}
	h.Kernel = sys("kern.osrelease")
	h.CPUModel = sys("machdep.cpu.brand_string")
	h.MemTotal, _ = strconv.ParseUint(sys("hw.memsize"), 10, 64)
	if bt := sys("kern.boottime"); bt != "" { // { sec = 1700000000, usec = 0 } ...
		if i := strings.Index(bt, "sec = "); i >= 0 {
			rest := bt[i+6:]
			if j := strings.IndexAny(rest, ","); j > 0 {
				sec, _ := strconv.ParseInt(rest[:j], 10, 64)
				h.BootTime = time.Unix(sec, 0).UTC()
				h.UptimeSec = int64(time.Since(h.BootTime).Seconds())
			}
		}
	}
	if la := strings.Fields(strings.Trim(sys("vm.loadavg"), "{ }")); len(la) >= 3 {
		for i := 0; i < 3; i++ {
			h.Load[i], _ = strconv.ParseFloat(la[i], 64)
		}
	}
	if out, err := execx.Run(c, 3*time.Second, "vm_stat"); err == nil {
		page := uint64(16384)
		if strings.Contains(out, "page size of 4096") {
			page = 4096
		}
		v := map[string]uint64{}
		for _, ln := range strings.Split(out, "\n") {
			if k, val, ok := strings.Cut(ln, ":"); ok {
				n, _ := strconv.ParseUint(strings.Trim(strings.TrimSpace(val), "."), 10, 64)
				v[strings.TrimSpace(k)] = n * page
			}
		}
		h.MemAvailable = v["Pages free"] + v["Pages inactive"] + v["Pages speculative"]
		h.MemCached = v["File-backed pages"]
	}
	if sw := sys("vm.swapusage"); sw != "" { // total = 2048.00M  used = 1.25M  free = ...
		f := strings.Fields(sw)
		for i := 0; i+2 < len(f); i++ {
			if f[i+1] == "=" {
				n := parseSize(f[i+2])
				switch f[i] {
				case "total":
					h.SwapTotal = n
				case "free":
					h.SwapFree = n
				}
			}
		}
	}
}

func mounts(c Ctx) []inventory.Mount {
	var ms []inventory.Mount
	seen := map[string]bool{}
	add := func(dev, mp, fs string, ro bool) {
		if fs == "overlay" && mp == "/" {
			fs = "overlay (container root)"
		}
		if mp == "/dev" || pseudoFS[fs] || seen[mp] || strings.HasPrefix(mp, "/System/Volumes/") && mp != "/System/Volumes/Data" ||
			strings.HasPrefix(mp, "/proc/") || strings.HasPrefix(mp, "/sys/") || strings.HasPrefix(mp, "/dev/") || strings.HasPrefix(mp, "/run/") && fs == "tmpfs" {
			return
		}
		if fi, err := os.Stat(mp); err != nil || !fi.IsDir() { // bind-mounted files (/etc/hosts in containers)
			return
		}
		seen[mp] = true
		m := inventory.Mount{Device: dev, Mountpoint: mp, FSType: fs, ReadOnly: ro}
		if t, f, ti, fi, ok := statfs(mp); ok && t > 0 {
			m.TotalBytes, m.UsedBytes = t, t-f
			m.UsedPct = pct(float64(t-f), float64(t))
			if ti > 0 {
				m.InodesPct = pct(float64(ti-fi), float64(ti))
			}
		} else if !ok {
			return
		}
		ms = append(ms, m)
	}
	if b, err := os.ReadFile("/proc/mounts"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			f := strings.Fields(ln)
			if len(f) >= 4 {
				ro := false
				for _, o := range strings.Split(f[3], ",") {
					ro = ro || o == "ro"
				}
				add(f[0], strings.ReplaceAll(f[1], `\040`, " "), f[2], ro)
			}
		}
		return ms
	}
	out, err := execx.Run(c, 3*time.Second, "mount")
	if err != nil {
		c.Warn("mount list unavailable: %v", err)
		return ms
	}
	for _, ln := range strings.Split(out, "\n") { // dev on /mp (fs, opt, opt)
		dev, rest, ok := strings.Cut(ln, " on ")
		if !ok {
			continue
		}
		i := strings.LastIndex(rest, " (")
		if i < 0 {
			continue
		}
		opts := strings.Split(strings.Trim(rest[i+2:], ")"), ", ")
		ro := false
		for _, o := range opts {
			ro = ro || o == "read-only"
		}
		add(dev, rest[:i], opts[0], ro)
	}
	return ms
}

func loadavg() (l [3]float64) {
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		for i := 0; i < 3 && i < len(f); i++ {
			l[i], _ = strconv.ParseFloat(f[i], 64)
		}
	}
	return
}

func meminfo() map[string]uint64 {
	m := map[string]uint64{}
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return m
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(ln, ":"); ok {
			f := strings.Fields(v)
			if len(f) > 0 {
				n, _ := strconv.ParseUint(f[0], 10, 64)
				m[k] = n * 1024
			}
		}
	}
	return m
}

func readKV(path, sep string) map[string]string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, ln := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(ln, sep); ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

func parseSize(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	mult := map[byte]float64{'K': 1 << 10, 'M': 1 << 20, 'G': 1 << 30, 'T': 1 << 40, 'k': 1 << 10}
	u := s[len(s)-1]
	f, err := strconv.ParseFloat(strings.TrimRight(s, "KMGTkBib"), 64)
	if err != nil {
		return 0
	}
	if m, ok := mult[u]; ok {
		f *= m
	}
	return uint64(f)
}

func pct(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return float64(int(a/b*1000)) / 10
}
