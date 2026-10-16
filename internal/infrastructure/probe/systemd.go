package probe

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
	"github.com/bakhod1r/serveradar/internal/infrastructure/redact"
)

func init() {
	register(Collector{Name: "systemd", Title: "systemd Services", Profiles: everywhere, Collect: collectSystemd})
}

func collectSystemd(c Ctx) (any, error) {
	if !execx.Has("systemctl") {
		return nil, ErrUnavailable("systemd not present")
	}
	out, err := execx.Run(c, 10*time.Second, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain")
	if err != nil && out == "" {
		return nil, err
	}
	s := &inventory.Systemd{}
	idx := map[string]int{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimLeft(ln, "● "))
		if len(f) < 4 {
			continue
		}
		u := inventory.Unit{Name: f[0], Load: f[1], Active: f[2], Sub: f[3], Desc: strings.Join(f[4:], " ")}
		idx[u.Name] = len(s.Units)
		s.Units = append(s.Units, u)
		if u.Active == "failed" {
			s.Failed = append(s.Failed, u.Name)
		}
	}
	if out, err := execx.Run(c, 10*time.Second, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"); err == nil {
		for _, ln := range strings.Split(out, "\n") {
			f := strings.Fields(ln)
			if len(f) < 2 {
				continue
			}
			if i, ok := idx[f[0]]; ok {
				s.Units[i].Enabled = f[1]
				if f[1] == "enabled" && s.Units[i].Active == "inactive" {
					s.EnabledInactive = append(s.EnabledInactive, f[0])
				}
			}
		}
	}
	if out, err := execx.Run(c, 10*time.Second, "systemctl", "list-timers", "--all", "--no-legend", "--no-pager"); err == nil {
		for _, ln := range nonEmpty(strings.Split(out, "\n")) {
			f := strings.Fields(ln)
			for _, x := range f {
				if strings.HasSuffix(x, ".timer") {
					s.Timers = append(s.Timers, x)
				}
			}
		}
	}
	// full definition of every loaded service (systemctl show is read-only)
	var names []string
	for _, u := range s.Units {
		if u.Load == "loaded" {
			names = append(names, u.Name)
		}
	}
	for i := 0; i < len(names); i += 40 {
		batch := names[i:min(i+40, len(names))]
		args := append([]string{"show", "--no-pager", "-p", unitProps}, batch...)
		out, err := execx.Run(c, 15*time.Second, "systemctl", args...)
		if err != nil && out == "" {
			c.Warn("systemctl show: %v", err)
			break
		}
		for _, blk := range strings.Split(out, "\n\n") {
			kv := map[string]string{}
			for _, ln := range strings.Split(blk, "\n") {
				if k, v, ok := strings.Cut(ln, "="); ok {
					kv[k] = v
				}
			}
			if kv["Id"] == "" {
				continue
			}
			d := unitDetail(kv)
			s.Details = append(s.Details, d)
			if d.Active == "active" || d.Active == "failed" {
				m := inventory.UnitMem{Unit: d.Name, MemBytes: d.Memory, Restarts: d.Restarts}
				m.CPUNsec, _ = strconv.ParseUint(kv["CPUUsageNSec"], 10, 64)
				s.Usage = append(s.Usage, m)
			}
		}
	}
	s.Counts = map[string]int{"services": len(s.Units), "failed": len(s.Failed)}
	for _, d := range s.Details {
		s.Counts["origin_"+d.Origin]++
		if d.Active == "active" {
			s.Counts["active"]++
		}
		if d.Enabled == "enabled" {
			s.Counts["enabled"]++
		}
	}
	sortBy(s.Details, func(a, b inventory.ServiceUnit) bool {
		if (a.Origin == "custom") != (b.Origin == "custom") {
			return a.Origin == "custom"
		}
		return a.Name < b.Name
	})
	for _, t := range []string{"socket", "mount"} {
		out, _ := execx.Run(c, 8*time.Second, "systemctl", "list-units", "--type="+t, "--all", "--no-legend", "--no-pager", "--plain")
		for _, ln := range nonEmpty(strings.Split(out, "\n")) {
			f := strings.Fields(strings.TrimLeft(ln, "● "))
			if len(f) >= 3 {
				e := f[0] + " (" + f[2] + ")"
				if t == "socket" {
					s.Sockets = append(s.Sockets, e)
				} else {
					s.Mounts = append(s.Mounts, e)
				}
			}
		}
	}
	sortBy(s.Usage, func(a, b inventory.UnitMem) bool { return a.MemBytes > b.MemBytes })
	return s, nil
}

const unitProps = "Id,Description,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,ExecStart,User,WorkingDirectory," +
	"EnvironmentFiles,Environment,Restart,MainPID,MemoryCurrent,CPUUsageNSec,NRestarts,ActiveEnterTimestamp,Type,WantedBy," +
	"ProtectSystem,ProtectHome,NoNewPrivileges,PrivateTmp,DynamicUser,ReadOnlyPaths"

func unitDetail(kv map[string]string) inventory.ServiceUnit {
	d := inventory.ServiceUnit{Name: kv["Id"], Description: kv["Description"], Active: kv["ActiveState"], Sub: kv["SubState"],
		Enabled: kv["UnitFileState"], Fragment: kv["FragmentPath"], User: kv["User"], WorkDir: kv["WorkingDirectory"],
		Restart: kv["Restart"], Type: kv["Type"], WantedBy: kv["WantedBy"], Since: kv["ActiveEnterTimestamp"]}
	if d.User == "" {
		d.User = "root"
		if kv["DynamicUser"] == "yes" {
			d.User = "(dynamic)"
		}
	}
	d.MainPID, _ = strconv.Atoi(kv["MainPID"])
	d.Restarts, _ = strconv.Atoi(kv["NRestarts"])
	if m, err := strconv.ParseUint(kv["MemoryCurrent"], 10, 64); err == nil && m < 1<<62 {
		d.Memory = m
	}
	d.DropIns = strings.Fields(kv["DropInPaths"])
	switch f := d.Fragment; {
	case strings.HasPrefix(f, "/etc/"):
		d.Origin = "custom"
	case strings.HasPrefix(f, "/run/systemd/generator"):
		d.Origin = "generated"
	case strings.HasPrefix(f, "/run/"):
		d.Origin = "runtime"
	case f == "":
		d.Origin = "none"
	default:
		d.Origin = "vendor"
	}
	// ExecStart={ path=/usr/bin/x ; argv[]=/usr/bin/x --flag ; ignore_errors=no ; ... }
	if i := strings.Index(kv["ExecStart"], "argv[]="); i >= 0 {
		rest := kv["ExecStart"][i+7:]
		if j := strings.Index(rest, " ;"); j >= 0 {
			rest = rest[:j]
		}
		d.ExecStart = redact.Text(truncate(rest, 300))
	}
	for _, f := range strings.Fields(kv["EnvironmentFiles"]) {
		if strings.HasPrefix(f, "/") || strings.HasPrefix(f, "-/") {
			d.EnvFiles = append(d.EnvFiles, strings.TrimPrefix(f, "-"))
		}
	}
	for _, e := range strings.Fields(kv["Environment"]) { // keys only; values may be secrets
		if k, _, ok := strings.Cut(e, "="); ok {
			d.EnvKeys = append(d.EnvKeys, k)
		}
	}
	for _, h := range []struct{ k, ok string }{{"ProtectSystem", "strict"}, {"ProtectSystem", "full"}, {"ProtectHome", "yes"}, {"ProtectHome", "read-only"},
		{"NoNewPrivileges", "yes"}, {"PrivateTmp", "yes"}, {"DynamicUser", "yes"}} {
		if kv[h.k] == h.ok {
			d.Hardening = append(d.Hardening, h.k+"="+h.ok)
		}
	}
	unitRisks(&d)
	return d
}

func unitRisks(d *inventory.ServiceUnit) {
	if bin := strings.Fields(d.ExecStart); len(bin) > 0 && strings.HasPrefix(bin[0], "/") {
		if fi, err := os.Stat(bin[0]); err == nil && fi.Mode().Perm()&0o002 != 0 {
			d.Risks = append(d.Risks, "ExecStart binary world-writable: "+bin[0])
		} else if os.IsNotExist(err) && d.Active != "inactive" {
			d.Risks = append(d.Risks, "ExecStart binary missing: "+bin[0])
		}
		if (strings.HasPrefix(bin[0], "/tmp/") || strings.HasPrefix(bin[0], "/dev/shm/")) && d.User == "root" {
			d.Risks = append(d.Risks, "root service runs binary from /tmp")
		}
	}
	for _, f := range d.EnvFiles {
		if fi, err := os.Stat(f); err == nil && fi.Mode().Perm()&0o004 != 0 {
			d.Risks = append(d.Risks, "EnvironmentFile world-readable: "+f)
		}
	}
	if d.Fragment != "" && d.Origin == "custom" {
		if fi, err := os.Stat(d.Fragment); err == nil && fi.Mode().Perm()&0o022 != 0 {
			d.Risks = append(d.Risks, "unit file writable by group/others: "+d.Fragment)
		}
		if d.User == "root" && len(d.Hardening) == 0 && d.Active == "active" {
			d.Risks = append(d.Risks, "custom service runs as root without sandboxing (consider User=, NoNewPrivileges, ProtectSystem)")
		}
		if d.Restart == "no" && d.Type != "oneshot" && d.Active == "active" {
			d.Risks = append(d.Risks, "Restart=no — will stay down after a crash")
		}
	}
}
