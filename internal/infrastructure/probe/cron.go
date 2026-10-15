package probe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/domain/schedule"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
	"github.com/bakhod1r/serveradar/internal/infrastructure/redact"
)

func init() {
	register(Collector{Name: "cron", Title: "Cron & Scheduled Jobs", Profiles: everywhere, Depends: []string{"processes"}, Collect: collectCron})
}

func collectCron(c Ctx) (any, error) {
	cr := &inventory.Cron{}
	// system crontab + cron.d: have a user column
	sys := []string{"/etc/crontab"}
	if m, _ := filepath.Glob("/etc/cron.d/*"); m != nil {
		sys = append(sys, m...)
	}
	for _, f := range sys {
		parseCronFile(cr, f, "", true)
	}
	// per-user spools: no user column
	for _, dir := range []string{"/var/spool/cron/crontabs", "/var/spool/cron", "/usr/lib/cron/tabs", "/var/at/tabs"} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			if os.IsPermission(err) {
				cr.Unreadable = append(cr.Unreadable, dir+" (needs sudo)")
			}
			continue
		}
		for _, e := range ents {
			if !e.IsDir() {
				parseCronFile(cr, filepath.Join(dir, e.Name()), e.Name(), false)
			}
		}
	}
	// current user's crontab via crontab -l (read-only)
	if out, err := execx.Run(c, 5*time.Second, "crontab", "-l"); err == nil {
		u := os.Getenv("USER")
		parseCronText(cr, "crontab -l", u, out, false)
	}
	// periodic dirs
	for _, d := range []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			if e.Name() != ".placeholder" {
				cr.Jobs = append(cr.Jobs, inventory.CronJob{Source: d, User: "root", Schedule: "@" + strings.TrimPrefix(filepath.Base(d), "cron."), Command: filepath.Join(d, e.Name())})
			}
		}
	}
	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		for _, d := range []string{"/Library/LaunchDaemons", "/Library/LaunchAgents", filepath.Join(home, "Library/LaunchAgents")} {
			ents, _ := os.ReadDir(d)
			for _, e := range ents {
				cr.LaunchAgents = append(cr.LaunchAgents, filepath.Join(d, e.Name()))
			}
		}
	}
	for _, s := range []struct{ bin, label string }{{"supervisord", "supervisor"}, {"pm2", "pm2"}, {"PM2", "pm2"}} {
		if pl, ok := c.Prior("processes").(*inventory.ProcessList); ok {
			for _, p := range pl.All {
				if strings.Contains(p.Cmdline, s.bin) {
					cr.Supervisors = appendUniq(cr.Supervisors, s.label)
				}
			}
		}
	}
	if len(cr.Unreadable) > 0 {
		c.Warn("some cron spools unreadable without sudo")
	}
	enrichCron(cr)
	cr.Timers = systemdTimers(c)
	cr.Summary = cronSummary(cr)
	return cr, nil
}

// enrichCron: human schedule, next run, frequency, script checks, risk notes. Never executes anything.
func enrichCron(cr *inventory.Cron) {
	now := time.Now()
	for i := range cr.Jobs {
		j := &cr.Jobs[i]
		if sp, err := schedule.Parse(j.Schedule); err == nil {
			j.Description = sp.Describe()
			if n, ok := sp.Next(now); ok {
				j.NextRun = n.Format("2006-01-02 15:04")
			}
			j.PerDay = float64(int(sp.PerDay(now)*100)) / 100
		} else {
			j.Risks = append(j.Risks, "unparseable schedule: "+err.Error())
		}
		cmd := j.Command
		if strings.HasPrefix(j.Source, "/etc/cron.") && !strings.Contains(j.Source, "cron.d") {
			cmd = j.Command // periodic dir entry: the command is the script itself
		}
		if f := strings.Fields(cmd); len(f) > 0 {
			for _, tok := range f {
				if strings.HasPrefix(tok, "/") && !strings.HasPrefix(tok, "/dev/") {
					j.Script = strings.Trim(tok, `"';&|`)
					break
				}
			}
		}
		if j.Script != "" {
			fi, err := os.Stat(j.Script)
			switch {
			case os.IsNotExist(err):
				j.Risks = append(j.Risks, "script missing: "+j.Script)
			case err == nil:
				if fi.Mode().Perm()&0o002 != 0 {
					j.Risks = append(j.Risks, "script world-writable ("+fi.Mode().Perm().String()+") — any user can inject code")
				}
				if j.User == "root" && fi.Mode().Perm()&0o020 != 0 {
					j.Risks = append(j.Risks, "root job script group-writable")
				}
				if d, err := os.Stat(filepath.Dir(j.Script)); err == nil && d.Mode().Perm()&0o002 != 0 && d.Mode()&os.ModeSticky == 0 {
					j.Risks = append(j.Risks, "script directory world-writable")
				}
			}
		}
		low := strings.ToLower(j.Command)
		if j.PerDay >= 1440 {
			j.Risks = append(j.Risks, "runs every minute")
		}
		if (strings.Contains(low, "curl") || strings.Contains(low, "wget")) && (strings.Contains(low, "| sh") || strings.Contains(low, "|sh") || strings.Contains(low, "| bash") || strings.Contains(low, "|bash")) {
			j.Risks = append(j.Risks, "downloads and executes remote code")
		}
		if strings.Contains(low, "/tmp/") || strings.Contains(low, "/dev/shm") {
			j.Risks = append(j.Risks, "references /tmp or /dev/shm")
		}
		if strings.Contains(j.Command, "***") {
			j.Risks = append(j.Risks, "secret in command line (redacted here; visible to local users via ps)")
		}
		if j.PerDay >= 24 && !strings.Contains(j.Command, ">") && !strings.Contains(j.Command, "|") && j.Schedule != "@reboot" {
			j.Risks = append(j.Risks, "frequent job without output redirect — cron mails/logs every run")
		}
		if (strings.Contains(low, "pg_dump") || strings.Contains(low, "mysqldump") || strings.Contains(low, "backup") || strings.Contains(low, "restic") || strings.Contains(low, "borg")) && j.Description != "" {
			j.Risks = append(j.Risks, "backup job (verify restores separately)")
		}
	}
	sortBy(cr.Jobs, func(a, b inventory.CronJob) bool { return a.PerDay > b.PerDay })
}

func systemdTimers(c Ctx) []inventory.Timer {
	if !execx.Has("systemctl") {
		return nil
	}
	var out []inventory.Timer
	if s, err := execx.Run(c, 8*time.Second, "systemctl", "list-timers", "--all", "--no-pager", "-o", "json"); err == nil && strings.HasPrefix(strings.TrimSpace(s), "[") {
		var raw []map[string]any
		if json.Unmarshal([]byte(s), &raw) == nil {
			usec := func(v any) string {
				f, ok := v.(float64)
				if !ok || f <= 0 {
					return ""
				}
				return time.UnixMicro(int64(f)).Format("2006-01-02 15:04")
			}
			for _, r := range raw {
				out = append(out, inventory.Timer{Unit: fmt.Sprint(r["unit"]), Activates: fmt.Sprint(r["activates"]), Next: usec(r["next"]), Last: usec(r["last"])})
			}
		}
	}
	for i := range out { // OnCalendar from unit (read-only show)
		if s, err := execx.Run(c, 3*time.Second, "systemctl", "show", "-p", "TimersCalendar", "--value", out[i].Unit); err == nil {
			if j := strings.Index(s, "OnCalendar="); j >= 0 {
				out[i].Schedule = strings.Fields(s[j+11:])[0]
			}
		}
	}
	return out
}

func cronSummary(cr *inventory.Cron) []string {
	users := map[string]int{}
	risky, root, everyMin := 0, 0, 0
	for _, j := range cr.Jobs {
		users[j.User]++
		if len(j.Risks) > 0 {
			risky++
		}
		if j.User == "root" {
			root++
		}
		if j.PerDay >= 1440 {
			everyMin++
		}
	}
	var us []string
	for u, n := range users {
		us = append(us, fmt.Sprintf("%s=%d", orDashS(u), n))
	}
	sortBy(us, func(a, b string) bool { return a < b })
	s := []string{
		fmt.Sprintf("%d cron jobs (%s), %d systemd timers", len(cr.Jobs), strings.Join(us, " "), len(cr.Timers)),
		fmt.Sprintf("%d run as root, %d every minute, %d with risk notes", root, everyMin, risky),
	}
	if len(cr.Unreadable) > 0 {
		s = append(s, "incomplete: "+strings.Join(cr.Unreadable, ", "))
	}
	return s
}

func parseCronFile(cr *inventory.Cron, path, user string, hasUser bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsPermission(err) {
			cr.Unreadable = append(cr.Unreadable, path)
		}
		return
	}
	parseCronText(cr, path, user, string(b), hasUser)
}

func parseCronText(cr *inventory.Cron, src, user, text string, hasUser bool) {
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln[0] == '#' {
			continue
		}
		f := strings.Fields(ln)
		if len(f) > 0 && strings.Contains(f[0], "=") && !strings.HasPrefix(f[0], "@") { // VAR=value
			continue
		}
		n := 5
		if strings.HasPrefix(f[0], "@") {
			n = 1
		}
		u := user
		if hasUser {
			if len(f) <= n {
				continue
			}
			u = f[n]
			n++
		}
		if len(f) <= n {
			continue
		}
		cr.Jobs = append(cr.Jobs, inventory.CronJob{Source: src, User: u, Schedule: strings.Join(f[:min(n, len(f))-boolInt(hasUser)], " "),
			Command: redact.Text(truncate(strings.Join(f[n:], " "), 300))})
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
