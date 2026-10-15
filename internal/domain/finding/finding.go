// Package finding evaluates domain rules over the inventory. Evidence-based, no overclaiming.
package finding

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/domain/policy"
	"github.com/bakhod1r/serveradar/internal/domain/topology"
)

type F = inventory.Finding

// Rule inspects a report and emits findings.
type Rule func(r *inventory.Report, p *policy.Policy) []F

var Rules = []Rule{diskRule, memRule, loadRule, publicDBRule, wildcardRule, dockerRule, systemdRule, tlsRule, nginxRule, sshRule, permsRule, mongoRule, envRule, rebootRule, collectorRule, exposureRule, cronRule, pgRule, mysqlRule, redisRule, dbAccessRule, servicesRule, unitRule}

func Evaluate(r *inventory.Report, p *policy.Policy) []F {
	var out []F
	now := time.Now().UTC()
	for _, rule := range Rules {
		for _, f := range rule(r, p) {
			f.Timestamp = now
			if f.Confidence == "" {
				f.Confidence = inventory.Confirmed
			}
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return inventory.SeverityOrder[out[i].Severity] < inventory.SeverityOrder[out[j].Severity]
	})
	for i := range out {
		out[i].ID = fmt.Sprintf("SR-%03d-%s", i+1, out[i].ID)
	}
	return out
}

func diskRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	h, ok := topology.Get[*inventory.Host](r, "host")
	if !ok {
		return
	}
	for _, m := range h.Mounts {
		sev := inventory.Severity("")
		switch {
		case m.UsedPct >= 95:
			sev = inventory.Critical
		case m.UsedPct >= 85:
			sev = inventory.High
		case m.UsedPct >= 75:
			sev = inventory.Medium
		}
		if sev != "" && !m.ReadOnly {
			out = append(out, F{ID: "DISK", Title: "Disk pressure on " + m.Mountpoint, Severity: sev, Component: m.Mountpoint,
				Evidence: fmt.Sprintf("%.1f%% used of %s", m.UsedPct, HumanBytes(m.TotalBytes)), Impact: "Writes fail when full; databases and logs may crash.",
				NextStep: "Check largest directories (resources section), rotate logs, prune unused images/volumes manually.", Method: "statfs"})
		}
		if m.InodesPct >= 90 {
			out = append(out, F{ID: "INODE", Title: "Inode exhaustion on " + m.Mountpoint, Severity: inventory.High, Component: m.Mountpoint,
				Evidence: fmt.Sprintf("%.1f%% inodes used", m.InodesPct), Impact: "File creation fails even with free space.", NextStep: "Find directories with many small files.", Method: "statfs"})
		}
	}
	return
}

func memRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	h, ok := topology.Get[*inventory.Host](r, "host")
	if !ok || h.MemTotal == 0 {
		return
	}
	used := 100 - float64(h.MemAvailable)/float64(h.MemTotal)*100
	if used >= 90 {
		out = append(out, F{ID: "MEM", Title: "Memory pressure", Severity: inventory.High, Component: "memory",
			Evidence: fmt.Sprintf("%.0f%% used, %s available", used, HumanBytes(h.MemAvailable)), Impact: "OOM kills, swapping, latency.",
			NextStep: "See top memory consumers in resources section.", Method: "meminfo"})
	}
	if h.SwapTotal > 0 && h.SwapTotal-h.SwapFree > h.SwapTotal/2 {
		out = append(out, F{ID: "SWAP", Title: "Heavy swap usage", Severity: inventory.Medium, Component: "swap",
			Evidence: fmt.Sprintf("%s of %s swap used", HumanBytes(h.SwapTotal-h.SwapFree), HumanBytes(h.SwapTotal)), Impact: "Degraded performance.", NextStep: "Identify memory-heavy processes.", Method: "meminfo"})
	}
	return
}

func loadRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	h, ok := topology.Get[*inventory.Host](r, "host")
	if ok && h.CPUs > 0 && h.Load[1] > float64(h.CPUs)*1.5 {
		out = append(out, F{ID: "LOAD", Title: "CPU saturation", Severity: inventory.Medium, Component: "cpu",
			Evidence: fmt.Sprintf("5m load %.2f on %d CPUs", h.Load[1], h.CPUs), Impact: "Request latency, timeouts.", NextStep: "Check top CPU processes.", Method: "loadavg"})
	}
	return
}

var dbPorts = map[int]string{5432: "PostgreSQL", 3306: "MySQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached", 5672: "RabbitMQ", 9092: "Kafka", 2379: "etcd", 8123: "ClickHouse", 9042: "Cassandra"}

func publicDBRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	p, ok := topology.Get[*inventory.Ports](r, "ports")
	if !ok {
		return
	}
	for _, s := range p.Sockets {
		if name, isDB := dbPorts[s.Port]; isDB && s.Public && s.Proto == "tcp" {
			out = append(out, F{ID: "DBBIND", Title: name + " listening on all interfaces", Severity: inventory.High, Component: fmt.Sprintf("%s:%d", s.Address, s.Port),
				Evidence: fmt.Sprintf("%s bound to %s:%d (pid %d %s)", name, s.Address, s.Port, s.PID, s.Process), Confidence: inventory.Strong,
				Impact: "May be reachable from network; actual exposure depends on firewall/NAT/cloud security groups.",
				NextStep: "Bind to 127.0.0.1/private IP or restrict via firewall; verify with external scan from authorized host.", Method: "socket inventory"})
		}
	}
	return
}

func wildcardRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	p, ok := topology.Get[*inventory.Ports](r, "ports")
	if !ok {
		return
	}
	var list []string
	for _, s := range p.Sockets {
		if s.Public {
			if _, isDB := dbPorts[s.Port]; !isDB {
				list = append(list, fmt.Sprintf("%s/%d(%s)", s.Proto, s.Port, s.Process))
			}
		}
	}
	if len(list) > 0 {
		out = append(out, F{ID: "WILDCARD", Title: fmt.Sprintf("%d sockets bound to wildcard address", len(list)), Severity: inventory.Info,
			Component: "network", Evidence: strings.Join(limit(list, 30), ", "), Confidence: inventory.Confirmed,
			Impact: "Context only: wildcard bind is not a vulnerability by itself.", NextStep: "Confirm each is intended to be network-facing.", Method: "socket inventory"})
	}
	return
}

func dockerRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	d, ok := topology.Get[*inventory.Docker](r, "docker")
	if !ok {
		return
	}
	for _, c := range d.Containers {
		if c.Privileged {
			out = append(out, F{ID: "DPRIV", Title: "Privileged container " + c.Name, Severity: inventory.High, Component: "container:" + c.Name,
				Evidence: "HostConfig.Privileged=true", Impact: "Container escape equals host root.", NextStep: "Drop privileged; grant only needed capabilities.", Method: "docker inspect"})
		}
		if c.SocketMount {
			out = append(out, F{ID: "DSOCK", Title: "Docker socket mounted into " + c.Name, Severity: inventory.High, Component: "container:" + c.Name,
				Evidence: strings.Join(c.Mounts, ", "), Impact: "Full control of Docker daemon = host root.", NextStep: "Use socket proxy with limited API, or remove mount.", Method: "docker inspect"})
		}
		if c.HostNet || c.HostPID {
			out = append(out, F{ID: "DHOSTNS", Title: "Host namespace shared by " + c.Name, Severity: inventory.Medium, Component: "container:" + c.Name,
				Evidence: fmt.Sprintf("host_network=%v host_pid=%v", c.HostNet, c.HostPID), Impact: "Reduced isolation.", NextStep: "Use bridge network / private PID namespace if possible.", Method: "docker inspect"})
		}
		for _, m := range c.Mounts {
			src := strings.SplitN(m, ":", 2)[0]
			if src == "/" || src == "/etc" || src == "/root" || strings.HasPrefix(src, "/proc") || src == "/var/lib/docker" {
				out = append(out, F{ID: "DMOUNT", Title: "Sensitive host path mounted in " + c.Name, Severity: inventory.Medium, Component: "container:" + c.Name,
					Evidence: m, Impact: "Container can read host files (and modify them if rw).", NextStep: "Narrow mount scope; keep read-only.", Method: "docker inspect"})
			}
		}
		if c.State == "restarting" || c.RestartCnt > 5 {
			out = append(out, F{ID: "DLOOP", Title: "Restart loop: " + c.Name, Severity: inventory.High, Component: "container:" + c.Name,
				Evidence: fmt.Sprintf("state=%s restarts=%d", c.State, c.RestartCnt), Impact: "Service unavailable/flapping.", NextStep: "docker logs " + c.Name, Method: "docker inspect"})
		}
		if c.Health == "unhealthy" {
			out = append(out, F{ID: "DHEALTH", Title: "Unhealthy container " + c.Name, Severity: inventory.High, Component: "container:" + c.Name,
				Evidence: "health=unhealthy", Impact: "Healthcheck failing.", NextStep: "docker inspect --format '{{json .State.Health}}' " + c.Name, Method: "docker inspect"})
		}
		if c.State == "exited" && c.Restart != "no" && c.Restart != "" {
			out = append(out, F{ID: "DEXIT", Title: "Exited container with restart policy: " + c.Name, Severity: inventory.Low, Component: "container:" + c.Name,
				Evidence: "restart=" + c.Restart, Impact: "Expected service may be down.", NextStep: "Check exit reason.", Method: "docker inspect"})
		}
	}
	if len(d.OrphanVols) > 0 {
		out = append(out, F{ID: "DVOL", Title: fmt.Sprintf("%d volumes not attached to any container", len(d.OrphanVols)), Severity: inventory.Info,
			Component: "docker volumes", Evidence: strings.Join(limit(d.OrphanVols, 20), ", "), Impact: "Disk usage; may hold old data.", NextStep: "Review before manual removal. Serveradar never deletes.", Method: "docker volume ls"})
	}
	if d.Dangling > 0 {
		out = append(out, F{ID: "DIMG", Title: fmt.Sprintf("%d dangling images", d.Dangling), Severity: inventory.Low, Component: "docker images",
			Evidence: "<none>:<none> images", Impact: "Wasted disk.", NextStep: "Review then `docker image prune` manually.", Method: "docker images"})
	}
	return
}

func systemdRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	s, ok := topology.Get[*inventory.Systemd](r, "systemd")
	if !ok {
		return
	}
	for _, u := range s.Failed {
		out = append(out, F{ID: "UNITFAIL", Title: "Failed service " + u, Severity: inventory.High, Component: u, Evidence: "ActiveState=failed",
			Impact: "Service down.", NextStep: "systemctl status " + u + "; journalctl -u " + u + " -n 100", Method: "systemctl"})
	}
	for _, u := range s.Usage {
		if u.Restarts >= 5 {
			out = append(out, F{ID: "UNITFLAP", Title: "Service restarted repeatedly: " + u.Unit, Severity: inventory.Medium, Component: u.Unit,
				Evidence: "NRestarts=" + strconv.Itoa(u.Restarts), Impact: "Crash loop.", NextStep: "journalctl -u " + u.Unit, Method: "systemctl show"})
		}
	}
	if len(s.EnabledInactive) > 0 {
		out = append(out, F{ID: "UNITINACT", Title: fmt.Sprintf("%d services enabled but inactive", len(s.EnabledInactive)), Severity: inventory.Low,
			Component: "systemd", Evidence: strings.Join(limit(s.EnabledInactive, 20), ", "), Confidence: inventory.Possible,
			Impact: "Oneshot units are normal here; others may have failed to start.", NextStep: "Review list.", Method: "systemctl"})
	}
	return
}

func tlsRule(r *inventory.Report, p *policy.Policy) (out []F) {
	t, ok := topology.Get[*inventory.TLS](r, "tls")
	if !ok {
		return
	}
	for _, c := range t.Certs {
		var sev inventory.Severity
		switch {
		case c.DaysLeft < 0:
			sev = inventory.Critical
		case c.DaysLeft < 7:
			sev = inventory.High
		case c.DaysLeft < p.CertWarnDays:
			sev = inventory.Medium
		default:
			continue
		}
		out = append(out, F{ID: "TLSEXP", Title: "Certificate expiring: " + c.Subject, Severity: sev, Component: c.Path,
			Evidence: fmt.Sprintf("notAfter=%s (%d days)", c.NotAfter.Format("2006-01-02"), c.DaysLeft), Impact: "Browsers/clients reject HTTPS.",
			NextStep: "Check renewal: certbot renew --dry-run (manual).", Method: "x509 parse"})
	}
	return
}

func nginxRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	n, ok := topology.Get[*inventory.Nginx](r, "nginx")
	if !ok {
		return
	}
	seen := map[string]string{}
	for _, v := range n.Vhosts {
		if v.StubStatus {
			out = append(out, F{ID: "NGXSTATUS", Title: "stub_status enabled", Severity: inventory.Low, Component: v.File,
				Evidence: strings.Join(v.ServerNames, " "), Confidence: inventory.Possible, Impact: "Exposes server metrics if not restricted.", NextStep: "Restrict with allow/deny.", Method: "nginx config"})
		}
		for _, root := range v.Roots {
			if root == "/" || root == "/etc" || root == "/home" || root == "/root" {
				out = append(out, F{ID: "NGXROOT", Title: "Overly broad root " + root, Severity: inventory.High, Component: v.File,
					Evidence: "root " + root, Impact: "Sensitive files may be served.", NextStep: "Narrow document root.", Method: "nginx config"})
			}
		}
		for _, sn := range v.ServerNames {
			for _, l := range v.Listens {
				k := sn + "|" + strings.Fields(l)[0]
				if f, dup := seen[k]; dup && f != v.File && sn != "_" {
					out = append(out, F{ID: "NGXDUP", Title: "Duplicate server_name " + sn, Severity: inventory.Medium, Component: sn,
						Evidence: f + " and " + v.File, Impact: "Nginx picks first; unexpected routing.", NextStep: "Remove duplicate.", Method: "nginx config"})
				}
				seen[k] = v.File
			}
		}
	}
	return
}

func sshRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	s, ok := topology.Get[*inventory.Security](r, "security")
	if !ok || s.SSHConfig == "" {
		return
	}
	if v := strings.ToLower(s.SSH["permitrootlogin"]); v == "yes" {
		out = append(out, F{ID: "SSHROOT", Title: "SSH root login with password allowed", Severity: inventory.High, Component: "sshd",
			Evidence: "PermitRootLogin yes", Impact: "Brute-force target.", NextStep: "Set PermitRootLogin prohibit-password or no.", Method: "sshd_config"})
	}
	if v := strings.ToLower(s.SSH["passwordauthentication"]); v == "yes" {
		out = append(out, F{ID: "SSHPASS", Title: "SSH password authentication enabled", Severity: inventory.Medium, Component: "sshd",
			Evidence: "PasswordAuthentication yes", Impact: "Credential brute-force risk.", NextStep: "Use keys only.", Method: "sshd_config"})
	}
	if strings.ToLower(s.SSH["permitemptypasswords"]) == "yes" {
		out = append(out, F{ID: "SSHEMPTY", Title: "SSH empty passwords permitted", Severity: inventory.Critical, Component: "sshd",
			Evidence: "PermitEmptyPasswords yes", Impact: "Unauthenticated login possible.", NextStep: "Set PermitEmptyPasswords no.", Method: "sshd_config"})
	}
	return
}

func permsRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	s, ok := topology.Get[*inventory.Security](r, "security")
	if !ok {
		return
	}
	for _, l := range s.Loose {
		out = append(out, F{ID: "PERM", Title: "Loose permissions on sensitive file", Severity: inventory.High, Component: strings.Fields(l)[0],
			Evidence: l, Impact: "Secrets readable/writable by other users.", NextStep: "chmod to restrictive mode.", Method: "stat"})
	}
	return
}

func mongoRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	d, ok := topology.Get[*inventory.Databases](r, "databases")
	if !ok {
		return
	}
	for _, m := range d.Mongo {
		public := strings.Contains(m.BindIP, "0.0.0.0") || strings.Contains(m.BindIP, "::")
		if public && strings.HasPrefix(m.Authorization, "disabled") {
			out = append(out, F{ID: "MONGOAUTH", Title: "MongoDB bound broadly without authorization", Severity: inventory.Critical, Component: m.ConfigPath,
				Evidence: "bindIp=" + m.BindIP + " authorization=" + m.Authorization, Confidence: inventory.Strong,
				Impact: "Anyone reaching the port can read/write all data.", NextStep: "Enable security.authorization and restrict bindIp/firewall.", Method: "mongod.conf"})
		} else if strings.HasPrefix(m.Authorization, "disabled") {
			out = append(out, F{ID: "MONGOAUTH", Title: "MongoDB authorization disabled", Severity: inventory.Medium, Component: m.ConfigPath,
				Evidence: "authorization=" + m.Authorization + " bindIp=" + m.BindIP, Impact: "Any local process can access data.", NextStep: "Enable security.authorization.", Method: "mongod.conf"})
		}
	}
	for _, cf := range d.Configs {
		if cf.Kind == "redis" && cf.Facts["protected-mode"] == "no" && cf.Facts["requirepass"] != "set" {
			out = append(out, F{ID: "REDISAUTH", Title: "Redis without password and protected-mode off", Severity: inventory.High, Component: cf.Path,
				Evidence: "protected-mode no, requirepass unset, bind=" + cf.Facts["bind"], Impact: "Unauthenticated access; known RCE vectors.", NextStep: "Set requirepass/ACL and bind localhost.", Method: "redis.conf"})
		}
		if b := cf.Facts["pg_hba_broad_rules"]; b != "" {
			out = append(out, F{ID: "PGHBA", Title: "Broad pg_hba.conf rules", Severity: inventory.High, Component: cf.Path,
				Evidence: b, Impact: "Wide network or trust auth.", NextStep: "Restrict CIDRs, use scram-sha-256.", Method: "pg_hba.conf"})
		}
	}
	return
}

func envRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	p, ok := topology.Get[*inventory.Projects](r, "projects")
	if !ok {
		return
	}
	for _, pr := range p.Items {
		if len(pr.EnvLoose) > 0 {
			out = append(out, F{ID: "ENVPERM", Title: "World-readable .env in " + pr.Path, Severity: inventory.Medium, Component: pr.Path,
				Evidence: strings.Join(pr.EnvLoose, ", "), Impact: "Secrets readable by any local user.", NextStep: "chmod 600.", Method: "stat"})
		}
		if pr.Git != nil && pr.Git.Dirty {
			out = append(out, F{ID: "GITDIRTY", Title: "Uncommitted changes in deployed repo " + pr.Path, Severity: inventory.Low, Component: pr.Path,
				Evidence: "branch " + pr.Git.Branch + " @" + pr.Git.Commit, Impact: "Drift between deployed and versioned code.", NextStep: "git status (manual).", Method: "git status"})
		}
	}
	return
}

func rebootRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	if h, ok := topology.Get[*inventory.Host](r, "host"); ok && h.RebootRequired {
		out = append(out, F{ID: "REBOOT", Title: "Reboot required", Severity: inventory.Low, Component: "host", Evidence: "/var/run/reboot-required exists",
			Impact: "Kernel/library updates not active.", NextStep: "Plan maintenance reboot.", Method: "file"})
	}
	return
}

func collectorRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	for _, n := range r.Order {
		c := r.Collectors[n]
		if c != nil && c.Status == inventory.StatusError {
			out = append(out, F{ID: "COLLECT", Title: "Collector failed: " + n, Severity: inventory.Info, Component: n, Evidence: c.Error,
				Confidence: inventory.Unknown, Impact: "Section incomplete.", NextStep: "Run `serveradar doctor`; retry with sudo if permission related.", Method: "runner"})
		}
	}
	return
}

func limit[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func HumanBytes(b uint64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%d B", b)
	}
	d, e := uint64(u), 0
	for n := b / u; n >= u; n /= u {
		d *= u
		e++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(d), "KMGTPE"[e])
}
