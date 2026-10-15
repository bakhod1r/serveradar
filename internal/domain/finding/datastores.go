package finding

import (
	"fmt"
	"strings"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/domain/policy"
	"github.com/bakhod1r/serveradar/internal/domain/topology"
)

func exposureRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	for _, e := range r.Exposure {
		if e.Risk != "high" {
			continue
		}
		// DB bind findings already emitted by publicDBRule for classic ports; avoid duplicates
		if _, dup := dbPorts[e.Port]; dup {
			continue
		}
		name := e.Service
		if name == "" {
			name = e.Process
		}
		out = append(out, F{ID: "PORTEXP", Title: fmt.Sprintf("%s port %d/%s reachable from network", name, e.Port, e.Proto), Severity: inventory.High,
			Component: fmt.Sprintf("%s:%d", e.Bind, e.Port), Evidence: fmt.Sprintf("scope=%s process=%s container=%s firewall=%s", e.Scope, e.Process, e.Container, e.Firewall),
			Confidence: inventory.Strong, Impact: e.Note, NextStep: "Bind to 127.0.0.1/private IP or restrict with firewall/security group.", Method: "socket + firewall analysis"})
	}
	return
}

func cronRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	cr, ok := topology.Get[*inventory.Cron](r, "cron")
	if !ok {
		return
	}
	for _, j := range cr.Jobs {
		for _, risk := range j.Risks {
			sev := inventory.Severity("")
			switch {
			case strings.Contains(risk, "world-writable"), strings.Contains(risk, "downloads and executes"):
				sev = inventory.High
				if j.User == "root" {
					sev = inventory.Critical
				}
			case strings.Contains(risk, "group-writable"), strings.Contains(risk, "secret in command"):
				sev = inventory.Medium
			case strings.Contains(risk, "script missing"), strings.Contains(risk, "/tmp"):
				sev = inventory.Low
			}
			if sev == "" {
				continue
			}
			out = append(out, F{ID: "CRON", Title: "Cron job risk: " + risk, Severity: sev, Component: j.Source + " (" + j.User + ")",
				Evidence: j.Schedule + " " + j.Command, Impact: "Scheduled code runs as " + j.User + ".", NextStep: "Fix ownership/permissions or remove job.", Method: "cron parse + stat"})
		}
	}
	return
}

func pgRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	pg, ok := topology.Get[*inventory.Postgres](r, "postgres")
	if !ok {
		return
	}
	for _, in := range pg.Instances {
		comp := "postgres " + in.Target
		for _, h := range in.HBA {
			if h.Type == "local" || h.Error != "" {
				continue
			}
			anyAddr := strings.Contains(h.Meaning, "ANY address")
			switch {
			case h.Auth == "trust" && anyAddr:
				out = append(out, F{ID: "PGTRUST", Title: "pg_hba trusts ANY address without password", Severity: inventory.Critical, Component: comp,
					Evidence: fmt.Sprintf("line %d: %s", h.Line, h.Meaning), Impact: "Anyone reaching the port logs in as any user.", NextStep: "Change to scram-sha-256 and narrow address.", Method: "pg_hba_file_rules"})
			case h.Auth == "trust":
				out = append(out, F{ID: "PGTRUST", Title: "pg_hba trust rule for network clients", Severity: inventory.High, Component: comp,
					Evidence: fmt.Sprintf("line %d: %s", h.Line, h.Meaning), Impact: "No password for matching hosts.", NextStep: "Use scram-sha-256.", Method: "pg_hba_file_rules"})
			case h.Auth == "password":
				out = append(out, F{ID: "PGCLEAR", Title: "pg_hba cleartext password auth", Severity: inventory.Medium, Component: comp,
					Evidence: fmt.Sprintf("line %d", h.Line), Impact: "Password sent in clear without TLS.", NextStep: "Use scram-sha-256 + hostssl.", Method: "pg_hba_file_rules"})
			case h.Auth == "md5":
				out = append(out, F{ID: "PGMD5", Title: "pg_hba uses md5", Severity: inventory.Low, Component: comp, Evidence: fmt.Sprintf("line %d: %s", h.Line, h.Meaning),
					Impact: "Weaker hashing than SCRAM.", NextStep: "password_encryption=scram-sha-256, re-set passwords, switch rule.", Method: "pg_hba_file_rules"})
			}
		}
		supers := []string{}
		for _, ro := range in.Roles {
			if ro.Superuser && ro.Login {
				supers = append(supers, ro.Name)
			}
		}
		if len(supers) > 2 {
			out = append(out, F{ID: "PGSUPER", Title: fmt.Sprintf("%d login superusers", len(supers)), Severity: inventory.Medium, Component: comp,
				Evidence: strings.Join(supers, ", "), Impact: "Broad blast radius on credential leak.", NextStep: "Apps should use least-privilege roles.", Method: "pg_roles"})
		}
		if in.Settings["ssl"] == "off" && (in.Settings["listen_addresses"] == "*" || in.Settings["listen_addresses"] == "0.0.0.0") {
			out = append(out, F{ID: "PGSSL", Title: "PostgreSQL listens broadly with ssl=off", Severity: inventory.Medium, Component: comp,
				Evidence: "listen_addresses=" + in.Settings["listen_addresses"], Impact: "Credentials/data unencrypted on the wire.", NextStep: "Enable ssl or restrict to localhost/private.", Method: "pg_settings"})
		}
		for _, s := range in.Slots {
			if !s.Active {
				out = append(out, F{ID: "PGSLOT", Title: "Inactive replication slot " + s.Name, Severity: inventory.High, Component: comp,
					Evidence: "retained WAL " + s.Retained, Impact: "WAL accumulates until disk fills.", NextStep: "Reconnect consumer or drop slot (manual).", Method: "pg_replication_slots"})
			}
		}
		for _, a := range in.Activity {
			if a.State == "idle in transaction" && a.MaxXactSec > 300 {
				out = append(out, F{ID: "PGIDLETX", Title: "Long idle-in-transaction sessions", Severity: inventory.Medium, Component: comp,
					Evidence: fmt.Sprintf("%d sessions user=%s db=%s oldest %ds", a.N, a.User, a.Database, a.MaxXactSec), Impact: "Blocks vacuum, holds locks.",
					NextStep: "Fix app transaction handling; set idle_in_transaction_session_timeout.", Method: "pg_stat_activity"})
			}
		}
		for _, d := range in.Databases {
			if d.Detail == nil {
				continue
			}
			for _, t := range d.Detail.Tables {
				if t.EstRows > 10000 && t.DeadTuples > t.EstRows/5 {
					out = append(out, F{ID: "PGBLOAT", Title: fmt.Sprintf("High dead tuples in %s.%s", d.Name, t.Name), Severity: inventory.Low, Component: comp,
						Evidence: fmt.Sprintf("%d dead / %d rows, last autovacuum %s", t.DeadTuples, t.EstRows, t.LastAutovac), Impact: "Bloat, slower scans.", NextStep: "Tune autovacuum for this table.", Method: "pg_stat_user_tables"})
				}
			}
		}
	}
	return
}

func mysqlRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	my, ok := topology.Get[*inventory.MySQL](r, "mysql")
	if !ok {
		return
	}
	for _, in := range my.Instances {
		comp := "mysql " + in.Target
		for _, u := range in.Users {
			who := fmt.Sprintf("'%s'@'%s'", u.User, u.Host)
			socket := strings.Contains(u.Plugin, "socket") || strings.Contains(u.Plugin, "unix")
			switch {
			case u.EmptyPassword && !socket && u.Host != "localhost":
				out = append(out, F{ID: "MYEMPTY", Title: "MySQL account with empty password reachable remotely", Severity: inventory.Critical, Component: comp,
					Evidence: who + " plugin=" + u.Plugin, Impact: "Login without password.", NextStep: "Set password or drop account.", Method: "mysql.user"})
			case u.User == "":
				out = append(out, F{ID: "MYANON", Title: "Anonymous MySQL account", Severity: inventory.High, Component: comp, Evidence: who,
					Impact: "Anyone can log in.", NextStep: "DROP USER ''@'" + u.Host + "' (manual).", Method: "mysql.user"})
			case u.Host == "%" && contains(u.Global, "Super"):
				out = append(out, F{ID: "MYSUPERANY", Title: "Superuser reachable from any host", Severity: inventory.High, Component: comp,
					Evidence: who + " global=" + strings.Join(u.Global, ","), Impact: "Full control if password leaks.", NextStep: "Restrict host to admin IPs.", Method: "mysql.user"})
			}
		}
		for _, a := range in.Analysis {
			switch {
			case strings.HasPrefix(a, "Replication error"):
				out = append(out, F{ID: "MYREPL", Title: "MySQL replication error", Severity: inventory.High, Component: comp, Evidence: a, Impact: "Replica stale.", NextStep: "SHOW REPLICA STATUS\\G", Method: "replica status"})
			case strings.Contains(a, "tables without PRIMARY KEY"):
				out = append(out, F{ID: "MYNOPK", Title: "Tables without primary key", Severity: inventory.Low, Component: comp, Evidence: a, Impact: "Replication/perf issues.", NextStep: "Add PKs.", Method: "information_schema"})
			case strings.HasPrefix(a, "Connections peaked"):
				out = append(out, F{ID: "MYCONN", Title: "Connection usage near max", Severity: inventory.Medium, Component: comp, Evidence: a, Impact: "New connections refused.", NextStep: "Pooling or raise max_connections.", Method: "status"})
			}
		}
	}
	return
}

func redisRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	rd, ok := topology.Get[*inventory.Redis](r, "redis")
	if !ok {
		return
	}
	for _, in := range rd.Instances {
		if in.Error != "" || in.AuthNeeded {
			continue
		}
		wide := false
		for _, e := range in.Exposure {
			wide = wide || strings.Contains(e, "ALL interfaces") || strings.Contains(e, "docker publishes 0.0.0.0")
		}
		sev := inventory.Medium
		if wide {
			sev = inventory.Critical
		}
		out = append(out, F{ID: "REDISNOAUTH", Title: "Redis accepts commands without password", Severity: sev, Component: "redis " + in.Target,
			Evidence: strings.Join(in.Exposure, "; "), Impact: "Read/write all keys; CONFIG abuse can lead to RCE.", NextStep: "requirepass / ACL, bind localhost, rename-command CONFIG.", Method: "RESP INFO"})
		if in.Info["maxmemory_human"] == "0B" && in.Info["role"] == "master" {
			out = append(out, F{ID: "REDISMAXMEM", Title: "Redis maxmemory unlimited", Severity: inventory.Low, Component: "redis " + in.Target,
				Evidence: "maxmemory=0, used " + in.Info["used_memory_human"], Impact: "Can exhaust host RAM (OOM).", NextStep: "Set maxmemory + eviction policy.", Method: "INFO memory"})
		}
		if in.Info["rdb_last_bgsave_status"] == "err" || in.Info["aof_last_write_status"] == "err" {
			out = append(out, F{ID: "REDISPERSIST", Title: "Redis persistence failing", Severity: inventory.High, Component: "redis " + in.Target,
				Evidence: "rdb=" + in.Info["rdb_last_bgsave_status"] + " aof=" + in.Info["aof_last_write_status"], Impact: "Data loss on restart.", NextStep: "Check disk space/permissions.", Method: "INFO persistence"})
		}
	}
	return
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func dbAccessRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	a, ok := topology.Get[*inventory.DBAccess](r, "dbaccess")
	if !ok {
		return
	}
	lanOpen := map[string]bool{}
	for _, c := range a.Checks {
		if strings.HasPrefix(c.Verdict, "OPEN WITHOUT PASSWORD") && strings.HasPrefix(c.Path, "LAN") {
			lanOpen[c.Owner+fmt.Sprint(c.Port)] = true
		}
	}
	for _, c := range a.Checks {
		if !strings.HasPrefix(c.Verdict, "OPEN WITHOUT PASSWORD") || c.Path == "loopback" && lanOpen[c.Owner+fmt.Sprint(c.Port)] {
			continue
		}
		sev, impact := inventory.Medium, "Any local process/user can read and write all data."
		if strings.HasPrefix(c.Path, "LAN") {
			sev, impact = inventory.Critical, "Anyone on the network can read and write all data — verified by live handshake."
		}
		out = append(out, F{ID: "DBOPEN", Title: fmt.Sprintf("%s on port %d answers without password (%s)", c.Engine, c.Port, c.Path), Severity: sev,
			Component: c.Owner, Evidence: c.Auth + ": " + c.Detail, Confidence: inventory.Confirmed, Impact: impact,
			NextStep: "Enable authentication and bind to localhost; for Docker publish as 127.0.0.1:PORT:PORT.", Method: "live anonymous handshake"})
	}
	return
}

func servicesRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	sv, ok := topology.Get[*inventory.Services](r, "services")
	if !ok {
		return
	}
	for _, ck := range sv.Checks {
		for _, n := range ck.Notes {
			sev := inventory.Severity("")
			switch {
			case strings.Contains(n, "NOT initialized"), strings.Contains(n, "keys (incl. Kubernetes secrets) readable"):
				sev = inventory.Critical
			case strings.Contains(n, "without authentication"), strings.Contains(n, "SEALED"), strings.Contains(n, "plain HTTP"),
				strings.Contains(n, "without auth"), strings.HasPrefix(n, "PLAINTEXT listener"):
				sev = inventory.High
			case strings.Contains(n, "SASL_PLAINTEXT"), strings.Contains(n, "no consumers"), strings.Contains(n, "replication factor 1"):
				sev = inventory.Medium
			case strings.Contains(n, "auto.create"), strings.Contains(n, "advertised.listeners"):
				sev = inventory.Low
			}
			if sev == "" {
				continue
			}
			out = append(out, F{ID: "SVC", Title: ck.Kind + ": " + n, Severity: sev, Component: ck.Kind + " " + ck.Owner,
				Evidence: ck.Endpoint + " " + ck.Auth, Confidence: inventory.Strong, Impact: n, NextStep: "Review " + ck.Kind + " security configuration.", Method: "status endpoint / config"})
		}
	}
	return
}

func unitRule(r *inventory.Report, _ *policy.Policy) (out []F) {
	sd, ok := topology.Get[*inventory.Systemd](r, "systemd")
	if !ok {
		return
	}
	for _, u := range sd.Details {
		for _, risk := range u.Risks {
			sev := inventory.Low
			switch {
			case strings.Contains(risk, "world-writable"), strings.Contains(risk, "from /tmp"), strings.Contains(risk, "writable by group/others"):
				sev = inventory.High
				if u.User == "root" {
					sev = inventory.Critical
				}
			case strings.Contains(risk, "EnvironmentFile world-readable"):
				sev = inventory.Medium
			case strings.Contains(risk, "missing"), strings.Contains(risk, "Restart=no"):
				sev = inventory.Low
			case strings.Contains(risk, "without sandboxing"):
				sev = inventory.Info
			}
			out = append(out, F{ID: "UNITRISK", Title: u.Name + ": " + risk, Severity: sev, Component: u.Name, Evidence: u.Fragment + " User=" + u.User,
				Impact: "Service runs as " + u.User + ".", NextStep: "Fix permissions / harden unit (systemd-analyze security " + u.Name + ").", Method: "systemctl show + stat"})
		}
	}
	return
}
