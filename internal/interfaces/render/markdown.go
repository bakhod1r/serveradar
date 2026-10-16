// Package render turns a report into JSON, Markdown, or terminal text.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/finding"
	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/domain/topology"
)

var hb = finding.HumanBytes

func JSON(w io.Writer, r *inventory.Report) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(r)
}

type md struct {
	w  io.Writer
	st *mdState
}

// mdState: when collapse is on, ## and ### headings become nested <details> blocks.
type mdState struct {
	collapse    bool
	grp, h2, h3 bool
	htmlCharts  bool
	report      *inventory.Report
	shownCfg    map[string]bool
	openNext    bool
	anchor      string
}

func (m md) p(f string, a ...any) { fmt.Fprintf(m.w, f+"\n", a...) }

func (m md) h(level int, s string) {
	if m.st == nil || !m.st.collapse || level > 3 {
		m.p("\n%s %s\n", strings.Repeat("#", level), s)
		return
	}
	if m.st.h3 {
		m.p("\n</details>\n")
		m.st.h3 = false
	}
	if level == 2 {
		if m.st.h2 {
			m.p("\n</details>\n")
		}
		open := ""
		if m.st.openNext {
			open = " open"
			m.st.openNext = false
		}
		if m.st.anchor != "" {
			m.p("\n<a id=\"%s\"></a>", m.st.anchor)
			m.st.anchor = ""
		}
		m.p("\n<details%s>\n<summary><h2>%s</h2></summary>\n", open, html(s))
		m.st.h2 = true
		return
	}
	m.p("\n<details>\n<summary><b>%s</b></summary>\n", html(s))
	m.st.h3 = true
}

// group opens a top-level collapsible area (closing any open one).
func (m md) group(anchor, title string, open bool) {
	if m.st == nil || !m.st.collapse {
		m.p("\n# %s\n", title)
		return
	}
	m.end()
	o := ""
	if open {
		o = " open"
	}
	m.p("\n<a id=\"%s\"></a>\n<details class=\"group\"%s>\n<summary><h1>%s</h1></summary>\n", anchor, o, html(title))
	m.st.grp = true
}

// end closes any open collapsible blocks.
func (m md) end() {
	if m.st == nil {
		return
	}
	if m.st.h3 {
		m.p("\n</details>\n")
		m.st.h3 = false
	}
	if m.st.h2 {
		m.p("\n</details>\n")
		m.st.h2 = false
	}
	if m.st.grp {
		m.p("\n</details>\n")
		m.st.grp = false
	}
}

func (m md) section2(anchor, title string, open bool) {
	if m.st != nil {
		m.st.anchor, m.st.openNext = anchor, open
	}
	m.h(2, title)
}

func html(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
func (m md) table(head []string, rows [][]string) {
	m.p("")
	if len(rows) == 0 {
		m.p("_none_")
		return
	}
	m.p("| %s |", strings.Join(head, " | "))
	m.p("|%s", strings.Repeat("---|", len(head)))
	for _, r := range rows {
		for i := range r {
			r[i] = strings.ReplaceAll(strings.ReplaceAll(r[i], "|", "\\|"), "\n", " ")
		}
		m.p("| %s |", strings.Join(r, " | "))
	}
}
func (m md) kv(pairs ...string) {
	var rows [][]string
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			rows = append(rows, []string{"**" + pairs[i] + "**", pairs[i+1]})
		}
	}
	m.table([]string{"Key", "Value"}, rows)
}

// Markdown writes the full report: every section, all collected data.
// Group is a top-level report area made of collector sections.
type Group struct {
	ID, Title string
	Members   []string // collector names; "exposure" is the derived port matrix
}

var Groups = []Group{
	{"g-security", "Security & Exposure", []string{"exposure", "dbaccess", "security", "firewall"}},
	{"g-system", "System & Resources", []string{"host", "resources", "processes", "systemd", "cron", "tools"}},
	{"g-network", "Network", []string{"network", "ports"}},
	{"g-containers", "Containers & Orchestration", []string{"docker", "kubernetes"}},
	{"g-data", "Data Stores & Brokers", []string{"databases", "postgres", "mysql", "redis", "services"}},
	{"g-web", "Web, Proxies & TLS", []string{"nginx", "tls"}},
	{"g-apps", "Applications & Deployments", []string{"projects"}},
}

func (g Group) present(r *inventory.Report) bool {
	for _, n := range g.Members {
		if n == "exposure" && len(r.Exposure) > 0 || r.Collectors[n] != nil {
			return true
		}
	}
	return false
}

// Markdown writes the full report grouped into collapsible areas, with charts and diagrams.
func Markdown(w io.Writer, r *inventory.Report) { markdown(w, r, false) }

func markdown(w io.Writer, r *inventory.Report, htmlCharts bool) {
	m := md{w, &mdState{collapse: true, htmlCharts: htmlCharts, report: r, shownCfg: map[string]bool{}}}
	m.p("# Serveradar Report — %s", r.Hostname)
	m.p("")
	m.p("Generated %s · profile `%s` · tool %s · schema %s · user `%s` (root=%v) · %s",
		r.FinishedAt.Format(time.RFC3339), r.Profile, r.ToolVersion, r.SchemaVersion, r.Privileges.User, r.Privileges.Root,
		r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))
	toc(m, r)

	m.group("g-overview", "Overview", true)
	m.section2("summary", "Executive Summary", true)
	summaryBody(m, r)
	m.section2("dashboard", "Dashboard", true)
	if htmlCharts {
		m.p(`<div class="charts">`)
		for _, c := range Charts(r) {
			m.p("%s", chartSVG(c))
		}
		m.p(`</div>`)
	} else {
		for _, c := range Charts(r) {
			chartMD(m, c)
		}
	}
	m.section2("findings", fmt.Sprintf("Findings & Recommended Actions (%d)", len(r.Findings)), true)
	var rows [][]string
	for _, f := range r.Findings {
		rows = append(rows, []string{f.ID, strings.ToUpper(string(f.Severity)), f.Title, f.Component, f.Evidence, string(f.Confidence), f.Impact, f.NextStep})
	}
	m.table([]string{"ID", "Severity", "Title", "Component", "Evidence", "Confidence", "Impact", "Next step"}, rows)
	if g := ArchitectureMermaid(r); g != "" {
		m.section2("architecture", "Architecture — what is exposed and who serves it", false)
		m.p("Red = high-risk exposure.\n\n```mermaid\n%s```", g)
	}
	if g := AccessMermaid(r); g != "" {
		m.section2("access", "Database access map (live handshake)", false)
		m.p("Red = answers without password · blue = password required · green dashed = closed/rejected.\n\n```mermaid\n%s```", g)
	}
	if g := topology.MermaidTopology(r); g != "" {
		m.section2("graph", fmt.Sprintf("Component Relationship Graph (%d)", len(r.Relationships)), false)
		m.p("Solid = confirmed, dashed = inferred.\n\n```mermaid\n%s```", g)
		rows = nil
		for _, x := range r.Relationships {
			rows = append(rows, []string{x.Source, x.Kind, x.Target, string(x.Confidence), x.Evidence})
		}
		m.table([]string{"Source", "Relation", "Target", "Confidence", "Evidence"}, rows)
	}

	for _, g := range Groups {
		if !g.present(r) {
			continue
		}
		m.group(g.ID, g.Title, false)
		for _, name := range g.Members {
			if name == "exposure" {
				if len(r.Exposure) > 0 {
					m.st.anchor = "exposure"
					exposureBody(m, r)
				}
				continue
			}
			if c := r.Collectors[name]; c != nil {
				m.st.anchor = "sec-" + name
				section(m, r, name, c)
			}
		}
	}

	m.group("g-meta", "Scan Scope & Limitations", false)
	m.section2("scope", "Collectors, permissions, warnings", false)
	rows = nil
	for _, n := range r.Order {
		c := r.Collectors[n]
		rows = append(rows, []string{n, string(c.Status), strconv.FormatInt(c.DurationMs, 10) + "ms", c.Error, strings.Join(c.Warnings, "; ")})
	}
	m.table([]string{"Collector", "Status", "Duration", "Error", "Warnings"}, rows)
	m.p("\nRead-only scan. Secrets, env values (unless `--show-env`), private keys, and DB contents are never collected. Wildcard binds are context, not proof of internet exposure.")
	m.end()
}

func summaryBody(m md, r *inventory.Report) {
	counts := map[inventory.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	m.p("- Findings: **%d critical**, **%d high**, %d medium, %d low, %d info", counts[inventory.Critical], counts[inventory.High], counts[inventory.Medium], counts[inventory.Low], counts[inventory.Info])
	if h, ok := topology.Get[*inventory.Host](r, "host"); ok {
		m.p("- %s · kernel %s · %s · %d CPU · RAM %s · up %s", h.Distro, h.Kernel, h.Arch, h.CPUs, hb(h.MemTotal), Dur(h.UptimeSec))
	}
	if p, ok := topology.Get[*inventory.Ports](r, "ports"); ok {
		m.p("- Listening sockets: %d · established peers: %d", len(p.Sockets), len(p.Peers))
	}
	if d, ok := topology.Get[*inventory.Docker](r, "docker"); ok {
		m.p("- Docker %s: %d containers, %d images, %d networks, %d volumes", d.Version, len(d.Containers), len(d.Images), len(d.Networks), len(d.Volumes))
	}
	if d, ok := topology.Get[*inventory.Databases](r, "databases"); ok {
		var k []string
		for _, s := range d.Services {
			k = append(k, s.Kind)
		}
		m.p("- Data services: %s", orNone(strings.Join(k, ", ")))
	}
	hi := 0
	for _, e := range r.Exposure {
		if e.Risk == "high" {
			hi++
		}
	}
	if len(r.Exposure) > 0 {
		m.p("- Open ports: %d listening, **%d high-risk exposures**", len(r.Exposure), hi)
	}
	if t, ok := topology.Get[*inventory.Tools](r, "tools"); ok {
		m.p("- DevOps tools: %d (%s)", len(t.Items), mapStr(t.ByCategory))
	}
	if cr, ok := topology.Get[*inventory.Cron](r, "cron"); ok {
		m.p("- Scheduled: %s", strings.Join(cr.Summary, "; "))
	}
	if pg, ok := topology.Get[*inventory.Postgres](r, "postgres"); ok {
		for _, in := range pg.Instances {
			var sz int64
			n := 0
			for _, d := range in.Databases {
				if !d.IsTemplate {
					n++
					if d.SizeBytes > 0 {
						sz += d.SizeBytes
					}
				}
			}
			m.p("- PostgreSQL %s: %d databases, %s, %d roles", in.Target, n, hbi(sz), len(in.Roles))
		}
	}
	if my, ok := topology.Get[*inventory.MySQL](r, "mysql"); ok {
		for _, in := range my.Instances {
			if len(in.Analysis) > 0 {
				m.p("- %s %s: %s, %d users", in.Flavor, in.Target, in.Analysis[0], len(in.Users))
			}
		}
	}
	if rd, ok := topology.Get[*inventory.Redis](r, "redis"); ok {
		for _, in := range rd.Instances {
			st := in.Info["used_memory_human"] + " used, " + strconv.Itoa(len(in.Keyspace)) + " keyspaces"
			if in.Error != "" {
				st = in.Error
			}
			m.p("- Redis %s: %s", in.Target, st)
		}
	}
}

func section(m md, r *inventory.Report, name string, c *inventory.CollectorResult) {
	title := map[string]string{"host": "Host & OS · CPU / Memory / Disk", "resources": "Resource Usage — who uses what",
		"processes": "Processes", "network": "Network Interfaces & Routes", "ports": "Listening Ports & IP Lists",
		"systemd": "systemd Services", "cron": "Cron & Scheduled Jobs", "docker": "Docker", "kubernetes": "Kubernetes / Swarm / Clusters",
		"nginx": "Nginx / Virtual Hosts / Upstreams", "tls": "TLS Certificates", "projects": "Application Projects & Git",
		"databases": "Databases (PostgreSQL / MySQL / Redis / MongoDB / ...)", "tools": "DevOps Tools", "services": "Brokers, Vault, Search & Other Services", "dbaccess": "Databases — open / closed check (live)", "dbconfig": "Databases — config files (active lines, secrets masked)", "postgres": "PostgreSQL — databases, sizes, users, access", "mysql": "MySQL / MariaDB — databases, sizes, users, access", "redis": "Redis — memory, keyspace, clients, access", "firewall": "Firewall", "security": "Security Posture"}[name]
	badge := ""
	if c.Status != inventory.StatusOK {
		badge = " · " + string(c.Status)
	}
	m.h(2, title+badge)
	if c.Status != inventory.StatusOK {
		m.p("> status: **%s** %s", c.Status, c.Error)
		for _, w := range c.Warnings {
			m.p("> - %s", w)
		}
	}
	defer func() { // config files live with their engine
		if fam, ok := cfgFamilies[name]; ok {
			cfgLeftovers(m, fam, "Config files")
		}
	}()
	if c.Data == nil {
		return
	}
	switch d := c.Data.(type) {
	case *inventory.Host:
		m.kv("Hostname", d.Hostname, "OS", d.Distro, "Kernel", d.Kernel, "Arch", d.Arch, "Virtualization", d.Virtualization,
			"Machine ID (hashed)", d.MachineIDHash, "Boot", d.BootTime.Format(time.RFC3339), "Uptime", Dur(d.UptimeSec), "Timezone", d.Timezone,
			"CPU", fmt.Sprintf("%s × %d", d.CPUModel, d.CPUs), "Load 1/5/15", fmt.Sprintf("%.2f / %.2f / %.2f", d.Load[0], d.Load[1], d.Load[2]),
			"Memory", fmt.Sprintf("%s total, %s available, %s cached", hb(d.MemTotal), hb(d.MemAvailable), hb(d.MemCached)),
			"Swap", fmt.Sprintf("%s total, %s used", hb(d.SwapTotal), hb(d.SwapTotal-d.SwapFree)), "Reboot required", strconv.FormatBool(d.RebootRequired))
		m.h(3, "Filesystems")
		var rows [][]string
		for _, x := range d.Mounts {
			rows = append(rows, []string{x.Mountpoint, x.Device, x.FSType, hb(x.TotalBytes), hb(x.UsedBytes), fmt.Sprintf("%.1f%%", x.UsedPct), fmt.Sprintf("%.1f%%", x.InodesPct), yn(x.ReadOnly)})
		}
		m.table([]string{"Mount", "Device", "FS", "Size", "Used", "Use%", "Inodes%", "RO"}, rows)
	case *inventory.Resources:
		ut := func(t string, u []inventory.Usage, keyName string) {
			if len(u) == 0 {
				return
			}
			m.h(3, t)
			var rows [][]string
			for _, x := range u {
				rows = append(rows, []string{x.Key, strconv.Itoa(x.Count), fmt.Sprintf("%.1f", x.CPU), hb(x.RSS), fmt.Sprintf("%.1f%%", x.MemPct), hbz(x.ReadB), hbz(x.WriteB)})
			}
			m.table([]string{keyName, "Procs", "CPU%", "RSS", "Mem%", "IO read", "IO write"}, rows)
		}
		ut("Top CPU processes", d.TopCPU, "Process")
		ut("Top memory processes", d.TopMem, "Process")
		ut("Top disk IO processes", d.TopIO, "Process")
		ut("By application", d.ByApp, "Application")
		ut("By user", d.ByUser, "User")
		ut("By systemd unit / container (cgroup)", d.ByUnit, "Unit")
		if d.IONote != "" {
			m.p("\n_%s_", d.IONote)
		}
		if len(d.BigDirs) > 0 {
			m.h(3, "Largest directories")
			var rows [][]string
			for _, x := range d.BigDirs {
				rows = append(rows, []string{x.Path, hb(x.Bytes)})
			}
			m.table([]string{"Path", "Size"}, rows)
		}
	case *inventory.ProcessList:
		m.p("Total processes: **%d**", d.Total)
		ps := append([]inventory.Process(nil), d.All...)
		sort.Slice(ps, func(i, j int) bool { return ps[i].MemRSS > ps[j].MemRSS })
		var rows [][]string
		for _, p := range ps {
			rows = append(rows, []string{strconv.Itoa(p.PID), strconv.Itoa(p.PPID), p.User, fmt.Sprintf("%.1f", p.CPU), hb(p.MemRSS), p.Start, p.Comm, "`" + trunc(p.Cmdline, 160) + "`"})
		}
		m.table([]string{"PID", "PPID", "User", "CPU%", "RSS", "Elapsed", "Name", "Command (redacted)"}, rows)
	case *inventory.Network:
		var rows [][]string
		for _, i := range d.Interfaces {
			rows = append(rows, []string{i.Name, strings.Join(i.Addrs, ", "), i.MAC, strconv.Itoa(i.MTU), yn(i.Up)})
		}
		m.table([]string{"Interface", "Addresses", "MAC", "MTU", "Up"}, rows)
		m.h(3, "Routes")
		m.p("```\n%s\n```", strings.Join(d.Routes, "\n"))
		m.kv("DNS resolvers", strings.Join(d.Nameservers, ", "), "IPv4 forwarding", d.IPForward, "TCP states", mapStr(d.ConnStates))
	case *inventory.Ports:
		m.p("Method: `%s`", d.Method)
		var rows [][]string
		for _, s := range d.Sockets {
			rows = append(rows, []string{s.Proto, s.Address, strconv.Itoa(s.Port), pid(s.PID), s.Process, yn(s.Public)})
		}
		m.table([]string{"Proto", "Bind", "Port", "PID", "Process", "Wildcard"}, rows)
		m.h(3, "Local IP addresses")
		m.p("%s", "`"+strings.Join(d.LocalIPs, "` `")+"`")
		m.h(3, "Established peers (remote IPs)")
		rows = nil
		for _, p := range d.Peers {
			rows = append(rows, []string{p.Address, strconv.Itoa(p.Count), ints(p.Ports)})
		}
		m.table([]string{"Remote IP", "Connections", "Local ports"}, rows)
		if d.PeerNote != "" {
			m.p("_%s_", d.PeerNote)
		}
	case *inventory.Systemd:
		m.p("Counts: %s", mapStr(d.Counts))
		m.kv("Failed", strings.Join(d.Failed, ", "), "Enabled but inactive", strings.Join(d.EnabledInactive, ", "))
		m.h(3, "Service resource usage")
		var rows [][]string
		for _, u := range d.Usage {
			if u.MemBytes == 0 && u.CPUNsec == 0 {
				continue
			}
			rows = append(rows, []string{u.Unit, hb(u.MemBytes), (time.Duration(u.CPUNsec)).Round(time.Second).String(), strconv.Itoa(u.Restarts)})
		}
		m.table([]string{"Unit", "Memory", "CPU time", "Restarts"}, rows)
		m.h(3, "Services (custom first)")
		rows = nil
		for _, u := range d.Details {
			rows = append(rows, []string{u.Name, u.Origin, u.Active + "/" + u.Sub, u.Enabled, u.User, u.Restart, pid(u.MainPID), hbz(u.Memory),
				"`" + trunc(u.ExecStart, 120) + "`", strings.Join(u.Risks, "; ")})
		}
		m.table([]string{"Unit", "Origin", "State", "Enabled", "User", "Restart", "PID", "Memory", "ExecStart (redacted)", "Risks"}, rows)
		for _, u := range d.Details {
			if u.Origin != "custom" {
				continue
			}
			m.p("\n<details><summary><b>%s</b> — %s</summary>\n", u.Name, u.Description)
			m.kv("Unit file", u.Fragment, "Drop-ins", strings.Join(u.DropIns, ", "), "Type", u.Type, "WorkingDirectory", u.WorkDir,
				"EnvironmentFile", strings.Join(u.EnvFiles, ", "), "Environment keys", strings.Join(u.EnvKeys, ", "),
				"WantedBy", u.WantedBy, "Active since", u.Since, "Restarts", strconv.Itoa(u.Restarts), "Hardening", strings.Join(u.Hardening, ", "))
			m.p("</details>")
		}
		m.kv("Socket units", strings.Join(d.Sockets, ", "), "Mount units", strings.Join(d.Mounts, ", "))
	case *inventory.Tools:
		m.p("By category: %s", mapStr(d.ByCategory))
		var rows [][]string
		for _, t := range d.Items {
			run := ""
			if t.Running {
				run = "running"
			}
			rows = append(rows, []string{t.Category, t.Name, run, t.Version, ints(t.Ports), t.UI, strings.Join(t.Evidence, ", ")})
		}
		m.table([]string{"Category", "Tool", "State", "Version", "Ports", "Web UI (anonymous GET /)", "Evidence"}, rows)
	case *inventory.Cron:
		cronMD(m, d)
	case *inventory.Services:
		for _, ck := range d.Checks {
			m.h(3, ck.Kind+" — "+ck.Owner)
			var pairs []string
			pairs = append(pairs, "Endpoint", ck.Endpoint, "Anonymous access", ck.Auth)
			keys := make([]string, 0, len(ck.Facts))
			for k := range ck.Facts {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				pairs = append(pairs, k, ck.Facts[k])
			}
			m.kv(pairs...)
			bullets(m, "Analysis", ck.Notes)
		}
	case *inventory.DBAccess:
		m.p("_%s_", d.Note)
		var rows [][]string
		for _, x := range d.Checks {
			port := ""
			if x.Port > 0 {
				port = strconv.Itoa(x.Port)
			}
			rows = append(rows, []string{x.Engine, x.Owner, x.Path, port, x.TCP, x.Auth, x.Verdict, x.Detail})
		}
		m.table([]string{"Engine", "Owner", "Path", "Port", "TCP", "Auth demanded", "Verdict", "Detail"}, rows)
	case *inventory.DBConfigs:
		for _, n := range d.Notes {
			m.p("> %s", n)
		}
		for _, f := range d.Files {
			m.h(3, f.Engine+" — "+f.Where+" — "+f.Path)
			if f.Error != "" {
				m.p("> %s", f.Error)
			}
			if len(f.Lines) > 0 {
				m.p("%d active of %d lines\n\n```\n%s\n```", len(f.Lines), f.Total, strings.Join(f.Lines, "\n"))
			}
		}
	case *inventory.Postgres:
		pgMD(m, d)
	case *inventory.MySQL:
		mysqlMD(m, d)
	case *inventory.Redis:
		redisMD(m, d)
	case *inventory.Docker:
		dockerMD(m, r, d)
	case *inventory.Kubernetes:
		m.kv("Distribution", d.Distro, "Signals", strings.Join(d.Signals, ", "), "kubectl context", d.Kubectl, "Swarm", d.Swarm)
	case *inventory.Nginx:
		m.kv("Version", d.Version, "Running", yn(d.Running), "Source", d.Source, "Heuristic parse", yn(d.Heuristic))
		var rows [][]string
		for _, v := range d.Vhosts {
			rows = append(rows, []string{strings.Join(v.ServerNames, " "), strings.Join(v.Listens, ", "), strings.Join(v.ProxyPass, ", "),
				strings.Join(v.Roots, ", "), v.SSLCert, yn(v.Redirect), yn(v.DefaultSrv), v.File})
		}
		m.table([]string{"server_name", "listen", "proxy_pass", "root", "ssl_certificate", "→https", "default", "file"}, rows)
		if len(d.Upstreams) > 0 {
			m.h(3, "Upstreams")
			rows = nil
			for k, v := range d.Upstreams {
				rows = append(rows, []string{k, strings.Join(v, ", ")})
			}
			m.table([]string{"Upstream", "Servers"}, rows)
		}
	case *inventory.TLS:
		var rows [][]string
		for _, c := range d.Certs {
			rows = append(rows, []string{c.Subject, strings.Join(c.SANs, ", "), c.Issuer, c.NotAfter.Format("2006-01-02"), strconv.Itoa(c.DaysLeft), strings.Join(c.UsedBy, "; "), c.Path})
		}
		m.table([]string{"Subject", "SANs", "Issuer", "Expires", "Days", "Used by", "Path"}, rows)
		m.kv("Renewal tooling", strings.Join(d.Renewal, ", "))
	case *inventory.Projects:
		m.p("Searched: `%s`", strings.Join(d.Roots, "`, `"))
		var rows [][]string
		for _, p := range d.Items {
			g := []string{"", "", "", ""}
			if p.Git != nil {
				g = []string{p.Git.Branch, p.Git.Commit, yn(p.Git.Dirty), p.Git.Remote}
			}
			rows = append(rows, append([]string{p.Path, strings.Join(p.Markers, ", "), strings.Join(p.Manifests, ", "), strings.Join(p.EnvFiles, ", ")}, g...))
		}
		m.table([]string{"Path", "Markers", "Deploy manifests", ".env files", "Branch", "Commit", "Dirty", "Remote"}, rows)
	case *inventory.Databases:
		var rows [][]string
		for _, s := range d.Services {
			rows = append(rows, []string{s.Kind, strings.Join(s.Source, ", "), ints(s.PIDs), ints(s.Ports), s.Container, s.Cluster, strings.Join(s.Configs, ", ")})
		}
		m.table([]string{"Service", "Detected by", "PIDs", "Ports", "Containers", "Cluster/replication hint", "Config"}, rows)
		if len(d.Mongo) > 0 {
			m.h(3, "MongoDB")
			rows = nil
			for _, x := range d.Mongo {
				rows = append(rows, []string{x.ConfigPath, x.BindIP, strconv.Itoa(x.Port), x.ReplSet, x.ShardRole, x.Authorization, x.TLSMode, x.DBPath})
			}
			m.table([]string{"Config", "bindIp", "Port", "Replica set", "Shard role", "Authorization", "TLS", "dbPath"}, rows)
		}
		for _, cf := range d.Configs {
			m.h(3, cf.Kind+" — "+cf.Path)
			var pairs []string
			keys := make([]string, 0, len(cf.Facts))
			for k := range cf.Facts {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				pairs = append(pairs, k, cf.Facts[k])
			}
			m.kv(pairs...)
		}
	case *inventory.Firewall:
		m.kv("Backends", strings.Join(d.Backends, ", "), "UFW", d.UFW)
		if len(d.Rules) > 0 {
			m.p("```\n%s\n```", strings.Join(d.Rules, "\n"))
		}
	case *inventory.Security:
		var pairs []string
		for k, v := range d.SSH {
			pairs = append(pairs, "sshd "+k, v)
		}
		m.kv(append(pairs, "Loose permissions", strings.Join(d.Loose, ", "), "Privileged groups", strings.Join(d.Sudoers, "; "),
			"Login-shell users", strings.Join(d.LoginUsers, ", "))...)
	default:
		b, _ := json.MarshalIndent(d, "", "  ")
		m.p("```json\n%s\n```", b)
	}
}

func dockerMD(m md, r *inventory.Report, d *inventory.Docker) {
	m.kv("Version", d.Version, "Rootless", yn(d.Rootless), "Dangling images", strconv.Itoa(d.Dangling))
	m.h(3, "Containers")
	var rows [][]string
	for _, c := range d.Containers {
		var nets []string
		for n, ip := range c.Networks {
			nets = append(nets, n+"="+ip)
		}
		sort.Strings(nets)
		rows = append(rows, []string{c.Name, c.Image, c.State, c.Health, c.Restart, strconv.Itoa(c.RestartCnt), strings.Join(c.Ports, ", "),
			strings.Join(nets, ", "), c.Compose, flags(c)})
	}
	m.table([]string{"Name", "Image", "State", "Health", "Restart", "Restarts", "Ports", "Networks (IP)", "Compose", "Risk flags"}, rows)

	m.h(3, "Container details (inspect)")
	for _, c := range d.Containers {
		m.p("\n<details><summary><b>%s</b> — %s (%s)</summary>\n", c.Name, c.Image, c.State)
		m.kv("ID", c.ID, "Created", c.Created, "Cmd", "`"+c.Cmd+"`", "Compose dir", c.ComposeDir, "Cap add", strings.Join(c.CapAdd, ", "))
		if len(c.Mounts) > 0 {
			m.p("\n**Mounts**\n```\n%s\n```", strings.Join(c.Mounts, "\n"))
		}
		if len(c.Env) > 0 {
			m.p("\n**Environment** (%d vars)\n```\n%s\n```", c.EnvCount, strings.Join(c.Env, "\n"))
		}
		m.p("</details>")
	}
	if len(d.Stats) > 0 {
		m.h(3, "Container resource usage (docker stats)")
		rows = nil
		for _, s := range d.Stats {
			rows = append(rows, []string{s["Name"], s["CPUPerc"], s["MemUsage"], s["MemPerc"], s["NetIO"], s["BlockIO"], s["PIDs"]})
		}
		m.table([]string{"Container", "CPU", "Mem", "Mem%", "Net IO", "Block IO", "PIDs"}, rows)
	}
	m.h(3, "Networks")
	rows = nil
	for _, n := range d.Networks {
		rows = append(rows, []string{n["Name"], n["Driver"], n["Scope"], n["Subnets"], n["AttachedContainers"]})
	}
	m.table([]string{"Network", "Driver", "Scope", "Subnet / gateway", "Containers"}, rows)
	if g := topology.MermaidDocker(r); g != "" {
		m.h(3, "Docker network diagram")
		m.p("```mermaid\n%s```", g)
	}
	m.h(3, "Images")
	rows = nil
	for _, i := range d.Images {
		rows = append(rows, []string{i["Repository"], i["Tag"], i["ID"], i["Size"], i["CreatedSince"]})
	}
	m.table([]string{"Repository", "Tag", "ID", "Size", "Created"}, rows)
	m.h(3, "Volumes")
	rows = nil
	for _, v := range d.Volumes {
		rows = append(rows, []string{v["Name"], v["Driver"], v["Mountpoint"]})
	}
	m.table([]string{"Volume", "Driver", "Mountpoint"}, rows)
	if len(d.ComposeProjects) > 0 {
		m.h(3, "Compose projects")
		rows = nil
		for k, v := range d.ComposeProjects {
			rows = append(rows, []string{k, v})
		}
		m.table([]string{"Project", "Working dir"}, rows)
	}
}

func flags(c inventory.Container) string {
	var f []string
	if c.Privileged {
		f = append(f, "PRIVILEGED")
	}
	if c.SocketMount {
		f = append(f, "docker.sock")
	}
	if c.HostNet {
		f = append(f, "host-net")
	}
	if c.HostPID {
		f = append(f, "host-pid")
	}
	if len(c.CapAdd) > 0 {
		f = append(f, "cap+"+strings.Join(c.CapAdd, ","))
	}
	return strings.Join(f, " ")
}

func Dur(s int64) string {
	d := s / 86400
	h := (s % 86400) / 3600
	mi := (s % 3600) / 60
	if d > 0 {
		return fmt.Sprintf("%dd %dh %dm", d, h, mi)
	}
	return fmt.Sprintf("%dh %dm", h, mi)
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
func hbz(b uint64) string {
	if b == 0 {
		return ""
	}
	return hb(b)
}
func pid(p int) string {
	if p == 0 {
		return ""
	}
	return strconv.Itoa(p)
}
func ints(s []int) string {
	var o []string
	for _, x := range s {
		o = append(o, strconv.Itoa(x))
	}
	return strings.Join(o, ", ")
}
func mapStr(m map[string]int) string {
	var o []string
	for k, v := range m {
		o = append(o, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(o)
	return strings.Join(o, " ")
}
func orNone(s string) string {
	if s == "" {
		return "none detected"
	}
	return s
}
func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// Section renders one collector's section as Markdown (used by the TUI).
func Section(r *inventory.Report, name string) string {
	var b strings.Builder
	c := r.Collectors[name]
	if c == nil {
		return ""
	}
	section(md{&b, &mdState{report: r, shownCfg: map[string]bool{}}}, r, name, c)
	return b.String()
}

// Findings renders the findings table.
func Findings(r *inventory.Report) []inventory.Finding { return r.Findings }

var sectionTitles = map[string]string{}

func toc(m md, r *inventory.Report) {
	m.p("\n**Overview:** [Summary](#summary) · [Dashboard](#dashboard) · [Findings](#findings) · [Architecture](#architecture) · [DB access map](#access) · [Graph](#graph)")
	for _, g := range Groups {
		if !g.present(r) {
			continue
		}
		var links []string
		for _, n := range g.Members {
			if n == "exposure" && len(r.Exposure) > 0 {
				links = append(links, "[open ports](#exposure)")
			} else if r.Collectors[n] != nil {
				links = append(links, fmt.Sprintf("[%s](#sec-%s)", n, n))
			}
		}
		m.p("\n**[%s](#%s):** %s", g.Title, g.ID, strings.Join(links, " · "))
	}
	m.p("\n_Click an area to expand. Overview starts open._")
}
