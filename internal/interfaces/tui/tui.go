// Package tui is the interactive terminal UI (Bubble Tea).
package tui

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bakhod1r/serveradar/internal/application/scan"
	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/domain/policy"
	"github.com/bakhod1r/serveradar/internal/domain/topology"
	"github.com/bakhod1r/serveradar/internal/interfaces/render"
)

var (
	accent    = lipgloss.Color("39")
	dim       = lipgloss.Color("244")
	sevColor  = map[inventory.Severity]lipgloss.Color{"critical": "196", "high": "208", "medium": "220", "low": "75", "info": "244"}
	statColor = map[inventory.Status]lipgloss.Color{"ok": "42", "partial": "220", "unavailable": "244", "error": "196", "skipped": "244"}

	titleSt = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(accent).Padding(0, 1)
	sideSt  = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(dim).Padding(0, 1)
	mainSt  = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(accent).Padding(0, 1)
	selSt   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("24"))
	dimSt   = lipgloss.NewStyle().Foreground(dim)
	headSt  = lipgloss.NewStyle().Bold(true).Foreground(accent)
	tblHead = lipgloss.NewStyle().Bold(true).Underline(true)
)

type progressMsg struct {
	name string
	r    *inventory.CollectorResult
}
type doneMsg struct{ r *inventory.Report }
type flashMsg string

type item struct{ key, label string }

type Model struct {
	svc       scan.Service
	pol       *policy.Policy
	rep       *inventory.Report
	scanning  bool
	done      map[string]*inventory.CollectorResult
	total     int
	items     []item
	sel       int
	vp        viewport.Model
	spin      spinner.Model
	search    textinput.Model
	searching bool
	filter    string
	w, h      int
	flash     string
	ch        chan tea.Msg
	initCmd   tea.Cmd
}

func New(svc scan.Service, pol *policy.Policy) Model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	ti := textinput.New()
	ti.Placeholder = "filter lines…"
	ti.Prompt = "/ "
	m := Model{svc: svc, pol: pol, spin: sp, search: ti, vp: viewport.New(80, 20), done: map[string]*inventory.CollectorResult{}}
	m.initCmd = m.startScan() // must mutate the model Bubble Tea will own, not a copy inside Init
	return m
}

func Run(svc scan.Service, pol *policy.Policy) error {
	_, err := tea.NewProgram(New(svc, pol), tea.WithAltScreen(), tea.WithMouseCellMotion()).Run()
	return err
}

func (m Model) Init() tea.Cmd { return tea.Batch(m.spin.Tick, m.initCmd) }

func (m *Model) startScan() tea.Cmd {
	m.scanning, m.done, m.rep = true, map[string]*inventory.CollectorResult{}, nil
	m.total = len(m.svc.Select(m.pol))
	m.ch = make(chan tea.Msg, 64)
	ch := m.ch
	go func() {
		r := m.svc.Run(context.Background(), m.pol, func(n string, res *inventory.CollectorResult) { ch <- progressMsg{n, res} })
		ch <- doneMsg{r}
	}()
	return wait(ch)
}

func wait(ch chan tea.Msg) tea.Cmd { return func() tea.Msg { return <-ch } }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.layout()
	case spinner.TickMsg:
		var c tea.Cmd
		m.spin, c = m.spin.Update(msg)
		if m.scanning {
			cmds = append(cmds, c)
			m.refresh()
		}
	case progressMsg:
		if m.done == nil {
			m.done = map[string]*inventory.CollectorResult{}
		}
		m.done[msg.name] = msg.r
		m.refresh()
		return m, wait(m.ch)
	case doneMsg:
		m.scanning, m.rep = false, msg.r
		m.buildItems()
		m.refresh()
	case flashMsg:
		m.flash = string(msg)
	case tea.MouseMsg:
		var c tea.Cmd
		m.vp, c = m.vp.Update(msg)
		return m, c
	case tea.KeyMsg:
		if m.searching {
			switch msg.String() {
			case "enter", "esc":
				m.searching = false
				if msg.String() == "esc" {
					m.search.SetValue("")
				}
				m.filter = m.search.Value()
				m.search.Blur()
				m.refresh()
				return m, nil
			}
			var c tea.Cmd
			m.search, c = m.search.Update(msg)
			m.filter = m.search.Value()
			m.refresh()
			return m, c
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k", "shift+tab":
			if m.sel > 0 {
				m.sel--
				m.vp.GotoTop()
				m.refresh()
			}
		case "down", "j", "tab":
			if m.sel < len(m.items)-1 {
				m.sel++
				m.vp.GotoTop()
				m.refresh()
			}
		case "/":
			m.searching = true
			m.search.Focus()
			return m, textinput.Blink
		case "r":
			if !m.scanning {
				m.items = nil
				cmd := m.startScan()
				return m, tea.Batch(cmd, m.spin.Tick)
			}
		case "m":
			return m, m.export("md")
		case "J":
			return m, m.export("json")
		case "H":
			return m, m.export("html")
		case "d": // opt-in: authenticated read-only DB inspection (local + docker)
			m.pol.PGLocal, m.pol.PGDocker, m.pol.MySQLLocal, m.pol.MySQLDocker, m.pol.RedisLocal = true, true, true, true, true
			if !m.scanning {
				m.items = nil
				m.flash = "DB inspection on — rescanning"
				cmd := m.startScan()
				return m, tea.Batch(cmd, m.spin.Tick)
			}
		case "p":
			m.cycleProfile()
			if !m.scanning {
				m.items = nil
				cmd := m.startScan()
				return m, tea.Batch(cmd, m.spin.Tick)
			}
		default:
			var c tea.Cmd
			m.vp, c = m.vp.Update(msg)
			return m, c
		}
	}
	return m, tea.Batch(cmds...)
}

func (m *Model) cycleProfile() {
	for i, p := range policy.Profiles {
		if p == m.pol.Profile {
			m.pol.Profile = policy.Profiles[(i+1)%len(policy.Profiles)]
			return
		}
	}
}

func (m Model) export(kind string) tea.Cmd {
	rep := m.rep
	return func() tea.Msg {
		if rep == nil {
			return flashMsg("scan not finished")
		}
		name := fmt.Sprintf("serveradar-%s-%s.%s", rep.Hostname, time.Now().Format("20060102-150405"), kind)
		f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return flashMsg("export failed: " + err.Error())
		}
		defer f.Close()
		if kind == "md" {
			render.Markdown(f, rep)
		} else if kind == "html" {
			if err := render.HTML(f, rep); err != nil {
				return flashMsg("export failed: " + err.Error())
			}
		} else if err := render.JSON(f, rep); err != nil {
			return flashMsg("export failed: " + err.Error())
		}
		return flashMsg("saved " + name + " (0600)")
	}
}

func (m *Model) buildItems() {
	m.items = []item{{"summary", "Summary"}, {"findings", fmt.Sprintf("Findings (%d)", len(m.rep.Findings))}, {"exposure", fmt.Sprintf("Open ports (%d)", len(m.rep.Exposure))}}
	titles := map[string]string{"host": "Host & OS", "resources": "Resources", "processes": "Processes", "network": "Network",
		"ports": "Ports & IPs", "systemd": "systemd", "cron": "Cron jobs", "docker": "Docker", "kubernetes": "Clusters",
		"nginx": "Nginx", "tls": "TLS certs", "projects": "Projects", "databases": "Databases", "tools": "DevOps tools", "services": "Kafka/Rabbit/Vault…", "dbaccess": "DB open/closed", "dbconfig": "DB configs", "postgres": "PostgreSQL", "mysql": "MySQL", "redis": "Redis", "firewall": "Firewall", "security": "Security"}
	for _, n := range m.rep.Order {
		m.items = append(m.items, item{n, titles[n]})
	}
	if topology.MermaidDocker(m.rep) != "" {
		m.items = append(m.items, item{"diagram", "Docker diagram"})
	}
	m.items = append(m.items, item{"graph", "Relationships"})
	if m.sel >= len(m.items) {
		m.sel = 0
	}
}

func (m *Model) layout() {
	sideW := 24
	m.vp.Width = max(20, m.w-sideW-6)
	m.vp.Height = max(5, m.h-5)
	m.refresh()
}

func (m *Model) refresh() {
	var content string
	if m.scanning || m.rep == nil {
		content = m.progressView()
	} else {
		content = m.sectionView(m.items[m.sel].key)
	}
	if m.filter != "" {
		var keep []string
		for _, ln := range strings.Split(content, "\n") {
			if strings.Contains(strings.ToLower(ln), strings.ToLower(m.filter)) {
				keep = append(keep, ln)
			}
		}
		content = strings.Join(keep, "\n")
	}
	m.vp.SetContent(content)
}

func (m Model) progressView() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s Scanning (profile %s) … %d/%d collectors\n\n", m.spin.View(), m.pol.Profile, len(m.done), m.total)
	for _, c := range m.svc.Select(m.pol) {
		r, ok := m.done[c.Name]
		if !ok {
			fmt.Fprintf(&b, "  %s %s\n", dimSt.Render("…"), c.Title)
			continue
		}
		st := lipgloss.NewStyle().Foreground(statColor[r.Status]).Render(fmt.Sprintf("%-11s", r.Status))
		fmt.Fprintf(&b, "  %s %-26s %s %s\n", st, c.Title, dimSt.Render(fmt.Sprintf("%5dms", r.DurationMs)), dimSt.Render(r.Error))
	}
	return b.String()
}

func (m Model) sectionView(key string) string {
	r := m.rep
	switch key {
	case "summary":
		var b strings.Builder
		render.Markdown(&cutWriter{b: &b, stopAt: "<a id=\"findings\">"}, r)
		return pretty(b.String(), m.vp.Width)
	case "findings":
		var b strings.Builder
		for _, f := range r.Findings {
			sev := lipgloss.NewStyle().Bold(true).Foreground(sevColor[f.Severity]).Render(fmt.Sprintf("%-8s", strings.ToUpper(string(f.Severity))))
			fmt.Fprintf(&b, "%s %s  %s\n", sev, lipgloss.NewStyle().Bold(true).Render(f.Title), dimSt.Render(f.ID))
			fmt.Fprintf(&b, "         component: %s · confidence: %s\n", f.Component, f.Confidence)
			fmt.Fprintf(&b, "         evidence:  %s\n", f.Evidence)
			fmt.Fprintf(&b, "         impact:    %s\n", f.Impact)
			fmt.Fprintf(&b, "         next:      %s\n\n", f.NextStep)
		}
		if len(r.Findings) == 0 {
			b.WriteString("No findings.")
		}
		return b.String()
	case "exposure":
		return pretty(render.ExposureMD(r), m.vp.Width)
	case "diagram":
		return "Mermaid source (paste into mermaid.live or view the exported .md):\n\n" + topology.MermaidDocker(r) + "\n" + asciiDocker(r)
	case "graph":
		var b strings.Builder
		for _, x := range r.Relationships {
			arrow := "──▶"
			if x.Confidence != inventory.Confirmed {
				arrow = "┄┄▶"
			}
			fmt.Fprintf(&b, "%s %s %s  %s\n", x.Source, arrow, x.Target, dimSt.Render(x.Kind+" · "+string(x.Confidence)))
		}
		return b.String()
	}
	return pretty(render.Section(r, key), m.vp.Width)
}

// asciiDocker: network-centric tree for the terminal.
func asciiDocker(r *inventory.Report) string {
	d, ok := topology.Get[*inventory.Docker](r, "docker")
	if !ok {
		return ""
	}
	var b strings.Builder
	b.WriteString(headSt.Render("Networks → containers") + "\n")
	byNet := map[string][]inventory.Container{}
	for _, c := range d.Containers {
		for n := range c.Networks {
			byNet[n] = append(byNet[n], c)
		}
	}
	for _, n := range d.Networks {
		cs := byNet[n["Name"]]
		fmt.Fprintf(&b, "◆ %s (%s) %s\n", n["Name"], n["Driver"], dimSt.Render(n["Subnets"]))
		for i, c := range cs {
			br := "├─"
			if i == len(cs)-1 {
				br = "└─"
			}
			fmt.Fprintf(&b, "  %s %s  %s  %s  %s\n", br, c.Name, dimSt.Render(c.Networks[n["Name"]]), c.State, strings.Join(c.Ports, " "))
		}
	}
	return b.String()
}

func (m Model) View() string {
	if m.w == 0 {
		return "loading…"
	}
	head := titleSt.Render("Serveradar") + " " + dimSt.Render(fmt.Sprintf("profile:%s", m.pol.Profile))
	if m.rep != nil {
		head += dimSt.Render(fmt.Sprintf("  host:%s  user:%s  %s", m.rep.Hostname, m.rep.Privileges.User, m.rep.FinishedAt.Local().Format("15:04:05")))
	}
	var side strings.Builder
	for i, it := range m.items {
		label := it.label
		if r := m.rep; r != nil {
			if c, ok := r.Collectors[it.key]; ok && c.Status != inventory.StatusOK {
				label += " " + lipgloss.NewStyle().Foreground(statColor[c.Status]).Render("●")
			}
		}
		if i == m.sel {
			side.WriteString(selSt.Render(fmt.Sprintf("%-20s", it.label)) + "\n")
		} else {
			side.WriteString(" " + label + "\n")
		}
	}
	if len(m.items) == 0 {
		side.WriteString(m.spin.View() + " scanning")
	}
	left := sideSt.Width(22).Height(m.h - 4).Render(side.String())
	right := mainSt.Width(m.vp.Width + 2).Height(m.h - 4).Render(m.vp.View())
	foot := dimSt.Render("d DB inspect · ↑↓ section · pgup/pgdn scroll · / filter · r rescan · p profile · m .md · J .json · H .html · q quit")
	if m.searching {
		foot = m.search.View()
	} else if m.filter != "" {
		foot = dimSt.Render("filter: "+m.filter+" (/ to change, esc clears) · ") + foot
	}
	if m.flash != "" {
		foot = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render(m.flash) + "  " + foot
	}
	return lipgloss.JoinVertical(lipgloss.Left, head, lipgloss.JoinHorizontal(lipgloss.Top, left, right), foot)
}

// pretty converts the Markdown subset we emit into aligned terminal text.
func pretty(mdText string, width int) string {
	var out []string
	var tbl [][]string
	flush := func() {
		if len(tbl) == 0 {
			return
		}
		out = append(out, table(tbl, width)...)
		tbl = nil
	}
	inCode := false
	for _, ln := range strings.Split(mdText, "\n") {
		if strings.HasPrefix(ln, "```") {
			flush()
			inCode = !inCode
			continue
		}
		if inCode {
			out = append(out, dimSt.Render("  "+ln))
			continue
		}
		if strings.HasPrefix(ln, "|") {
			if strings.HasPrefix(ln, "|---") {
				continue
			}
			cells := strings.Split(strings.Trim(ln, "| "), " | ")
			for i := range cells {
				cells[i] = strings.NewReplacer("**", "", "`", "", `\|`, "|").Replace(strings.TrimSpace(cells[i]))
			}
			tbl = append(tbl, cells)
			continue
		}
		flush()
		switch {
		case strings.HasPrefix(ln, "#"):
			out = append(out, "", headSt.Render(strings.TrimLeft(ln, "# ")))
		case strings.HasPrefix(ln, "<details"), strings.HasPrefix(ln, "</details>"), strings.HasPrefix(ln, "<summary>"), strings.HasPrefix(ln, "<a id="):
			s := tagRe.ReplaceAllString(ln, "")
			if strings.TrimSpace(s) != "" {
				out = append(out, lipgloss.NewStyle().Bold(true).Render("▸ "+s))
			}
		default:
			out = append(out, strings.NewReplacer("**", "", "`", "", "_none_", dimSt.Render("(none)")).Replace(ln))
		}
	}
	flush()
	return strings.Join(out, "\n")
}

func table(rows [][]string, width int) []string {
	cols := 0
	for _, r := range rows {
		cols = max(cols, len(r))
	}
	w := make([]int, cols)
	for _, r := range rows {
		for i, c := range r {
			w[i] = max(w[i], utf8.RuneCountInString(c))
		}
	}
	maxCell := max(8, (width-cols*2)/max(1, cols)+10)
	for i := range w {
		w[i] = min(w[i], max(maxCell, 12), 60)
	}
	var out []string
	for ri, r := range rows {
		var b strings.Builder
		for i := 0; i < cols; i++ {
			c := ""
			if i < len(r) {
				c = r[i]
			}
			if utf8.RuneCountInString(c) > w[i] {
				c = string([]rune(c)[:w[i]-1]) + "…"
			}
			b.WriteString(c + strings.Repeat(" ", w[i]-utf8.RuneCountInString(c)) + "  ")
		}
		s := b.String()
		if ri == 0 {
			s = tblHead.Render(s)
		}
		out = append(out, s)
	}
	return out
}

var tagRe = regexp.MustCompile(`<[^>]+>`)

// cutWriter stops writing after a marker (used to show just the summary).
type cutWriter struct {
	b      *strings.Builder
	stopAt string
	done   bool
}

func (c *cutWriter) Write(p []byte) (int, error) {
	if c.done {
		return len(p), nil
	}
	if i := strings.Index(string(p), c.stopAt); i >= 0 {
		c.b.Write(p[:i])
		c.done = true
		return len(p), nil
	}
	c.b.Write(p)
	return len(p), nil
}
