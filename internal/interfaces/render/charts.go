package render

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/domain/topology"
)

// Chart is a renderer-neutral chart: HTML draws inline SVG, Markdown draws a text-bar table.
type Chart struct {
	ID    string
	Title string
	Kind  string // bars | meters | stack
	Unit  string
	Items []ChartItem
	Note  string
}

type ChartItem struct {
	Label   string
	Value   float64
	Display string
	Status  string // good | warning | serious | critical | low | info (meters & stack)
}

func meterStatus(pct float64) string {
	switch {
	case pct >= 95:
		return "critical"
	case pct >= 85:
		return "serious"
	case pct >= 75:
		return "warning"
	}
	return "good"
}

// Charts derives the dashboard from a report.
func Charts(r *inventory.Report) []Chart {
	var cs []Chart
	sev := map[inventory.Severity]int{}
	for _, f := range r.Findings {
		sev[f.Severity]++
	}
	st := Chart{ID: "sev", Title: "Findings by severity", Kind: "stack"}
	for _, s := range []struct {
		k      inventory.Severity
		status string
	}{{"critical", "critical"}, {"high", "serious"}, {"medium", "warning"}, {"low", "low"}, {"info", "info"}} {
		st.Items = append(st.Items, ChartItem{Label: strings.Title(string(s.k)), Value: float64(sev[s.k]), Display: strconv.Itoa(sev[s.k]), Status: s.status})
	}
	cs = append(cs, st)

	if h, ok := topology.Get[*inventory.Host](r, "host"); ok {
		m := Chart{ID: "util", Title: "Memory & disk utilisation", Kind: "meters", Unit: "%"}
		if h.MemTotal > 0 {
			p := 100 - float64(h.MemAvailable)/float64(h.MemTotal)*100
			m.Items = append(m.Items, ChartItem{Label: "Memory", Value: p, Display: fmt.Sprintf("%.0f%% · %s of %s", p, hb(h.MemTotal-h.MemAvailable), hb(h.MemTotal)), Status: meterStatus(p)})
		}
		if h.SwapTotal > 0 {
			p := float64(h.SwapTotal-h.SwapFree) / float64(h.SwapTotal) * 100
			m.Items = append(m.Items, ChartItem{Label: "Swap", Value: p, Display: fmt.Sprintf("%.0f%% · %s of %s", p, hb(h.SwapTotal-h.SwapFree), hb(h.SwapTotal)), Status: meterStatus(p)})
		}
		mounts := append([]inventory.Mount(nil), h.Mounts...)
		sort.Slice(mounts, func(i, j int) bool { return mounts[i].UsedPct > mounts[j].UsedPct })
		for _, mt := range limitM(mounts, 8) {
			if mt.TotalBytes < 1<<30 {
				continue
			}
			m.Items = append(m.Items, ChartItem{Label: "Disk " + mt.Mountpoint, Value: mt.UsedPct, Display: fmt.Sprintf("%.0f%% · %s of %s", mt.UsedPct, hb(mt.UsedBytes), hb(mt.TotalBytes)), Status: meterStatus(mt.UsedPct)})
		}
		cs = append(cs, m)
	}

	if res, ok := topology.Get[*inventory.Resources](r, "resources"); ok {
		mem := Chart{ID: "mem", Title: "Top applications by memory (RSS)", Kind: "bars"}
		apps := append([]inventory.Usage(nil), res.ByApp...)
		sort.Slice(apps, func(i, j int) bool { return apps[i].RSS > apps[j].RSS })
		for _, u := range limitU(apps, 10) {
			mem.Items = append(mem.Items, ChartItem{Label: u.Key, Value: float64(u.RSS), Display: fmt.Sprintf("%s · %d procs", hb(u.RSS), u.Count)})
		}
		cs = append(cs, mem)
		cpu := Chart{ID: "cpu", Title: "Top applications by CPU", Kind: "bars", Unit: "%"}
		sort.Slice(apps, func(i, j int) bool { return apps[i].CPU > apps[j].CPU })
		for _, u := range limitU(apps, 10) {
			if u.CPU > 0 {
				cpu.Items = append(cpu.Items, ChartItem{Label: u.Key, Value: u.CPU, Display: fmt.Sprintf("%.1f%%", u.CPU)})
			}
		}
		if len(cpu.Items) > 0 {
			cs = append(cs, cpu)
		}
		if len(res.BigDirs) > 0 {
			d := Chart{ID: "dirs", Title: "Largest directories", Kind: "bars"}
			for _, x := range limitD(res.BigDirs, 10) {
				d.Items = append(d.Items, ChartItem{Label: x.Path, Value: float64(x.Bytes), Display: hb(x.Bytes)})
			}
			cs = append(cs, d)
		}
	}

	if len(r.Exposure) > 0 {
		order := []string{"all interfaces", "public IP", "private network", "local only"}
		cnt := map[string]int{}
		for _, e := range r.Exposure {
			cnt[e.Scope]++
		}
		c := Chart{ID: "scope", Title: "Listening ports — reachable from", Kind: "bars"}
		for _, s := range order {
			if cnt[s] > 0 {
				c.Items = append(c.Items, ChartItem{Label: s, Value: float64(cnt[s]), Display: strconv.Itoa(cnt[s])})
			}
		}
		cs = append(cs, c)
		rk := Chart{ID: "risk", Title: "Port exposure risk", Kind: "stack"}
		rc := map[string]int{}
		for _, e := range r.Exposure {
			rc[e.Risk]++
		}
		for _, s := range []struct{ k, status string }{{"high", "critical"}, {"medium", "warning"}, {"low", "low"}, {"info", "info"}} {
			rk.Items = append(rk.Items, ChartItem{Label: strings.Title(s.k), Value: float64(rc[s.k]), Display: strconv.Itoa(rc[s.k]), Status: s.status})
		}
		cs = append(cs, rk)
	}

	var dbs []ChartItem
	if pg, ok := topology.Get[*inventory.Postgres](r, "postgres"); ok {
		for _, in := range pg.Instances {
			for _, d := range in.Databases {
				if !d.IsTemplate && d.SizeBytes > 0 {
					dbs = append(dbs, ChartItem{Label: "pg " + shortTarget(in.Target) + " / " + d.Name, Value: float64(d.SizeBytes), Display: hbi(d.SizeBytes)})
				}
			}
		}
	}
	if my, ok := topology.Get[*inventory.MySQL](r, "mysql"); ok {
		for _, in := range my.Instances {
			for _, d := range in.Databases {
				if !d.System {
					s := d.DataBytes + d.IndexBytes
					dbs = append(dbs, ChartItem{Label: "mysql " + shortTarget(in.Target) + " / " + d.Name, Value: float64(s), Display: hbi(s)})
				}
			}
		}
	}
	if len(dbs) > 0 {
		sort.Slice(dbs, func(i, j int) bool { return dbs[i].Value > dbs[j].Value })
		note := ""
		if len(dbs) > 15 {
			note = fmt.Sprintf("Top 15 of %d databases", len(dbs))
		}
		cs = append(cs, Chart{ID: "dbsize", Title: "Largest databases", Kind: "bars", Items: dbs[:min(15, len(dbs))], Note: note})
	}

	if d, ok := topology.Get[*inventory.Docker](r, "docker"); ok && len(d.Stats) > 0 {
		c := Chart{ID: "ctrmem", Title: "Containers by memory (docker stats)", Kind: "bars"}
		for _, s := range d.Stats {
			used := strings.TrimSpace(strings.SplitN(s["MemUsage"], "/", 2)[0])
			c.Items = append(c.Items, ChartItem{Label: s["Name"], Value: float64(parseSize(used)), Display: used + " · CPU " + s["CPUPerc"]})
		}
		sort.Slice(c.Items, func(i, j int) bool { return c.Items[i].Value > c.Items[j].Value })
		c.Items = c.Items[:min(12, len(c.Items))]
		cs = append(cs, c)
	}
	return cs
}

func shortTarget(t string) string {
	t = strings.TrimPrefix(t, "container ")
	return truncateR(t, 22)
}

func truncateR(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func parseSize(s string) uint64 {
	s = strings.TrimSpace(s)
	units := []struct {
		suf string
		m   float64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"kB", 1e3}, {"B", 1}}
	for _, u := range units {
		if strings.HasSuffix(s, u.suf) {
			f, _ := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(s, u.suf)), 64)
			return uint64(f * u.m)
		}
	}
	f, _ := strconv.ParseFloat(s, 64)
	return uint64(f)
}

func limitM(s []inventory.Mount, n int) []inventory.Mount {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func limitD(s []inventory.DirUsage, n int) []inventory.DirUsage {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---- Markdown: text-bar tables (render everywhere, incl. terminals) ----

func chartMD(m md, c Chart) {
	m.p("\n**%s**\n", c.Title)
	max := 0.0
	total := 0.0
	for _, it := range c.Items {
		max = math.Max(max, it.Value)
		total += it.Value
	}
	var rows [][]string
	for _, it := range c.Items {
		frac := 0.0
		switch c.Kind {
		case "meters":
			frac = it.Value / 100
		case "stack":
			if total > 0 {
				frac = it.Value / total
			}
		default:
			if max > 0 {
				frac = it.Value / max
			}
		}
		n := int(math.Round(math.Min(frac, 1) * 24))
		bar := strings.Repeat("█", n) + strings.Repeat("░", 24-n)
		label := it.Label
		if it.Status != "" && c.Kind == "meters" && it.Status != "good" {
			label += " ⚠"
		}
		rows = append(rows, []string{label, "`" + bar + "`", it.Display})
	}
	m.table([]string{"", "", "Value"}, rows)
	if c.Note != "" {
		m.p("_%s_", c.Note)
	}
}

// ---- HTML: inline SVG ----

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func chartSVG(c Chart) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<figure class="chart" id="chart-%s"><figcaption>%s</figcaption>`, c.ID, esc(c.Title))
	switch c.Kind {
	case "stack":
		total := 0.0
		for _, it := range c.Items {
			total += it.Value
		}
		const W, H = 640.0, 22.0
		fmt.Fprintf(&b, `<svg viewBox="0 0 %v %v" role="img" aria-label="%s" preserveAspectRatio="none" class="stack">`, W, H, esc(c.Title))
		if total == 0 {
			fmt.Fprintf(&b, `<rect x="0" y="0" width="%v" height="%v" rx="4" class="track"/>`, W, H)
		}
		x := 0.0
		for i, it := range c.Items {
			if it.Value == 0 {
				continue
			}
			w := it.Value / total * W
			gap := 2.0
			if i == len(c.Items)-1 || x+w >= W-0.5 {
				gap = 0
			}
			fmt.Fprintf(&b, `<rect x="%.1f" y="0" width="%.1f" height="%v" rx="4" class="mark st-%s"><title>%s: %s</title></rect>`,
				x, math.Max(w-gap, 1), H, it.Status, esc(it.Label), esc(it.Display))
			x += w
		}
		b.WriteString(`</svg><div class="legend">`)
		for _, it := range c.Items {
			fmt.Fprintf(&b, `<span><i class="sw st-%s"></i>%s <b>%s</b></span>`, it.Status, esc(it.Label), esc(it.Display))
		}
		b.WriteString(`</div>`)
	case "meters":
		for _, it := range c.Items {
			pct := math.Max(0, math.Min(100, it.Value))
			icon := map[string]string{"good": "✓", "warning": "!", "serious": "!!", "critical": "✕"}[it.Status]
			fmt.Fprintf(&b, `<div class="meter" title="%s: %s"><div class="ml"><span>%s</span><span class="mv"><em class="ic st-%s">%s</em>%s</span></div>`+
				`<div class="mt"><div class="mf st-%s" style="width:%.1f%%"></div></div></div>`,
				esc(it.Label), esc(it.Display), esc(it.Label), it.Status, icon, esc(it.Display), it.Status, pct)
		}
	default: // horizontal bars, single series
		max := 0.0
		for _, it := range c.Items {
			max = math.Max(max, it.Value)
		}
		const rowH, labelW, barW, W = 26.0, 190.0, 300.0, 600.0
		H := rowH*float64(len(c.Items)) + 4
		fmt.Fprintf(&b, `<svg viewBox="0 0 %v %v" role="img" aria-label="%s" class="bars">`, W, H, esc(c.Title))
		for i, it := range c.Items {
			y := float64(i)*rowH + 4
			w := 0.0
			if max > 0 {
				w = math.Max(it.Value/max*barW, 2)
			}
			fmt.Fprintf(&b, `<g class="row"><rect x="0" y="%.1f" width="%v" height="%v" class="hit"/>`, y-3, W, rowH)
			fmt.Fprintf(&b, `<text x="%v" y="%.1f" class="lbl" text-anchor="end">%s</text>`, labelW-10, y+14, esc(truncateR(it.Label, 30)))
			// data end rounded, baseline end square
			r := math.Min(4, w/2)
			fmt.Fprintf(&b, `<path class="mark s1" d="M%v %.1f h%.1f a%.1f %.1f 0 0 1 %.1f %.1f v%.1f a%.1f %.1f 0 0 1 %.1f %.1f h%.1f z"/>`,
				labelW, y, w-r, r, r, r, r, 18-2*r, r, r, -r, r, -(w - r))
			fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" class="val">%s</text>`, labelW+w+8, y+14, esc(it.Display))
			fmt.Fprintf(&b, `<title>%s — %s</title></g>`, esc(it.Label), esc(it.Display))
		}
		b.WriteString(`</svg>`)
	}
	if c.Note != "" {
		fmt.Fprintf(&b, `<div class="cnote">%s</div>`, esc(c.Note))
	}
	b.WriteString(`</figure>`)
	return b.String()
}
