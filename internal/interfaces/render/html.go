package render

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"regexp"
	"strings"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/domain/topology"
)

// HTML writes a single self-contained report page (inline CSS/JS; Mermaid loaded from CDN when online).
func HTML(w io.Writer, r *inventory.Report) error {
	var b strings.Builder
	markdown(&b, r, true)
	body := mdToHTML(b.String())

	sev := map[inventory.Severity]int{}
	for _, f := range r.Findings {
		sev[f.Severity]++
	}
	type navItem struct{ ID, Label, Status string }
	type navGroup struct {
		ID, Title string
		Items     []navItem
	}
	nav := []navGroup{{"g-overview", "Overview", []navItem{{"summary", "Summary", ""}, {"dashboard", "Dashboard", ""},
		{"findings", fmt.Sprintf("Findings · %d", len(r.Findings)), ""}}}}
	if ArchitectureMermaid(r) != "" {
		nav[0].Items = append(nav[0].Items, navItem{"architecture", "Architecture", ""})
	}
	if AccessMermaid(r) != "" {
		nav[0].Items = append(nav[0].Items, navItem{"access", "DB access map", ""})
	}
	if len(r.Relationships) > 0 {
		nav[0].Items = append(nav[0].Items, navItem{"graph", "Relationships", ""})
	}
	for _, g := range Groups {
		if !g.present(r) {
			continue
		}
		ng := navGroup{ID: g.ID, Title: g.Title}
		for _, n := range g.Members {
			if n == "exposure" {
				if len(r.Exposure) > 0 {
					ng.Items = append(ng.Items, navItem{"exposure", fmt.Sprintf("Open ports · %d", len(r.Exposure)), ""})
				}
				continue
			}
			if c := r.Collectors[n]; c != nil {
				ng.Items = append(ng.Items, navItem{"sec-" + n, n, string(c.Status)})
			}
		}
		nav = append(nav, ng)
	}
	nav = append(nav, navGroup{"g-meta", "Scan", []navItem{{"scope", "Scope & limits", ""}}})

	host := map[string]string{"host": r.Hostname, "user": r.Privileges.User, "profile": r.Profile,
		"time": r.FinishedAt.Format("2006-01-02 15:04 MST"), "duration": r.FinishedAt.Sub(r.StartedAt).Round(1e6).String()}
	if h, ok := topology.Get[*inventory.Host](r, "host"); ok {
		host["os"] = h.Distro
		host["cpu"] = fmt.Sprintf("%d CPU · load %.2f", h.CPUs, h.Load[0])
		host["mem"] = fmt.Sprintf("%s / %s free", hb(h.MemAvailable), hb(h.MemTotal))
		host["uptime"] = Dur(h.UptimeSec)
	}
	type kpi struct{ Label, Value, Tone string }
	kpis := []kpi{
		{"Critical", fmt.Sprint(sev[inventory.Critical]), "crit"}, {"High", fmt.Sprint(sev[inventory.High]), "high"},
		{"Medium", fmt.Sprint(sev[inventory.Medium]), "med"}, {"Low", fmt.Sprint(sev[inventory.Low] + sev[inventory.Info]), "low"},
	}
	hi := 0
	for _, e := range r.Exposure {
		if e.Risk == "high" {
			hi++
		}
	}
	kpis = append(kpis, kpi{"Open ports", fmt.Sprintf("%d · %d risky", len(r.Exposure), hi), "neutral"})
	if d, ok := topology.Get[*inventory.Docker](r, "docker"); ok {
		run := 0
		for _, c := range d.Containers {
			if c.State == "running" {
				run++
			}
		}
		kpis = append(kpis, kpi{"Containers", fmt.Sprintf("%d / %d running", run, len(d.Containers)), "neutral"})
	}
	if d, ok := topology.Get[*inventory.Databases](r, "databases"); ok {
		kpis = append(kpis, kpi{"Data services", fmt.Sprint(len(d.Services)), "neutral"})
	}

	jsonData, _ := json.Marshal(struct {
		Findings []inventory.Finding `json:"findings"`
	}{r.Findings})

	return pageTmpl.Execute(w, map[string]any{
		"Title": "Serveradar · " + r.Hostname, "Host": host, "KPIs": kpis, "Nav": nav,
		"Body": template.HTML(body), "Findings": template.JS(jsonData),
	})
}

var (
	reBold   = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	reCode   = regexp.MustCompile("`([^`]+)`")
	reItal   = regexp.MustCompile(`(^|\s)_([^_]+)_(\s|$)`)
	reLink   = regexp.MustCompile(`\[([^\]]+)\]\((#[^)]+)\)`)
	sevWords = regexp.MustCompile(`\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b`)
)

func inline(s string) string {
	s = template.HTMLEscapeString(s)
	s = strings.ReplaceAll(s, `\|`, "|")
	s = reCode.ReplaceAllString(s, "<code>$1</code>")
	s = reBold.ReplaceAllString(s, "<strong>$1</strong>")
	s = reItal.ReplaceAllString(s, "$1<em>$2</em>$3")
	s = reLink.ReplaceAllString(s, `<a href="$2">$1</a>`)
	s = sevWords.ReplaceAllStringFunc(s, func(w string) string {
		return `<span class="sev sev-` + strings.ToLower(w) + `">` + w + `</span>`
	})
	return s
}

// mdToHTML converts the Markdown subset the report emits. Raw HTML lines (<details>, <summary>, <a id>) pass through.
func mdToHTML(src string) string {
	var out strings.Builder
	lines := strings.Split(src, "\n")
	inCode, codeLang := false, ""
	var code []string
	var table [][]string
	var list []string
	flushTable := func() {
		if len(table) == 0 {
			return
		}
		out.WriteString(`<div class="tbl"><table><thead><tr>`)
		for _, h := range table[0] {
			out.WriteString("<th>" + inline(h) + "</th>")
		}
		out.WriteString("</tr></thead><tbody>")
		for _, row := range table[1:] {
			out.WriteString("<tr>")
			for _, c := range row {
				out.WriteString("<td>" + inline(c) + "</td>")
			}
			out.WriteString("</tr>")
		}
		out.WriteString("</tbody></table></div>\n")
		table = nil
	}
	flushList := func() {
		if len(list) == 0 {
			return
		}
		out.WriteString("<ul>")
		for _, li := range list {
			out.WriteString("<li>" + inline(li) + "</li>")
		}
		out.WriteString("</ul>\n")
		list = nil
	}
	for _, ln := range lines {
		if strings.HasPrefix(ln, "```") {
			if inCode {
				body := template.HTMLEscapeString(strings.Join(code, "\n"))
				if codeLang == "mermaid" {
					out.WriteString(`<div class="mermaid-wrap"><pre class="mermaid">` + body + "</pre></div>\n")
				} else {
					out.WriteString("<pre><code>" + body + "</code></pre>\n")
				}
				inCode, code = false, nil
			} else {
				flushTable()
				flushList()
				inCode, codeLang = true, strings.TrimPrefix(ln, "```")
			}
			continue
		}
		if inCode {
			code = append(code, ln)
			continue
		}
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "|"):
			flushList()
			if strings.HasPrefix(t, "|---") {
				continue
			}
			cells := strings.Split(strings.Trim(t, "|"), " | ")
			for i := range cells {
				cells[i] = strings.TrimSpace(cells[i])
			}
			table = append(table, cells)
			continue
		case strings.HasPrefix(t, "- "):
			flushTable()
			list = append(list, t[2:])
			continue
		}
		flushTable()
		flushList()
		switch {
		case t == "":
		case strings.HasPrefix(t, "<"):
			out.WriteString(t + "\n")
		case strings.HasPrefix(t, "# "), strings.HasPrefix(t, "Generated "), strings.HasPrefix(t, "**Sections:**"), strings.HasPrefix(t, "_Click a"), strings.HasPrefix(t, "**Overview:**"), strings.HasPrefix(t, "**[") && strings.Contains(t, "](#g-"):
			// page title rendered by template
		case strings.HasPrefix(t, "#### "):
			out.WriteString("<h4>" + inline(t[5:]) + "</h4>\n")
		case strings.HasPrefix(t, "### "):
			out.WriteString("<h3>" + inline(t[4:]) + "</h3>\n")
		case strings.HasPrefix(t, "## "):
			out.WriteString("<h2>" + inline(t[3:]) + "</h2>\n")
		case strings.HasPrefix(t, "> "):
			out.WriteString(`<div class="note">` + inline(t[2:]) + "</div>\n")
		default:
			out.WriteString("<p>" + inline(t) + "</p>\n")
		}
	}
	flushTable()
	flushList()
	return out.String()
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{--bg:#f6f7fb;--panel:#fff;--panel2:#f1f3f9;--text:#151a2d;--muted:#5d6785;--line:#e3e7f0;--accent:#4f6bff;--accent2:#8b5cf6;
--crit:#e5484d;--high:#f76b15;--med:#e5a000;--low:#3e8ef7;--info:#8a94ad;--ok:#30a46c;--shadow:0 1px 2px rgba(16,24,40,.06),0 8px 24px rgba(16,24,40,.06)}
[data-theme=dark]{--bg:#0b0e17;--panel:#121725;--panel2:#171d2e;--text:#e6e9f2;--muted:#8d97b5;--line:#232a3f;--shadow:0 1px 2px rgba(0,0,0,.4),0 10px 30px rgba(0,0,0,.35)}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
code{font:12.5px/1.4 "JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--panel2);padding:1px 6px;border-radius:6px;word-break:break-all}
pre{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:14px;overflow:auto;max-height:520px}pre code{background:none;padding:0}
.layout{display:grid;grid-template-columns:260px 1fr;min-height:100vh}
aside{position:sticky;top:0;height:100vh;overflow:auto;background:var(--panel);border-right:1px solid var(--line);padding:20px 14px}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;margin:0 6px 18px}
.logo{width:30px;height:30px;border-radius:9px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:grid;place-items:center;color:#fff;font-size:15px}
aside nav a{display:flex;justify-content:space-between;align-items:center;padding:7px 10px;border-radius:9px;color:var(--muted);font-size:13px}
aside nav a:hover,aside nav a.active{background:var(--panel2);color:var(--text);text-decoration:none}
.dot{width:7px;height:7px;border-radius:50%;background:var(--ok)}.dot.partial{background:var(--med)}.dot.error{background:var(--crit)}.dot.unavailable,.dot.skipped{background:var(--info)}
main{padding:28px 36px 80px;min-width:0}
header.top{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-end;justify-content:space-between;margin-bottom:22px}
h1{margin:0;font-size:26px;letter-spacing:-.02em}.sub{color:var(--muted);font-size:13px;margin-top:4px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.chip{background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:4px 11px;font-size:12px;color:var(--muted)}
.tools{display:flex;gap:8px;align-items:center}
.search{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:9px 12px;color:var(--text);width:280px;outline:none}
.search:focus{border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 20%,transparent)}
.btn{background:var(--panel);border:1px solid var(--line);color:var(--text);border-radius:10px;padding:8px 12px;cursor:pointer;font-size:13px}.btn:hover{border-color:var(--accent)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:6px 0 22px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 16px;box-shadow:var(--shadow);position:relative;overflow:hidden}
.kpi:before{content:"";position:absolute;inset:0 auto 0 0;width:4px;background:var(--info)}
.kpi.crit:before{background:var(--crit)}.kpi.high:before{background:var(--high)}.kpi.med:before{background:var(--med)}.kpi.low:before{background:var(--low)}.kpi.neutral:before{background:linear-gradient(var(--accent),var(--accent2))}
.kpi .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}.kpi .v{font-size:22px;font-weight:700;margin-top:4px}
details{background:var(--panel);border:1px solid var(--line);border-radius:14px;margin:12px 0;box-shadow:var(--shadow)}
details details{box-shadow:none;background:var(--panel2);margin:10px 0}
summary{cursor:pointer;list-style:none;padding:12px 16px;display:flex;align-items:center;gap:10px;user-select:none}
summary::-webkit-details-marker{display:none}
summary:before{content:"›";font-size:18px;color:var(--muted);transition:transform .15s;display:inline-block;width:12px}
details[open]>summary:before{transform:rotate(90deg)}
summary h2{margin:0;font-size:17px;letter-spacing:-.01em}
details>*:not(summary){margin-left:18px;margin-right:18px}details>:last-child{margin-bottom:16px}
h3{font-size:15px;margin:18px 0 8px}h4{font-size:13.5px;margin:16px 0 6px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.tbl{overflow:auto;border:1px solid var(--line);border-radius:10px;margin:8px 0 12px;max-height:620px}
table{border-collapse:collapse;width:100%;font-size:12.8px}
th{position:sticky;top:0;background:var(--panel2);text-align:left;font-weight:600;color:var(--muted);padding:8px 10px;border-bottom:1px solid var(--line);cursor:pointer;white-space:nowrap}
th:hover{color:var(--text)}th.asc:after{content:" ▲"}th.desc:after{content:" ▼"}
td:first-child{white-space:nowrap}td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top;max-width:520px;overflow-wrap:anywhere}
tr:hover td{background:color-mix(in srgb,var(--accent) 5%,transparent)}
.sev{font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px;letter-spacing:.03em;white-space:nowrap}
.sev-critical{background:color-mix(in srgb,var(--crit) 18%,transparent);color:var(--crit)}.sev-high{background:color-mix(in srgb,var(--high) 18%,transparent);color:var(--high)}
.sev-medium{background:color-mix(in srgb,var(--med) 20%,transparent);color:var(--med)}.sev-low{background:color-mix(in srgb,var(--low) 18%,transparent);color:var(--low)}.sev-info{background:color-mix(in srgb,var(--info) 18%,transparent);color:var(--info)}
.note{border-left:3px solid var(--med);background:color-mix(in srgb,var(--med) 8%,transparent);padding:8px 12px;border-radius:8px;margin:8px 0;color:var(--muted)}
ul{margin:6px 0 10px;padding-left:20px}li{margin:3px 0}
.mermaid-wrap{overflow:auto;background:var(--panel2);border-radius:12px;padding:12px}
.hidden{display:none!important}
.navq{width:100%;margin:0 0 14px;padding:7px 10px;font-size:12.5px}
.kpi{cursor:pointer;transition:transform .12s,border-color .12s}.kpi:hover{transform:translateY(-2px);border-color:var(--accent)}
.hits{font-size:12px;color:var(--muted);min-height:16px;margin:2px 0 4px}
.fab{position:fixed;right:22px;bottom:22px;border-radius:999px;width:42px;height:42px;font-size:16px;box-shadow:var(--shadow);opacity:0;pointer-events:none;transition:opacity .2s}.fab.show{opacity:1;pointer-events:auto}
table.kv{max-width:860px}table.kv td:first-child{color:var(--muted);width:34%;white-space:normal}table.kv thead{display:none}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.pill{display:inline-block;font-size:11px;font-weight:650;padding:1px 8px;border-radius:999px;white-space:nowrap}
.p-good{background:color-mix(in srgb,#0ca30c 16%,transparent);color:#0ca30c}.p-bad{background:color-mix(in srgb,#d03b3b 16%,transparent);color:#e5484d}
.p-warn{background:color-mix(in srgb,#fab219 18%,transparent);color:#d39500}.p-neutral{background:var(--panel2);color:var(--muted);border:1px solid var(--line)}
.tblbar{display:flex;gap:8px;align-items:center;justify-content:space-between;margin:10px 0 -2px}
.tblbar input{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:5px 9px;color:var(--text);font-size:12px;width:220px;outline:none}
.tblbar span{font-size:11.5px;color:var(--muted)}
.more{display:block;width:100%;border:0;border-top:1px solid var(--line);background:var(--panel2);color:var(--accent);padding:8px;cursor:pointer;font-size:12.5px}
.prewrap{position:relative}.prewrap .copy{position:absolute;top:8px;right:8px;font-size:11px;padding:4px 9px;opacity:.75}.prewrap .copy:hover{opacity:1}
.prewrap.clip pre{max-height:240px;overflow:hidden;-webkit-mask-image:linear-gradient(#000 70%,transparent)}
.prewrap .exp{margin:-6px 0 8px;font-size:12px;background:none;border:0;color:var(--accent);cursor:pointer;padding:0}
details.cfg{background:var(--panel);box-shadow:none;margin:8px 0}details.cfg>summary{font-size:12.5px;padding:9px 12px}
.cfgline{font-size:12.5px;margin:8px 0}
mark{background:color-mix(in srgb,var(--med) 40%,transparent);color:inherit;border-radius:3px;padding:0 1px}
main{max-width:1500px}
p,li{max-width:110ch}
td{line-height:1.45}

.ng{margin-bottom:10px}.ng a.gt{color:var(--text);font-weight:650;font-size:11.5px;text-transform:uppercase;letter-spacing:.07em;padding:9px 10px 4px}
.ng a:not(.gt){padding-left:18px}
details.group{background:transparent;border:0;box-shadow:none;margin:22px 0 8px}
details.group>summary{padding:8px 0;border-bottom:1px solid var(--line);margin-bottom:6px}
details.group>summary h1{margin:0;font-size:20px;letter-spacing:-.015em}
details.group>*:not(summary){margin-left:0;margin-right:0}
.viz{--s1:#2a78d6;--track:#e1e0d9;--good:#0ca30c;--warning:#fab219;--serious:#ec835a;--critical:#d03b3b;--lowc:#2a78d6;--infoc:#898781}
[data-theme=dark] .viz{--s1:#3987e5;--track:#2c2c2a}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:14px;margin:6px 0 10px}
figure.chart{margin:0;background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
figure.chart figcaption{font-weight:650;font-size:13.5px;margin-bottom:10px}
svg.bars{width:100%;height:auto;display:block}svg.bars .lbl{fill:var(--muted);font-size:12px}svg.bars .val{fill:var(--text);font-size:12px;font-variant-numeric:tabular-nums}
svg .s1{fill:var(--s1)}svg .hit{fill:transparent}svg .row:hover .hit{fill:color-mix(in srgb,var(--s1) 8%,transparent)}svg .row:hover .mark{filter:brightness(1.12)}
svg.stack{width:100%;height:22px;display:block}svg .track{fill:var(--track)}
.st-good{fill:var(--good);background:var(--good)}.st-warning{fill:var(--warning);background:var(--warning)}.st-serious{fill:var(--serious);background:var(--serious)}
.st-critical{fill:var(--critical);background:var(--critical)}.st-low{fill:var(--lowc);background:var(--lowc)}.st-info{fill:var(--infoc);background:var(--infoc)}
.legend{display:flex;flex-wrap:wrap;gap:12px;margin-top:10px;font-size:12px;color:var(--muted)}.legend b{color:var(--text);font-weight:650}
.legend .sw{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.meter{margin:8px 0 12px}.ml{display:flex;justify-content:space-between;font-size:12.5px;margin-bottom:5px;color:var(--muted)}.mv{color:var(--text);font-variant-numeric:tabular-nums}
.mt{height:8px;border-radius:999px;background:var(--track);overflow:hidden}.mf{height:100%;border-radius:999px}
.ic{font-style:normal;font-size:10px;font-weight:800;color:#fff;border-radius:999px;padding:0 5px;margin-right:6px}
.cnote{font-size:11.5px;color:var(--muted);margin-top:6px}
.sevfilter{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0}.sevfilter button{border-radius:999px}
.sevfilter button.on{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 12%,transparent)}
@media(max-width:900px){.layout{grid-template-columns:1fr}aside{position:relative;height:auto}main{padding:18px}.search{width:100%}}
@media print{aside,.tools{display:none}.layout{display:block}details{break-inside:avoid}}
</style>
</head>
<body>
<div class="layout">
<aside>
  <div class="brand"><div class="logo">◎</div>Serveradar</div>
  <input id="navq" class="search navq" placeholder="Jump to section…" autocomplete="off">
  <nav id="nav">{{range .Nav}}<div class="ng"><a class="gt" href="#{{.ID}}">{{.Title}}</a>{{range .Items}}<a href="#{{.ID}}">{{.Label}}{{if .Status}}<span class="dot {{.Status}}" title="{{.Status}}"></span>{{end}}</a>{{end}}</div>{{end}}</nav>
</aside>
<main>
  <header class="top">
    <div>
      <h1>{{.Host.host}}</h1>
      <div class="sub">{{.Host.os}} · scanned {{.Host.time}} in {{.Host.duration}} · profile {{.Host.profile}} · user {{.Host.user}}</div>
      <div class="chips">{{if .Host.cpu}}<span class="chip">{{.Host.cpu}}</span>{{end}}{{if .Host.mem}}<span class="chip">RAM {{.Host.mem}}</span>{{end}}{{if .Host.uptime}}<span class="chip">up {{.Host.uptime}}</span>{{end}}<span class="chip">read-only scan</span></div>
    </div>
    <div class="tools">
      <input id="q" class="search" placeholder="Search everything…  ( / )" autocomplete="off">
      <button class="btn" id="expand">Expand all</button>
      <button class="btn" id="theme" title="Toggle theme">◐</button>
      <button class="btn" onclick="window.print()">Print</button>
    </div>
  </header>
  <section class="kpis">{{range .KPIs}}<div class="kpi {{.Tone}}" data-kpi="{{.Label}}" tabindex="0"><div class="l">{{.Label}}</div><div class="v">{{.Value}}</div></div>{{end}}</section>
  <div class="sevfilter" id="sevf">
    <button class="btn on" data-s="all">All findings</button><button class="btn" data-s="critical">Critical</button><button class="btn" data-s="high">High</button>
    <button class="btn" data-s="medium">Medium</button><button class="btn" data-s="low">Low</button><button class="btn" data-s="info">Info</button>
  </div>
  <div id="hits" class="hits"></div>
  <div id="content" class="viz">{{.Body}}</div>
  <button id="top" class="btn fab" title="Back to top">↑</button>
</main>
</div>
<script>
const FINDINGS = {{.Findings}};
(function(){
  const root=document.documentElement, $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
  try{const t=localStorage.getItem('ss-theme');if(t)root.dataset.theme=t;}catch(e){}
  $('#theme').onclick=()=>{root.dataset.theme=root.dataset.theme==='dark'?'light':'dark';try{localStorage.setItem('ss-theme',root.dataset.theme)}catch(e){}};
  let all=false;$('#expand').onclick=e=>{all=!all;$$('#content details').forEach(d=>d.open=all);e.target.textContent=all?'Collapse all':'Expand all'};
  // open a section when navigating to it
  function openFor(id){const a=document.getElementById(id);if(!a)return;let el=a.nextElementSibling;if(el&&el.tagName==='DETAILS')el.open=true;
    for(let p=a.parentElement;p;p=p.parentElement){if(p.tagName==='DETAILS')p.open=true}setTimeout(()=>a.scrollIntoView({block:'start'}),0)}
  $$('#nav a').forEach(a=>a.addEventListener('click',()=>openFor(a.getAttribute('href').slice(1))));
  $$('#content a[href^="#"]').forEach(a=>a.addEventListener('click',()=>openFor(a.getAttribute('href').slice(1))));
  if(location.hash)openFor(location.hash.slice(1));
  // active nav on scroll
  const anchors=$$('#content a[id]');const navMap={};$$('#nav a').forEach(a=>navMap[a.getAttribute('href').slice(1)]=a);
  addEventListener('scroll',()=>{let cur=null;for(const a of anchors){if(a.getBoundingClientRect().top<120)cur=a.id}
    $$('#nav a').forEach(x=>x.classList.remove('active'));if(cur&&navMap[cur])navMap[cur].classList.add('active')},{passive:true});
  // sortable tables
  $$('#content table').forEach(t=>{t.querySelectorAll('th').forEach((th,i)=>th.addEventListener('click',()=>{
    const tb=t.tBodies[0],rows=[...tb.rows],asc=!th.classList.contains('asc');t.querySelectorAll('th').forEach(x=>x.classList.remove('asc','desc'));th.classList.add(asc?'asc':'desc');
    const num=s=>{const m=s.replace(/,/g,'').match(/^-?[\d.]+\s*([KMGT]i?B)?/);if(!m)return null;let v=parseFloat(m[0]);const u={KiB:1024,MiB:1048576,GiB:1073741824,TiB:1099511627776}[m[1]];return u?v*u:v};
    rows.sort((a,b)=>{const x=a.cells[i]?.innerText.trim()||'',y=b.cells[i]?.innerText.trim()||'',nx=num(x),ny=num(y);
      const r=(nx!==null&&ny!==null)?nx-ny:x.localeCompare(y,undefined,{numeric:true});return asc?r:-r});rows.forEach(r=>tb.appendChild(r))}))});

  // ---- readability: pills, numbers, kv tables
  const good=/^(ok|yes|true|running|open|active|enabled|confirmed|healthy|primary|on)$/i, bad=/^(no auth.*|critical|error|failed|exited|unhealthy|closed|false|off|dead)$/i, warn=/^(partial|warning|restarting|password required|possible|strong|degraded)$/i;
  $$('#content td').forEach(td=>{if(td.children.length)return;const t=td.textContent.trim();if(!t||t.length>22)return;
    if(/^-?[\d.,]+\s*(%|[KMGT]i?B|B|ms|s|d)?$/.test(t)){td.classList.add('num');return}
    const c=good.test(t)?'p-good':bad.test(t)?'p-bad':warn.test(t)?'p-warn':(/^(no|n\/a|none|unavailable|skipped|info)$/i.test(t)?'p-neutral':'');
    if(c)td.innerHTML='<span class="pill '+c+'">'+td.innerHTML+'</span>'});
  $$('#content table').forEach(t=>{const h=[...t.tHead.rows[0].cells].map(c=>c.textContent.trim());if(h.length===2&&h[0]==='Key')t.classList.add('kv')});
  // ---- per-table filter + row cap
  $$('#content .tbl').forEach(w=>{const t=w.querySelector('table'),rows=[...t.tBodies[0].rows];if(t.classList.contains('kv'))return;
    const CAP=20;let expanded=rows.length<=CAP;
    const apply=q=>{let shown=0;rows.forEach(r=>{const hit=!q||r.innerText.toLowerCase().includes(q);r.dataset.f=hit?'1':'0';
      const vis=hit&&(expanded||q||shown<CAP);r.classList.toggle('hidden',!vis);if(hit)shown++});if(cnt)cnt.textContent=(q?shown+' / ':'')+rows.length+' rows';
      if(more)more.classList.toggle('hidden',expanded||!!q||rows.length<=CAP)};
    let cnt=null,more=null;
    if(rows.length>8){const bar=document.createElement('div');bar.className='tblbar';bar.innerHTML='<input placeholder="Filter this table…"><span></span>';
      w.before(bar);cnt=bar.querySelector('span');bar.querySelector('input').addEventListener('input',e=>apply(e.target.value.trim().toLowerCase()))}
    if(rows.length>CAP){more=document.createElement('button');more.className='more';more.textContent='Show all '+rows.length+' rows';w.appendChild(more);
      more.onclick=()=>{expanded=true;apply('')}}
    apply('')});
  // ---- code blocks: copy + clip long
  $$('#content pre:not(.mermaid)').forEach(pre=>{const wrap=document.createElement('div');wrap.className='prewrap';pre.before(wrap);wrap.appendChild(pre);
    const cp=document.createElement('button');cp.className='btn copy';cp.textContent='Copy';wrap.appendChild(cp);
    cp.onclick=()=>{navigator.clipboard?.writeText(pre.innerText).then(()=>{cp.textContent='Copied';setTimeout(()=>cp.textContent='Copy',1200)})};
    if(pre.innerText.split('\n').length>14){wrap.classList.add('clip');const ex=document.createElement('button');ex.className='exp';ex.textContent='Show full';wrap.after(ex);
      ex.onclick=()=>{const c=wrap.classList.toggle('clip');ex.textContent=c?'Show full':'Show less'}}});
  // ---- KPI cards jump to findings with filter
  $$('.kpi').forEach(k=>{const go=()=>{const l=k.dataset.kpi.toLowerCase(),map={critical:'critical',high:'high',medium:'medium',low:'low'};
    if(map[l]){openFor('findings');const b=document.querySelector('#sevf button[data-s="'+map[l]+'"]');b&&b.click();return}
    if(l.startsWith('open ports'))openFor('exposure');else if(l.startsWith('containers'))openFor('sec-docker');else if(l.startsWith('data'))openFor('sec-databases')};
    k.onclick=go;k.onkeydown=e=>{if(e.key==='Enter')go()}});
  // ---- sidebar jump filter
  $('#navq').addEventListener('input',e=>{const q=e.target.value.toLowerCase();$$('#nav .ng').forEach(g=>{let any=false;
    g.querySelectorAll('a:not(.gt)').forEach(a=>{const h=!q||a.textContent.toLowerCase().includes(q)||g.querySelector('.gt').textContent.toLowerCase().includes(q);a.classList.toggle('hidden',!h);any=any||h});
    g.classList.toggle('hidden',!any)})});
  $('#navq').addEventListener('keydown',e=>{if(e.key==='Enter'){const a=[...$$('#nav a:not(.gt)')].find(x=>!x.classList.contains('hidden'));if(a){a.click();location.hash=a.getAttribute('href')}}});
  // ---- back to top
  const top=$('#top');addEventListener('scroll',()=>top.classList.toggle('show',scrollY>900),{passive:true});top.onclick=()=>scrollTo({top:0,behavior:'smooth'});
  // severity filter on findings table
  const ft=document.getElementById('findings')?.nextElementSibling?.querySelector('table');
  $$('#sevf button').forEach(b=>b.onclick=()=>{$$('#sevf button').forEach(x=>x.classList.remove('on'));b.classList.add('on');
    if(!ft)return;const s=b.dataset.s;[...ft.tBodies[0].rows].forEach(r=>r.classList.toggle('hidden',s!=='all'&&!r.cells[1].innerText.toLowerCase().includes(s)))});
  // global search: filter table rows, open matching sections
  let tmr;$('#q').addEventListener('input',e=>{clearTimeout(tmr);tmr=setTimeout(()=>{const q=e.target.value.trim().toLowerCase();
    let n=0;$$('#content tbody tr').forEach(r=>{const h=!q||r.innerText.toLowerCase().includes(q);r.classList.toggle('hidden',!h&&!!q);if(q&&h)n++});
    $('#hits').textContent=q?n+' matching rows':'';
    if(q)$$('#content details').forEach(d=>{if(d.innerText.toLowerCase().includes(q))d.open=true})},150)});
  addEventListener('keydown',e=>{if(e.key==='/'&&document.activeElement!==$('#q')){e.preventDefault();$('#q').focus()}});
  // mermaid (optional, online)
  if(document.querySelector('.mermaid')){const s=document.createElement('script');s.src='https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js';
    s.onload=()=>{mermaid.initialize({startOnLoad:false,theme:root.dataset.theme==='dark'?'dark':'default',securityLevel:'strict'});
      $$('details').forEach(d=>d.addEventListener('toggle',()=>{if(d.open)mermaid.run({nodes:d.querySelectorAll('.mermaid:not([data-processed])')})}));
      mermaid.run({nodes:[...document.querySelectorAll('details[open] .mermaid')]})};document.head.appendChild(s)}
})();
</script>
</body>
</html>
`))
