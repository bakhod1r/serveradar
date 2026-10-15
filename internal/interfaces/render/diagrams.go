package render

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/domain/topology"
)

func nodeID(prefix, s string) string {
	var b strings.Builder
	b.WriteString(prefix)
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func q(s string) string { return strings.NewReplacer(`"`, "'", "<", "‹", ">", "›").Replace(s) }

// ArchitectureMermaid: network → exposed ports → owning container/process → data stores.
func ArchitectureMermaid(r *inventory.Report) string {
	var exposed []inventory.PortExposure
	for _, e := range r.Exposure {
		if e.Scope != "local only" && (e.Risk == "high" || e.Risk == "medium" || e.Category == "web" || e.Category == "remote access") {
			exposed = append(exposed, e)
		}
	}
	if len(exposed) == 0 {
		return ""
	}
	if len(exposed) > 40 {
		exposed = exposed[:40]
	}
	dataKinds := map[string]bool{}
	if d, ok := topology.Get[*inventory.Databases](r, "databases"); ok {
		for _, s := range d.Services {
			for _, part := range strings.Split(s.Container, ", ") {
				if name, _, ok := strings.Cut(part, "("); ok && name != "" {
					dataKinds[name] = true
				}
			}
		}
	}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	b.WriteString("  net((\"Network / LAN / Internet\"))\n")
	b.WriteString("  subgraph PORTS[\"Exposed ports\"]\n")
	for _, e := range exposed {
		label := fmt.Sprintf(":%d %s", e.Port, e.Service)
		fmt.Fprintf(&b, "    %s[\"%s<br/>%s\"]\n", nodeID("p", strconv.Itoa(e.Port)+e.Proto), q(strings.TrimSpace(label)), q(e.Scope))
	}
	b.WriteString("  end\n")
	owners := map[string]string{}
	var apps, data []string
	for _, e := range exposed {
		o := e.Container
		if o != "" {
			o, _, _ = strings.Cut(o, " (")
		} else {
			o = e.Process
		}
		if o == "" {
			o = "unknown"
		}
		id := nodeID("o", o)
		if _, seen := owners[id]; !seen {
			owners[id] = o
			if dataKinds[o] {
				data = append(data, id)
			} else {
				apps = append(apps, id)
			}
		}
	}
	b.WriteString("  subgraph APPS[\"Services & apps\"]\n")
	for _, id := range apps {
		fmt.Fprintf(&b, "    %s[\"%s\"]\n", id, q(owners[id]))
	}
	b.WriteString("  end\n  subgraph DATA[\"Data stores\"]\n")
	for _, id := range data {
		fmt.Fprintf(&b, "    %s[(\"%s\")]\n", id, q(owners[id]))
	}
	b.WriteString("  end\n")
	edge := 0
	var red []int
	for _, e := range exposed {
		pid := nodeID("p", strconv.Itoa(e.Port)+e.Proto)
		o := e.Container
		if o != "" {
			o, _, _ = strings.Cut(o, " (")
		} else if o = e.Process; o == "" {
			o = "unknown"
		}
		fmt.Fprintf(&b, "  net --> %s\n", pid)
		if e.Risk == "high" {
			red = append(red, edge)
		}
		edge++
		fmt.Fprintf(&b, "  %s --> %s\n", pid, nodeID("o", o))
		edge++
	}
	for _, i := range red {
		fmt.Fprintf(&b, "  linkStyle %d stroke:#d03b3b,stroke-width:2.5px\n", i)
	}
	for _, e := range exposed {
		if e.Risk == "high" {
			fmt.Fprintf(&b, "  style %s stroke:#d03b3b,stroke-width:2px\n", nodeID("p", strconv.Itoa(e.Port)+e.Proto))
		}
	}
	return b.String()
}

// AccessMermaid: from loopback / LAN to each DB endpoint, edge label = what the server demanded.
func AccessMermaid(r *inventory.Report) string {
	a, ok := topology.Get[*inventory.DBAccess](r, "dbaccess")
	if !ok || len(a.Checks) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	srcs := map[string]bool{}
	ends := map[string]bool{}
	edge := 0
	var styles []string
	for _, c := range a.Checks {
		if c.Path == "not published" {
			continue
		}
		src := nodeID("s", c.Path)
		if !srcs[src] {
			srcs[src] = true
			fmt.Fprintf(&b, "  %s((\"from %s\"))\n", src, q(c.Path))
		}
		dst := nodeID("d", c.Owner+strconv.Itoa(c.Port))
		if !ends[dst] {
			ends[dst] = true
			fmt.Fprintf(&b, "  %s[(\"%s<br/>%s :%d\")]\n", dst, q(c.Engine), q(strings.TrimPrefix(c.Owner, "container ")), c.Port)
		}
		label, color := "open", "#8a94ad"
		switch {
		case c.TCP != "open":
			label, color = "closed", "#0ca30c"
		case strings.HasPrefix(c.Verdict, "OPEN WITHOUT PASSWORD"):
			label, color = "NO AUTH", "#d03b3b"
		case strings.Contains(c.Verdict, "password required"):
			label, color = "password", "#2a78d6"
		case strings.Contains(c.Verdict, "rejects"):
			label, color = "rejected", "#0ca30c"
		}
		arrow := "-->"
		if label == "closed" || label == "rejected" {
			arrow = "-.-x"
		}
		fmt.Fprintf(&b, "  %s %s|%s| %s\n", src, arrow, label, dst)
		styles = append(styles, fmt.Sprintf("  linkStyle %d stroke:%s,stroke-width:2px", edge, color))
		edge++
	}
	b.WriteString(strings.Join(styles, "\n") + "\n")
	return b.String()
}
