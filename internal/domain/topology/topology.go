// Package topology correlates observations into relationships with confidence labels.
package topology

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
)

func Correlate(r *inventory.Report) []inventory.Relationship {
	var rels []inventory.Relationship
	add := func(s, t, k string, c inventory.Confidence, ev string) {
		rels = append(rels, inventory.Relationship{Source: s, Target: t, Kind: k, Confidence: c, Evidence: ev})
	}
	ports, _ := get[*inventory.Ports](r, "ports")
	dk, _ := get[*inventory.Docker](r, "docker")
	ngx, _ := get[*inventory.Nginx](r, "nginx")
	tls, _ := get[*inventory.TLS](r, "tls")
	projs, _ := get[*inventory.Projects](r, "projects")
	dbs, _ := get[*inventory.Databases](r, "databases")

	// host port -> container (docker publish)
	pub := map[int]string{}
	if dk != nil {
		for _, c := range dk.Containers {
			for _, p := range c.Ports {
				hp := p[strings.LastIndex(p[:strings.Index(p, "->")], ":")+1 : strings.Index(p, "->")]
				if n, err := strconv.Atoi(hp); err == nil {
					pub[n] = c.Name
					add("port:"+hp, "container:"+c.Name, "publishes", inventory.Confirmed, "docker port mapping "+p)
				}
			}
			for net, ip := range c.Networks {
				add("container:"+c.Name, "network:"+net, "attached", inventory.Confirmed, "docker inspect ip="+ip)
			}
			if c.ComposeDir != "" {
				add("container:"+c.Name, "project:"+c.ComposeDir, "deployed-from", inventory.Confirmed, "compose label")
			}
		}
	}
	// port -> process
	if ports != nil {
		for _, s := range ports.Sockets {
			if s.Process != "" && pub[s.Port] == "" {
				add("port:"+strconv.Itoa(s.Port), "process:"+s.Process, "owned-by", inventory.Confirmed, ports.Method)
			}
		}
	}
	// domain -> nginx -> upstream -> port
	if ngx != nil {
		for _, v := range ngx.Vhosts {
			name := strings.Join(v.ServerNames, " ")
			if name == "" {
				name = "(default)"
			}
			for _, l := range v.Listens {
				add("domain:"+name, "port:"+strings.Fields(l)[0], "served-on", inventory.Confirmed, "nginx listen in "+v.File)
			}
			if v.SSLCert != "" {
				add("domain:"+name, "cert:"+v.SSLCert, "tls", inventory.Confirmed, "ssl_certificate")
			}
			for _, pp := range v.ProxyPass {
				target, port := upstreamTarget(pp, ngx.Upstreams)
				for _, t := range target {
					add("domain:"+name, "upstream:"+t, "proxies-to", inventory.Confirmed, "proxy_pass "+pp)
				}
				for _, p := range port {
					conf := inventory.Strong
					tgt := "port:" + strconv.Itoa(p)
					if c, ok := pub[p]; ok {
						tgt = "container:" + c
					}
					add("upstream:"+pp, tgt, "resolves-to", conf, "upstream port matches local listener")
				}
			}
		}
	}
	_ = tls
	// project -> database (possible: via compose dir / container names)
	if dbs != nil && projs != nil {
		for _, s := range dbs.Services {
			for _, p := range s.Ports {
				add("db:"+s.Kind, "port:"+strconv.Itoa(p), "listens", inventory.Confirmed, strings.Join(s.Source, ","))
			}
		}
	}
	return rels
}

func upstreamTarget(pp string, ups map[string][]string) (targets []string, ports []int) {
	u, err := url.Parse(pp)
	if err != nil || u.Host == "" {
		return []string{pp}, nil
	}
	hosts := []string{u.Host}
	if list, ok := ups[u.Hostname()]; ok {
		hosts = nil
		for _, s := range list {
			hosts = append(hosts, strings.Fields(s)[0])
		}
	}
	for _, h := range hosts {
		targets = append(targets, h)
		if i := strings.LastIndex(h, ":"); i >= 0 {
			if p, err := strconv.Atoi(h[i+1:]); err == nil {
				ports = append(ports, p)
			}
		} else if u.Scheme == "https" {
			ports = append(ports, 443)
		} else {
			ports = append(ports, 80)
		}
	}
	return
}

func get[T any](r *inventory.Report, name string) (T, bool) {
	var zero T
	c, ok := r.Collectors[name]
	if !ok || c.Data == nil {
		return zero, false
	}
	v, ok := c.Data.(T)
	return v, ok
}

// Get exposes typed access for other layers.
func Get[T any](r *inventory.Report, name string) (T, bool) { return get[T](r, name) }

// MermaidDocker: networks <-> containers <-> host ports diagram.
func MermaidDocker(r *inventory.Report) string {
	dk, ok := get[*inventory.Docker](r, "docker")
	if !ok || len(dk.Containers) == 0 {
		return ""
	}
	id := func(p, s string) string {
		var b strings.Builder
		b.WriteString(p)
		for _, ch := range s {
			if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
				b.WriteRune(ch)
			} else {
				b.WriteByte('_')
			}
		}
		return b.String()
	}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	b.WriteString("  host((\"Host " + r.Hostname + "\"))\n")
	nets := map[string]string{}
	for _, n := range dk.Networks {
		nets[n["Name"]] = n["Driver"] + " " + n["Subnets"]
	}
	for _, c := range dk.Containers {
		for n := range c.Networks {
			if _, ok := nets[n]; !ok {
				nets[n] = ""
			}
		}
	}
	for n, d := range nets {
		fmt.Fprintf(&b, "  %s{{\"net: %s<br/>%s\"}}\n", id("n_", n), n, strings.TrimSpace(d))
	}
	for _, c := range dk.Containers {
		label := c.Name + "<br/>" + c.Image + "<br/>" + c.State
		if c.Compose != "" {
			label += "<br/>compose:" + c.Compose
		}
		fmt.Fprintf(&b, "  %s[\"%s\"]\n", id("c_", c.Name), strings.ReplaceAll(label, `"`, "'"))
		for n, ip := range c.Networks {
			fmt.Fprintf(&b, "  %s ---|%s| %s\n", id("c_", c.Name), orDash(ip), id("n_", n))
		}
		for _, p := range c.Ports {
			fmt.Fprintf(&b, "  host -->|\"%s\"| %s\n", p, id("c_", c.Name))
		}
		if c.Privileged || c.SocketMount || c.HostNet {
			fmt.Fprintf(&b, "  style %s stroke:#d33,stroke-width:3px\n", id("c_", c.Name))
		}
	}
	return b.String()
}

// MermaidTopology: full relationship graph.
func MermaidTopology(r *inventory.Report) string {
	if len(r.Relationships) == 0 {
		return ""
	}
	ids := map[string]string{}
	nid := func(s string) string {
		if v, ok := ids[s]; ok {
			return v
		}
		v := "x" + strconv.Itoa(len(ids))
		ids[s] = v
		return v
	}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	for _, rel := range r.Relationships {
		s, t := nid(rel.Source), nid(rel.Target)
		arrow := "-->"
		if rel.Confidence != inventory.Confirmed {
			arrow = "-.->"
		}
		fmt.Fprintf(&b, "  %s[\"%s\"] %s|%s| %s[\"%s\"]\n", s, esc(rel.Source), arrow, rel.Kind, t, esc(rel.Target))
	}
	return b.String()
}

func esc(s string) string { return strings.NewReplacer(`"`, "'", "<", "‹", ">", "›").Replace(s) }

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
