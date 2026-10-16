package probe

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
)

func init() {
	register(Collector{Name: "nginx", Title: "Nginx", Profiles: std, Depends: []string{"processes"}, Collect: collectNginx})
}

func collectNginx(c Ctx) (any, error) {
	n := &inventory.Nginx{Upstreams: map[string][]string{}}
	if pl, ok := c.Prior("processes").(*inventory.ProcessList); ok {
		for _, p := range pl.All {
			if strings.HasPrefix(p.Cmdline, "nginx: master") {
				n.Running = true
			}
		}
	}
	hasBin := execx.Has("nginx")
	if hasBin {
		if _, err := execx.Run(c, 5*time.Second, "nginx", "-v"); err != nil {
			// nginx -v prints to stderr; error text includes it
			if i := strings.Index(err.Error(), "nginx/"); i >= 0 {
				n.Version = strings.Fields(err.Error()[i:])[0]
			}
		}
	}
	files := map[string]string{} // path -> content
	if hasBin && c.Policy().NginxDump {
		// nginx -T: test config and dump all included files. Reads only, no reload.
		out, err := execx.Run(c, 10*time.Second, "nginx", "-T")
		if out != "" {
			n.Source = "nginx -T"
			cur := ""
			for _, ln := range strings.SplitAfter(out, "\n") {
				if strings.HasPrefix(ln, "# configuration file ") {
					cur = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(ln), "# configuration file "), ":")
					continue
				}
				if cur != "" {
					files[cur] += ln
				}
			}
		} else if err != nil {
			c.Warn("nginx -T failed (likely permissions): falling back to file parse")
		}
	}
	if len(files) == 0 {
		n.Source, n.Heuristic = "files", true
		for _, root := range c.Policy().NginxRoots {
			_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if !d.IsDir() && (strings.HasSuffix(p, ".conf") || strings.Contains(p, "sites-enabled")) {
					if b, err := os.ReadFile(p); err == nil && len(b) < 2<<20 {
						files[p] = string(b)
					} else if os.IsPermission(err) {
						c.Warn("cannot read %s", p)
					}
				}
				return nil
			})
		}
	}
	if len(files) == 0 && !hasBin && !n.Running {
		return nil, ErrUnavailable("nginx not installed")
	}
	for path, txt := range files {
		parseNginx(n, path, txt)
	}
	sortBy(n.Vhosts, func(a, b inventory.Vhost) bool {
		return strings.Join(a.ServerNames, ",") < strings.Join(b.ServerNames, ",")
	})
	return n, nil
}

type ngxFrame struct {
	name, arg string
	vhost     *inventory.Vhost
}

// parseNginx: brace-aware tokenizer; collects server{} and upstream{} blocks. Heuristic, not a full grammar.
func parseNginx(n *inventory.Nginx, path, txt string) {
	var stack []ngxFrame
	var stmt []string
	cur := func() (*inventory.Vhost, string) {
		var v *inventory.Vhost
		up := ""
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].vhost != nil && v == nil {
				v = stack[i].vhost
			}
			if stack[i].name == "upstream" {
				up = stack[i].arg
			}
		}
		return v, up
	}
	for _, t := range tokenize(txt) {
		switch t {
		case "{":
			f := ngxFrame{}
			if len(stmt) > 0 {
				f.name = stmt[0]
				if len(stmt) > 1 {
					f.arg = stmt[1]
				}
			}
			if f.name == "server" {
				if v, _ := cur(); v == nil {
					f.vhost = &inventory.Vhost{File: path}
				}
			}
			stack = append(stack, f)
			stmt = nil
		case "}":
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if top.vhost != nil && (len(top.vhost.Listens) > 0 || len(top.vhost.ServerNames) > 0) {
					n.Vhosts = append(n.Vhosts, *top.vhost)
				}
			}
			stmt = nil
		case ";":
			if len(stmt) > 0 {
				v, up := cur()
				directive(n, v, up, stmt)
			}
			stmt = nil
		default:
			stmt = append(stmt, t)
		}
	}
}

func directive(n *inventory.Nginx, v *inventory.Vhost, upstream string, s []string) {
	args := s[1:]
	if upstream != "" && s[0] == "server" && len(args) > 0 {
		n.Upstreams[upstream] = append(n.Upstreams[upstream], strings.Join(args, " "))
		return
	}
	if v == nil {
		return
	}
	switch s[0] {
	case "server_name":
		v.ServerNames = append(v.ServerNames, args...)
	case "listen":
		v.Listens = append(v.Listens, strings.Join(args, " "))
		for _, a := range args {
			if a == "default_server" || a == "default" {
				v.DefaultSrv = true
			}
		}
	case "proxy_pass", "fastcgi_pass", "uwsgi_pass", "grpc_pass":
		if len(args) > 0 {
			v.ProxyPass = appendUniq(v.ProxyPass, args[0])
		}
	case "root", "alias":
		if len(args) > 0 {
			v.Roots = appendUniq(v.Roots, args[0])
		}
	case "ssl_certificate":
		if len(args) > 0 {
			v.SSLCert = args[0]
		}
	case "return", "rewrite":
		if strings.Contains(strings.Join(args, " "), "https://") {
			v.Redirect = true
		}
	case "stub_status":
		v.StubStatus = true
	}
}

func tokenize(s string) []string {
	var toks []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			toks = append(toks, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '#':
			flush()
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case ch == '"' || ch == '\'':
			q := ch
			i++
			for i < len(s) && s[i] != q {
				b.WriteByte(s[i])
				i++
			}
		case ch == '{' || ch == '}' || ch == ';':
			flush()
			toks = append(toks, string(ch))
		case ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r':
			flush()
		default:
			b.WriteByte(ch)
		}
	}
	flush()
	return toks
}
