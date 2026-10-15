package probe

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
)

func init() {
	register(Collector{Name: "tools", Title: "DevOps Tools", Profiles: everywhere,
		Depends: []string{"processes", "docker", "ports", "systemd"}, Collect: collectTools})
}

func collectTools(c Ctx) (any, error) {
	pl, _ := c.Prior("processes").(*inventory.ProcessList)
	dk, _ := c.Prior("docker").(*inventory.Docker)
	sd, _ := c.Prior("systemd").(*inventory.Systemd)
	ports, _ := c.Prior("ports").(*inventory.Ports)
	res := &inventory.Tools{ByCategory: map[string]int{}}
	hc := httpClient()
	hc.Timeout = 2 * time.Second

	for _, sig := range toolCatalog {
		t := inventory.Tool{Name: sig.name, Category: sig.cat}
		for _, b := range sig.bins {
			if execx.Has(b) {
				t.Evidence = appendUniq(t.Evidence, "binary:"+b)
			}
		}
		pids := map[int]bool{}
		if pl != nil {
			for _, p := range pl.All {
				for _, n := range sig.procs {
					if p.Comm == n || p.Comm == "java" && strings.Contains(strings.ToLower(p.Cmdline), strings.ToLower(n)) {
						pids[p.PID] = true
						t.Running = true
						t.Evidence = appendUniq(t.Evidence, "process:"+p.Comm)
					}
				}
			}
		}
		if dk != nil {
			for _, ct := range dk.Containers {
				img := strings.ToLower(ct.Image)
				for _, im := range sig.images {
					if strings.Contains(img, im) {
						t.Evidence = appendUniq(t.Evidence, "container:"+ct.Name+"("+ct.State+")")
						t.Running = t.Running || ct.State == "running"
						for _, pm := range ct.Ports {
							if i := strings.Index(pm, "->"); i > 0 {
								if n, err := strconv.Atoi(pm[strings.LastIndex(pm[:i], ":")+1 : i]); err == nil && !containsInt(t.Ports, n) {
									t.Ports = append(t.Ports, n)
								}
							}
						}
					}
				}
			}
		}
		if sd != nil {
			for _, u := range sd.Units {
				for _, pre := range sig.units {
					if strings.HasPrefix(u.Name, pre+".") || strings.HasPrefix(u.Name, pre+"@") {
						t.Evidence = appendUniq(t.Evidence, "unit:"+u.Name+"("+u.Active+")")
						t.Running = t.Running || u.Active == "active"
					}
				}
			}
		}
		for _, p := range sig.paths {
			if _, err := os.Stat(p); err == nil {
				t.Evidence = appendUniq(t.Evidence, "path:"+p)
			}
		}
		if ports != nil && len(pids) > 0 {
			for _, s := range ports.Sockets {
				if pids[s.PID] && !containsInt(t.Ports, s.Port) {
					t.Ports = append(t.Ports, s.Port)
				}
			}
		}
		if len(t.Evidence) == 0 {
			continue
		}
		if len(sig.ver) > 0 && execx.Has(sig.ver[0]) {
			if out, err := execx.Run(c, 4*time.Second, sig.ver[0], sig.ver[1:]...); err == nil || out != "" {
				t.Version = truncate(firstLine(out), 90)
			}
		}
		// web UI: only for running services with known ports; HTTP status of "/" — no credentials sent
		if t.Running {
			for _, p := range t.Ports {
				if code := uiStatus(hc, p); code != "" {
					t.UI = "http(s)://127.0.0.1:" + strconv.Itoa(p) + " → " + code
					break
				}
			}
		}
		res.Items = append(res.Items, t)
		res.ByCategory[t.Category]++
	}
	sortBy(res.Items, func(a, b inventory.Tool) bool {
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Name < b.Name
	})
	return res, nil
}

func uiStatus(hc *http.Client, port int) string {
	for _, scheme := range []string{"http", "https"} {
		resp, err := hc.Get(scheme + "://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/")
		if err != nil {
			continue
		}
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		s := strconv.Itoa(resp.StatusCode)
		if loc != "" {
			s += " → " + truncate(loc, 60)
		}
		return scheme + " " + s
	}
	return ""
}
