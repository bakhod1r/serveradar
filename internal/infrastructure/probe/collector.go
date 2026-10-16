// Package probe implements inventory.Probe adapters backed by host tools, /proc and local files. All read-only.
package probe

import (
	"sort"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
)

type (
	Ctx            = inventory.ProbeContext
	Collector      = inventory.Probe
	ErrUnavailable = inventory.ErrUnavailable
)

var all = map[string]Collector{}

func register(c Collector) { all[c.Name] = c }

// Order is run/display order.
var Order = []string{"host", "resources", "processes", "network", "ports", "systemd", "cron", "tools", "docker", "kubernetes",
	"nginx", "tls", "projects", "databases", "dbaccess", "postgres", "mysql", "redis", "services", "dbconfig", "firewall", "security"}

var (
	std        = []string{"standard", "deep"}
	everywhere = []string{"quick", "standard", "deep"}
)

// Catalog implements inventory.ProbeCatalog.
type Catalog struct{}

func (Catalog) Probes() []inventory.Probe {
	var out []inventory.Probe
	for _, n := range Order {
		if c, ok := all[n]; ok {
			out = append(out, c)
		}
	}
	return out
}

func sortBy[T any](s []T, less func(a, b T) bool) {
	sort.SliceStable(s, func(i, j int) bool { return less(s[i], s[j]) })
}
