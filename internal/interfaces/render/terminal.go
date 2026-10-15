package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/domain/topology"
)

var ansi = map[inventory.Severity]string{"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[90m"}

const reset = "\033[0m"

func Terminal(w io.Writer, r *inventory.Report) {
	fmt.Fprintf(w, "\n\033[1mServeradar — %s\033[0m  profile=%s  %s\n", r.Hostname, r.Profile, r.FinishedAt.Sub(r.StartedAt).Round(1e6))
	if h, ok := topology.Get[*inventory.Host](r, "host"); ok {
		fmt.Fprintf(w, "  %s · %s · %d CPU · load %.2f · RAM %s/%s avail · up %s\n", h.Distro, h.Kernel, h.CPUs, h.Load[0], hb(h.MemAvailable), hb(h.MemTotal), Dur(h.UptimeSec))
		for _, m := range h.Mounts {
			if m.TotalBytes > 1<<30 {
				fmt.Fprintf(w, "  disk %-24s %5.1f%% of %s\n", m.Mountpoint, m.UsedPct, hb(m.TotalBytes))
			}
		}
	}
	if res, ok := topology.Get[*inventory.Resources](r, "resources"); ok {
		fmt.Fprintln(w, "\n\033[1mTop apps (CPU / RAM)\033[0m")
		for _, u := range limitU(res.ByApp, 10) {
			fmt.Fprintf(w, "  %-28s %3d procs  cpu %6.1f%%  rss %9s (%4.1f%%)\n", trunc(u.Key, 28), u.Count, u.CPU, hb(u.RSS), u.MemPct)
		}
	}
	if p, ok := topology.Get[*inventory.Ports](r, "ports"); ok {
		fmt.Fprintf(w, "\n\033[1mListening (%d)\033[0m\n", len(p.Sockets))
		for _, s := range p.Sockets {
			fmt.Fprintf(w, "  %-4s %-22s %6d  %s\n", s.Proto, s.Address, s.Port, s.Process)
		}
	}
	if d, ok := topology.Get[*inventory.Docker](r, "docker"); ok {
		fmt.Fprintf(w, "\n\033[1mDocker %s — %d containers\033[0m\n", d.Version, len(d.Containers))
		for _, c := range d.Containers {
			fmt.Fprintf(w, "  %-24s %-10s %-30s %s\n", trunc(c.Name, 24), c.State, trunc(c.Image, 30), strings.Join(c.Ports, " "))
		}
	}
	if d, ok := topology.Get[*inventory.Databases](r, "databases"); ok && len(d.Services) > 0 {
		fmt.Fprintln(w, "\n\033[1mData services\033[0m")
		for _, s := range d.Services {
			fmt.Fprintf(w, "  %-14s ports=%v  %s  %s\n", s.Kind, s.Ports, strings.Join(s.Source, ","), s.Cluster)
		}
	}
	TerminalFindings(w, r)
}

func TerminalFindings(w io.Writer, r *inventory.Report) {
	fmt.Fprintf(w, "\n\033[1mFindings (%d)\033[0m\n", len(r.Findings))
	for _, f := range r.Findings {
		fmt.Fprintf(w, "  %s%-8s%s %s\n           %s\n           → %s\n", ansi[f.Severity], strings.ToUpper(string(f.Severity)), reset, f.Title, f.Evidence, f.NextStep)
	}
}

func limitU(s []inventory.Usage, n int) []inventory.Usage {
	if len(s) > n {
		return s[:n]
	}
	return s
}
