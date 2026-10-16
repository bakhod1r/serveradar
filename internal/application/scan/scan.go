// Package scan is the application service: runs probes per policy, then correlation and finding rules.
package scan

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/exposure"
	"github.com/bakhod1r/serveradar/internal/domain/finding"
	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/domain/policy"
	"github.com/bakhod1r/serveradar/internal/domain/topology"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
)

// ToolVersion is set at build time: -ldflags "-X .../scan.ToolVersion=v1.2.3"
var ToolVersion = "dev"

// Progress receives updates while scanning (may be nil).
type Progress func(name string, r *inventory.CollectorResult)

type Service struct {
	Catalog inventory.ProbeCatalog
}

func (s Service) Select(p *policy.Policy) []inventory.Probe {
	var out []inventory.Probe
	for _, c := range s.Catalog.Probes() {
		if slices.Contains(p.Disabled, c.Name) {
			continue
		}
		if len(p.Only) > 0 {
			if slices.Contains(p.Only, c.Name) {
				out = append(out, c)
			}
			continue
		}
		if slices.Contains(c.Profiles, p.Profile) {
			out = append(out, c)
		}
	}
	return out
}

// Run collects, correlates, and evaluates. Never mutates the host.
func (s Service) Run(ctx context.Context, p *policy.Policy, progress Progress) *inventory.Report {
	host, _ := os.Hostname()
	rep := &inventory.Report{
		SchemaVersion: inventory.SchemaVersion, ToolVersion: ToolVersion, Hostname: host, Profile: p.Profile,
		StartedAt: time.Now().UTC(), Collectors: map[string]*inventory.CollectorResult{}, Privileges: privileges(),
	}
	sel := s.Select(p)
	// include dependencies even if not selected
	names := map[string]bool{}
	for _, c := range sel {
		names[c.Name] = true
	}
	for changed := true; changed; { // transitive closure
		changed = false
		for _, c := range sel {
			for _, d := range c.Depends {
				if names[d] {
					continue
				}
				for _, x := range s.Catalog.Probes() {
					if x.Name == d {
						sel = append(sel, x)
						names[d], changed = true, true
					}
				}
			}
		}
	}
	prior := map[string]any{}
	var mu sync.Mutex
	done := map[string]chan struct{}{}
	for _, c := range sel {
		done[c.Name] = make(chan struct{})
	}
	for _, c := range s.Catalog.Probes() {
		if names[c.Name] {
			rep.Order = append(rep.Order, c.Name)
		}
	}
	sem := make(chan struct{}, max(1, p.Concurrency))
	var wg sync.WaitGroup
	for _, c := range sel {
		wg.Add(1)
		go func(c inventory.Probe) {
			defer wg.Done()
			defer close(done[c.Name])
			for _, d := range c.Depends {
				if ch, ok := done[d]; ok {
					<-ch
				}
			}
			sem <- struct{}{}
			defer func() { <-sem }()
			r := runOne(ctx, p, c, prior, &mu)
			mu.Lock()
			rep.Collectors[c.Name] = r
			if r.Data != nil {
				prior[c.Name] = r.Data
			}
			mu.Unlock()
			if progress != nil {
				progress(c.Name, r)
			}
		}(c)
	}
	wg.Wait()
	rep.Relationships = topology.Correlate(rep)
	ports, _ := topology.Get[*inventory.Ports](rep, "ports")
	dk, _ := topology.Get[*inventory.Docker](rep, "docker")
	fw, _ := topology.Get[*inventory.Firewall](rep, "firewall")
	rep.Exposure = exposure.Analyze(rep, ports, dk, fw)
	rep.Findings = finding.Evaluate(rep, p)
	rep.FinishedAt = time.Now().UTC()
	return rep
}

type probeCtx struct {
	context.Context
	pol      *policy.Policy
	warnings []string
	partial  bool
	prior    map[string]any
	mu       *sync.Mutex
}

func (c *probeCtx) Policy() *policy.Policy { return c.pol }
func (c *probeCtx) Warn(f string, a ...any) {
	c.warnings = append(c.warnings, fmt.Sprintf(f, a...))
	c.partial = true
}
func (c *probeCtx) Prior(n string) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.prior[n]
}

func runOne(parent context.Context, p *policy.Policy, c inventory.Probe, prior map[string]any, mu *sync.Mutex) *inventory.CollectorResult {
	start := time.Now()
	ctx, cancel := context.WithTimeout(parent, p.Timeout)
	defer cancel()
	cx := &probeCtx{Context: ctx, pol: p, prior: prior, mu: mu}
	res := &inventory.CollectorResult{Name: c.Name}
	type out struct {
		d   any
		err error
	}
	ch := make(chan out, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- out{nil, fmt.Errorf("panic: %v", r)}
			}
		}()
		d, err := c.Collect(cx)
		ch <- out{d, err}
	}()
	select {
	case o := <-ch:
		res.Data = o.d
		switch e := o.err.(type) {
		case nil:
			res.Status = inventory.StatusOK
			if cx.partial {
				res.Status = inventory.StatusPartial
			}
		case inventory.ErrUnavailable:
			res.Status, res.Error = inventory.StatusUnavailable, string(e)
		default:
			res.Status, res.Error = inventory.StatusError, e.Error()
		}
		res.Warnings = cx.warnings
	case <-ctx.Done():
		res.Status, res.Error = inventory.StatusError, "collector timeout"
	}
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

func privileges() inventory.Privileges {
	p := inventory.Privileges{UID: os.Geteuid(), Platform: runtime.GOOS + "/" + runtime.GOARCH, SudoBin: execx.Has("sudo")}
	p.Root = p.UID == 0
	if u, err := user.Current(); err == nil {
		p.User = u.Username
	}
	return p
}
