package inventory

import (
	"context"

	"github.com/bakhod1r/serveradar/internal/domain/policy"
)

// ProbeContext is what a probe sees while collecting: cancellation, policy, warnings, results of its dependencies.
type ProbeContext interface {
	context.Context
	Policy() *policy.Policy
	Warn(format string, a ...any)
	Prior(name string) any
}

// Probe is the domain port for a read-only observation source. Infrastructure implements it.
type Probe struct {
	Name     string
	Title    string
	Profiles []string
	Depends  []string
	Collect  func(ProbeContext) (any, error)
}

// ErrUnavailable means the subsystem is absent on this host. Not a failure.
type ErrUnavailable string

func (e ErrUnavailable) Error() string { return string(e) }

// ProbeCatalog lists probes in run/display order.
type ProbeCatalog interface {
	Probes() []Probe
}
