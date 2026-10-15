// Package execx runs fixed executables with argv arrays, timeouts and output caps. No shell.
package execx

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"time"
)

const MaxOutput = 4 << 20

var ErrMissing = errors.New("tool not installed")

type limitedBuf struct{ bytes.Buffer }

func (l *limitedBuf) Write(p []byte) (int, error) {
	if room := MaxOutput - l.Len(); room > 0 {
		if len(p) > room {
			l.Buffer.Write(p[:room])
		} else {
			l.Buffer.Write(p)
		}
	}
	return len(p), nil
}

func Has(tool string) bool { _, err := exec.LookPath(tool); return err == nil }

// Run executes name with args. Returns stdout; error on missing tool, timeout, or non-zero exit.
func Run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	return RunEnv(ctx, timeout, nil, name, args...)
}

// RunEnv is Run with extra environment variables.
func RunEnv(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) (string, error) {
	if !Has(name) {
		return "", ErrMissing
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(append(os.Environ(), "LC_ALL=C"), env...)
	var out, errb limitedBuf
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return out.String(), errors.New(name + ": timeout")
	}
	if err != nil {
		msg := errb.String()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return out.String(), errors.New(name + ": " + err.Error() + " " + msg)
	}
	return out.String(), nil
}
