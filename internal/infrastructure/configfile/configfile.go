// Package configfile loads a scan policy from JSON: /etc/serveradar/config.json, ~/.config/serveradar/config.json.
package configfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/policy"
)

func Load(path string) (*policy.Policy, error) {
	p := policy.Default()
	paths := []string{"/etc/serveradar/config.json"}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config/serveradar/config.json"))
	}
	if path != "" {
		paths = []string{path}
	}
	for _, f := range paths {
		b, err := os.ReadFile(f)
		if err != nil {
			if path != "" {
				return nil, err
			}
			continue
		}
		if err := json.Unmarshal(b, p); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		p.Source = f
		break
	}
	p.Timeout = time.Duration(p.TimeoutSec) * time.Second
	return p, p.Validate()
}
