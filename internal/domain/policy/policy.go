// Package policy is the scan policy value object: profile, scope, limits.
package policy

import (
	"fmt"
	"os"
	"time"
)

var Profiles = []string{"quick", "standard", "deep"}

type Policy struct {
	Profile         string        `json:"profile"`
	Timeout         time.Duration `json:"-"`
	TimeoutSec      int           `json:"timeout_sec"`
	Concurrency     int           `json:"concurrency"`
	ProjectRoots    []string      `json:"project_roots"`
	ProjectMaxDepth int           `json:"project_max_depth"`
	ExcludePaths    []string      `json:"exclude_paths"`
	NginxRoots      []string      `json:"nginx_roots"`
	CertDirs        []string      `json:"cert_dirs"`
	CertWarnDays    int           `json:"cert_warn_days"`
	Disabled        []string      `json:"disabled_collectors"`
	Only            []string      `json:"-"`
	NginxDump       bool          `json:"use_nginx_dump"`
	ShowEnv         bool          `json:"show_env_values"`
	PGDSNs          []string      `json:"postgres_dsns"`   // explicit targets; may use PGPASSFILE
	PGLocal         bool          `json:"postgres_local"`  // psql as OS user postgres via unix socket
	PGDocker        bool          `json:"postgres_docker"` // docker exec psql in postgres containers
	PGMaxDBs        int           `json:"postgres_max_dbs"`
	RedisURLs       []string      `json:"redis_urls"`
	RedisLocal      bool          `json:"redis_local"` // try discovered endpoints without auth
	MySQLDSNs       []string      `json:"mysql_dsns"`
	MySQLLocal      bool          `json:"mysql_local"`
	MySQLDocker     bool          `json:"mysql_docker"` // docker exec; root password read inside container only
	Source          string        `json:"-"`
}

func Default() *Policy {
	home, _ := os.UserHomeDir()
	return &Policy{
		Profile: "standard", TimeoutSec: 30, Concurrency: 6, Timeout: 30 * time.Second,
		ProjectRoots:    []string{"/srv", "/opt", "/var/www", "/home", "/root", home},
		ProjectMaxDepth: 4,
		ExcludePaths:    []string{"node_modules", ".cache", "vendor", ".venv", "venv", "Library", ".Trash", "go/pkg"},
		NginxRoots:      []string{"/etc/nginx", "/usr/local/etc/nginx", "/opt/homebrew/etc/nginx"},
		CertDirs:        []string{"/etc/letsencrypt/live"},
		CertWarnDays:    21,
		NginxDump:       true,
		PGMaxDBs:        20,
		Source:          "defaults",
	}
}

func (p *Policy) Validate() error {
	for _, x := range Profiles {
		if x == p.Profile {
			return nil
		}
	}
	return fmt.Errorf("unknown profile %q (quick|standard|deep)", p.Profile)
}

// DeepDataStores: deep profile turns on local/docker datastore inspection.
func (p *Policy) PGEnabled() bool {
	return len(p.PGDSNs) > 0 || p.PGLocal || p.PGDocker || p.Profile == "deep"
}
func (p *Policy) RedisEnabled() bool {
	return len(p.RedisURLs) > 0 || p.RedisLocal || p.Profile == "deep"
}
func (p *Policy) MySQLEnabled() bool {
	return len(p.MySQLDSNs) > 0 || p.MySQLLocal || p.MySQLDocker || p.Profile == "deep"
}
