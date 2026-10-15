// Package cli wires flags and subcommands to application services.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/application/scan"
	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/domain/policy"
	"github.com/bakhod1r/serveradar/internal/infrastructure/configfile"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
	"github.com/bakhod1r/serveradar/internal/infrastructure/probe"
	"github.com/bakhod1r/serveradar/internal/interfaces/render"
	"github.com/bakhod1r/serveradar/internal/interfaces/tui"
)

const usage = `Serveradar — read-only server discovery & diagnostics

Usage:
  serveradar [tui]                       interactive TUI (default)
  serveradar scan    [flags]             scan, print terminal summary
  serveradar report  --format md|json|html [--output FILE]
  serveradar <section> [flags]           one section: host resources processes network ports
                                          systemd cron tools docker kubernetes nginx tls projects
                                          databases services dbaccess dbconfig postgres mysql redis firewall security
  serveradar exposure                    open-port exposure matrix
  serveradar findings                    findings only
  serveradar doctor                      tools & permissions check
  serveradar version

Flags:
  --profile quick|standard|deep   (default standard)
  --config FILE                   JSON config (default /etc/serveradar/config.json)
  --show-env                      include non-secret container env values (secrets still masked)
  --timeout SEC                   per-collector timeout
  --format md|json|html  --output FILE

Database inspection (read-only, metadata only, opt-in; all on with --profile deep):
  --db                            all of the below for local + docker
  --pg DSN | --pg-local | --pg-docker           e.g. --pg 'postgres://user@host:5432/postgres'
  --mysql DSN | --mysql-local | --mysql-docker  e.g. --mysql 'mysql://user@host:3306/'
  --redis URL | --redis-local                   e.g. --redis 'redis://:pass@127.0.0.1:6379'
  Env (keeps secrets out of ps/history): SERVERADAR_PG_DSN, SERVERADAR_MYSQL_DSN, SERVERADAR_REDIS_URL,
       SERVERADAR_RABBITMQ_URL (management API, e.g. http://monitor:PASS@127.0.0.1:15672)
  --pg-docker / --mysql-docker run the DB client via "docker exec" inside the container.
`

func Main(args []string) int {
	cmd := "tui"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	profile := fs.String("profile", "", "")
	cfgPath := fs.String("config", "", "")
	format := fs.String("format", "md", "")
	output := fs.String("output", "", "")
	showEnv := fs.Bool("show-env", false, "")
	timeout := fs.Int("timeout", 0, "")
	var pgDSNs, myDSNs, redisURLs []string
	fs.Func("pg", "", func(v string) error { pgDSNs = append(pgDSNs, v); return nil })
	fs.Func("mysql", "", func(v string) error { myDSNs = append(myDSNs, v); return nil })
	fs.Func("redis", "", func(v string) error { redisURLs = append(redisURLs, v); return nil })
	pgLocal := fs.Bool("pg-local", false, "")
	pgDocker := fs.Bool("pg-docker", false, "")
	myLocal := fs.Bool("mysql-local", false, "")
	myDocker := fs.Bool("mysql-docker", false, "")
	redisLocal := fs.Bool("redis-local", false, "")
	allDB := fs.Bool("db", false, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	pol, err := configfile.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 2
	}
	if *profile != "" {
		pol.Profile = *profile
	}
	if *showEnv {
		pol.ShowEnv = true
	}
	// DSNs from env keep passwords out of shell history and `ps`
	for _, e := range []struct {
		env string
		dst *[]string
	}{{"SERVERADAR_PG_DSN", &pgDSNs}, {"SERVERADAR_MYSQL_DSN", &myDSNs}, {"SERVERADAR_REDIS_URL", &redisURLs}} {
		if v := os.Getenv(e.env); v != "" {
			*e.dst = append(*e.dst, strings.Split(v, ",")...)
		}
	}
	pol.PGDSNs = append(pol.PGDSNs, pgDSNs...)
	pol.MySQLDSNs = append(pol.MySQLDSNs, myDSNs...)
	pol.RedisURLs = append(pol.RedisURLs, redisURLs...)
	pol.PGLocal = pol.PGLocal || *pgLocal || *allDB
	pol.PGDocker = pol.PGDocker || *pgDocker || *allDB
	pol.MySQLLocal = pol.MySQLLocal || *myLocal || *allDB
	pol.MySQLDocker = pol.MySQLDocker || *myDocker || *allDB
	pol.RedisLocal = pol.RedisLocal || *redisLocal || *allDB
	if *timeout > 0 {
		pol.TimeoutSec = *timeout
	}
	pol.Timeout = secs(pol.TimeoutSec)
	if err := pol.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	svc := scan.Service{Catalog: probe.Catalog{}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	switch cmd {
	case "help", "-h", "--help":
		fmt.Print(usage)
	case "version":
		fmt.Println("serveradar", scan.ToolVersion, "schema", inventory.SchemaVersion)
	case "tui":
		if err := tui.Run(svc, pol); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	case "doctor":
		doctor(svc, pol)
	case "scan", "summary":
		r := svc.Run(ctx, pol, progress)
		render.Terminal(os.Stdout, r)
	case "findings":
		r := svc.Run(ctx, pol, progress)
		render.TerminalFindings(os.Stdout, r)
	case "exposure":
		pol.Only = []string{"ports", "docker", "firewall"}
		r := svc.Run(ctx, pol, nil)
		fmt.Print(render.ExposureMD(r))
	case "report":
		r := svc.Run(ctx, pol, progress)
		return write(r, *format, *output)
	default:
		if _, ok := find(svc, cmd); !ok {
			fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
			return 2
		}
		pol.Only = []string{cmd}
		switch cmd { // asking for a datastore section is the opt-in for local + docker inspection
		case "postgres":
			pol.PGLocal, pol.PGDocker = true, true
		case "mysql":
			pol.MySQLLocal, pol.MySQLDocker = true, true
		case "redis":
			pol.RedisLocal = true
		case "dbconfig":
			pol.PGDocker, pol.MySQLDocker, pol.RedisLocal = true, true, true
		}
		r := svc.Run(ctx, pol, nil)
		fmt.Print(render.Section(r, cmd))
	}
	return 0
}

func write(r *inventory.Report, format, output string) int {
	var w io.Writer = os.Stdout
	if output != "" {
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // reports may be sensitive
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer f.Close()
		w = f
	}
	switch format {
	case "json":
		if err := render.JSON(w, r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	case "md", "markdown":
		render.Markdown(w, r)
	case "html":
		if err := render.HTML(w, r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown format", format)
		return 2
	}
	if output != "" {
		fmt.Fprintln(os.Stderr, "wrote", output)
	}
	return 0
}

func progress(name string, r *inventory.CollectorResult) {
	fmt.Fprintf(os.Stderr, "  %-11s %-12s %5dms %s\n", r.Status, name, r.DurationMs, r.Error)
}

func find(svc scan.Service, name string) (inventory.Probe, bool) {
	for _, p := range svc.Catalog.Probes() {
		if p.Name == name {
			return p, true
		}
	}
	return inventory.Probe{}, false
}

func doctor(svc scan.Service, pol *policy.Policy) {
	fmt.Printf("user uid=%d root=%v config=%s profile=%s\n\n", os.Geteuid(), os.Geteuid() == 0, pol.Source, pol.Profile)
	tools := []struct{ bin, why string }{
		{"ps", "processes"}, {"ss", "ports (linux)"}, {"lsof", "ports (macOS fallback)"}, {"ip", "routes"},
		{"systemctl", "services"}, {"docker", "containers"}, {"nginx", "vhost dump (nginx -T)"}, {"git", "repo dirty state"},
		{"du", "largest directories"}, {"crontab", "user cron"}, {"ufw", "firewall"}, {"nft", "firewall"}, {"iptables", "firewall"},
		{"kubectl", "cluster context"}, {"psql", "deep PG (future)"}, {"mysql", "deep MySQL (future)"}, {"redis-cli", "deep Redis (future)"},
		{"mongosh", "deep MongoDB (future)"}, {"nmap", "authorized remote scan (future)"},
	}
	for _, t := range tools {
		mark := "✗ missing"
		if execx.Has(t.bin) {
			mark = "✓"
		}
		fmt.Printf("  %-10s %-10s %s\n", t.bin, mark, t.why)
	}
	if os.Geteuid() != 0 {
		fmt.Println("\nNot root: other users' socket owners, /proc/*/io, cron spools, firewall rules, some configs hidden. Re-run with sudo for full data.")
	}
	fmt.Println("\nCollectors for profile", pol.Profile+":")
	for _, p := range svc.Select(pol) {
		fmt.Println("  -", p.Name, "—", p.Title)
	}
}

func secs(n int) time.Duration { return time.Duration(n) * time.Second }
