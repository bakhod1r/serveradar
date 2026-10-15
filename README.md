# Serveradar

Read-only server discovery, inventory and diagnostics for Linux (macOS works for development). Single static Go binary with an interactive TUI.

```bash
make build              # bin/serveradar
make linux              # static linux amd64/arm64 binaries
./bin/serveradar       # TUI
sudo ./bin/serveradar  # TUI with full visibility (other users' sockets, /proc/*/io, cron spools, firewall)
```

## Commands

| Command | What |
|---|---|
| `serveradar` / `tui` | Interactive TUI: sections, findings, Docker network diagram, relationships, filter, export |
| `scan` | Terminal summary + findings |
| `report --format md\|json --output FILE` | Full report (file mode 0600) |
| `host resources processes network ports systemd cron docker kubernetes nginx tls projects databases firewall security` | One section as Markdown |
| `findings` | Findings only |
| `doctor` | Available tools, permissions, collectors per profile |

Flags: `--profile quick|standard|deep`, `--config FILE`, `--timeout SEC`, `--show-env`.

Database inspection (read-only, metadata only; `--profile deep` or TUI key `d` turns all on):

```bash
serveradar report --db --format md --output full.md        # everything: local + docker PG/MySQL/Redis
serveradar postgres | mysql | redis                        # one engine, local + docker
SERVERADAR_PG_DSN='postgres://ro@db1:5432/postgres' serveradar postgres
serveradar mysql --mysql 'mysql://ro@db2:3306/'
serveradar redis --redis 'redis://:PASS@10.0.0.5:6379'
serveradar exposure                                        # open-port matrix
```

- **PostgreSQL**: every database with size, owner, encoding, connections, schemas, extensions, object counts, 25 largest tables (size, rows, dead tuples, vacuum), roles + memberships, pg_hba rules in plain words, listen_addresses/ssl exposure, sessions, replication, slots
- **MySQL/MariaDB**: every database with data/index/free size, tables, rows, engines, views/routines/triggers/events, tables without PK, 50 largest tables, users@hosts with auth plugin, empty-password check, global and schema privileges, connections, replica/binlog/Group Replication/Galera, analysis (fragmentation, buffer-pool hit ratio, slow queries, tmp disk tables)
- **Redis**: version, role, memory, eviction, persistence, keyspace, clients by IP, ACL users (secrets stripped), config, cluster, replicas
- Read-only: `BEGIN READ ONLY` / `transaction_read_only` / `statement_timeout`; Redis only sends an allowlist of read commands. Password hashes, query text and row data are never read. `--pg-docker`/`--mysql-docker` run the client with `docker exec`, and the MySQL root password is read from the container env inside the container only.

TUI keys: `↑/↓` section · `PgUp/PgDn` scroll · `/` filter · `r` rescan · `p` cycle profile · `m` save .md · `J` save .json · `q` quit.

## What it collects

- **Host**: OS, kernel, CPU, load, RAM/swap, filesystems + inodes, uptime, virtualization, reboot-required
- **Resources**: top CPU / RAM / disk-IO processes; usage grouped by application, user, systemd unit / container cgroup; largest directories; `docker stats`; per-service memory/CPU/restarts
- **Processes**: full list, command lines redacted
- **Network & IPs**: interfaces, local IPs, routes, DNS, TCP state counts, listening sockets with owner, established remote peers
- **Scheduled jobs**: /etc/crontab, cron.d, user spools, `crontab -l`, cron.{hourly,daily,...}, systemd timers, launchd, Supervisor/PM2
- **Docker**: containers (inspect: ports, networks + IPs, mounts, env keys, caps, restart/health), images, networks, volumes, compose projects, Mermaid network diagram
- **Databases**: PostgreSQL, PgBouncer, Patroni, MySQL, MariaDB, ProxySQL, Redis, Sentinel, Valkey, **MongoDB** (bindIp, port, replSet, sharding, authorization, TLS), ClickHouse, Elasticsearch, OpenSearch, RabbitMQ, Kafka, ZooKeeper, etcd, Memcached, NATS, Cassandra, InfluxDB, MinIO — by process, port, container image, config file
- **Nginx**: vhosts, listens, server_names, proxy_pass, upstreams, TLS certs (via `nginx -T`, fallback file parse)
- **TLS**: certificate subject/SANs/issuer/expiry, renewal tooling
- **Projects**: Git repos (branch, commit, dirty, redacted remote), markers, deploy manifests, `.env` presence/permissions
- **Clusters**: Kubernetes/k3s/MicroK8s/RKE2 signals, kubectl context, Swarm state
- **Security**: sshd policy, sensitive file permissions, privileged groups, login users, firewall rules
- **Findings**: severity, evidence, confidence, impact, next step. **Relationship graph** with confidence.

## Safety

- Never restarts, modifies, prunes, or writes to the host (except report files you ask for, mode 0600).
- Fixed argv only, no shell. Every collector has a timeout; failures produce partial reports.
- Secrets redacted from command lines, cron, git remotes. Container env: names only by default; `--show-env` shows values but still masks keys that look secret. `.env` contents are never read. Private keys never read.
- Wildcard binds are reported as context, not as proof of internet exposure.

## Architecture (DDD)

```
cmd/serveradar/                 entrypoint
internal/
  domain/                        pure model + rules, no I/O
    inventory/   entities, value objects, report aggregate, Probe port
    policy/      scan policy value object (profile, scope, limits)
    finding/     finding rules (domain service)
    topology/    correlation + Mermaid graphs (domain service)
  application/
    scan/        use case: select probes, run with deps/timeouts, correlate, evaluate
  infrastructure/
    probe/       Probe adapters (ps, ss/lsof, docker, nginx, /proc, files…)
    execx/       safe subprocess runner
    redact/      secret redaction
    configfile/  JSON config loader
  interfaces/
    cli/ tui/ render/ (markdown, json, terminal)
```

Config: `/etc/serveradar/config.json` or `~/.config/serveradar/config.json`:

```json
{ "profile": "standard", "timeout_sec": 30, "project_roots": ["/srv", "/opt"], "cert_warn_days": 21,
  "disabled_collectors": ["firewall"], "show_env_values": false }
```
