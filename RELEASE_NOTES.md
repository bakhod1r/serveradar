# Serveradar v0.1.1

## Fixes

- TUI crashed on start ("assignment to entry in nil map"): scan state was set on a copy of the model.
- install.sh: binary is made executable before the self-check, and the check runs from the install dir (works with noexec /tmp).
- Linux: processes and listening sockets read from /proc (works without ps/ss, e.g. BusyBox); bind-mounted files no longer listed as disks.

---

# Serveradar v0.1.0

First public release. Read-only server discovery, inventory and diagnostics in a single static binary with a TUI and HTML/Markdown/JSON reports.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/install.sh | sh        # user install (~/.local/bin)
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/install.sh | sudo sh   # system install (/usr/local/bin)
```

Binaries: linux amd64/arm64, darwin amd64/arm64. Verify with `SHA256SUMS`.

## Highlights

- **TUI** (`serveradar`) with live scan progress, sections, filter, exports (`m` .md, `J` .json, `H` .html)
- **Reports**: HTML (dashboard charts, grouped collapsible sections, search, sortable/filterable tables, diagrams), Markdown (collapsible, text-bar charts, Mermaid), JSON (schema 1.0)
- **System**: host/OS, CPU/RAM/swap/disk/inodes, who uses what (by process, app, user, systemd unit/container, disk IO), largest directories
- **Processes, systemd** (unit files, ExecStart, User, hardening, risks), **cron/timers** (human schedule, next run, risks)
- **Network**: interfaces, routes, DNS, listening sockets with owners, established peers, open-port exposure matrix with firewall/Docker awareness
- **Docker**: containers (inspect, networks, mounts, env keys), images, networks, volumes, stats, Mermaid network diagram
- **Data stores**: PostgreSQL, MySQL/MariaDB, Redis deep read-only inspection (databases, sizes, tables, users, access rules); 50+ engines detected; config files read with secrets masked; live open/closed + anonymous auth handshake
- **Brokers & services**: Kafka, RabbitMQ, Vault, Consul, etcd, NATS, Elasticsearch/OpenSearch, ClickHouse, MinIO, InfluxDB
- **DevOps tools**: 85+ (CI/CD, registries, monitoring, logging, proxies, IaC, cloud CLIs, VPN, security)
- **Findings** with severity, evidence, confidence, impact and next step

## Safety

Read-only. No service restarts, no config changes, no data reads, no credential guessing. Secrets are redacted. Database inspection and `docker exec` are opt-in (`--db` or `--profile deep`).

## Known limitations

- Run with `sudo` for full visibility (other users' sockets, /proc/*/io, cron spools, firewall rules).
- MongoDB: config-level only (no authenticated inspection yet).
- No remote Nmap scanning or report diff yet.
