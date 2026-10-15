#!/bin/sh
# Serveradar installer.
#
#   sudo ./install.sh                         install from local ./bin or ./dist (after `make dist`)
#   curl -fsSL https://raw.githubusercontent.com/<repo>/main/install.sh | sh
#                                             latest GitHub release, verified; no root -> ~/.local/bin
#   sudo ./install.sh --uninstall             remove only Serveradar-owned files
#
# Env:
#   SERVERADAR_REPO       GitHub owner/repo (default bakhod1r/serveradar)
#   SERVERADAR_BASE_URL   where serveradar-<os>-<arch> and SHA256SUMS live
#   SERVERADAR_VERSION    optional, appended as <base>/<version>/...
#   PREFIX                 default /usr/local
#   SKIP_VERIFY=1          skip checksum (not recommended)
set -eu

NAME=serveradar
REPO=${SERVERADAR_REPO:-bakhod1r/serveradar}
if [ "$(id -u)" -eq 0 ]; then
	PREFIX=${PREFIX:-/usr/local}
	CONF_DIR=/etc/serveradar
	DATA_DIR=/var/lib/serveradar
else # user install, no sudo needed
	PREFIX=${PREFIX:-$HOME/.local}
	CONF_DIR=${XDG_CONFIG_HOME:-$HOME/.config}/serveradar
	DATA_DIR=${XDG_DATA_HOME:-$HOME/.local/share}/serveradar
fi
BIN_DIR="$PREFIX/bin"
SRC_DIR=$(dirname "$0")
SRC_DIR=$(cd "$SRC_DIR" 2>/dev/null && pwd) || SRC_DIR=$(pwd)

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need_root() { :; }

detect() {
	OS=$(uname -s | tr '[:upper:]' '[:lower:]')
	case "$OS" in linux|darwin) ;; *) die "unsupported OS: $OS" ;; esac
	case "$(uname -m)" in
		x86_64|amd64) ARCH=amd64 ;;
		aarch64|arm64) ARCH=arm64 ;;
		*) die "unsupported arch: $(uname -m)" ;;
	esac
	ASSET="$NAME-$OS-$ARCH"
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
	else die "no sha256sum/shasum for verification (set SKIP_VERIFY=1 to bypass)"; fi
}

verify() { # file sumsfile asset
	[ "${SKIP_VERIFY:-0}" = 1 ] && { warn "checksum verification skipped"; return; }
	[ -f "$2" ] || die "SHA256SUMS missing; refusing to install unverified binary"
	want=$(awk -v a="$3" '$2==a || $2=="*"a {print $1}' "$2")
	[ -n "$want" ] || die "no checksum for $3 in SHA256SUMS"
	got=$(sha256 "$1")
	[ "$want" = "$got" ] || die "checksum mismatch for $3"
	say "checksum ok"
}

fetch() { # url out
	if command -v curl >/dev/null 2>&1; then curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then wget -q --https-only -O "$2" "$1"
	else die "need curl or wget"; fi
}

obtain() {
	TMP=$(mktemp -d)
	trap 'rm -rf "$TMP"' EXIT INT TERM
	for d in "$SRC_DIR/dist" "$SRC_DIR/bin"; do
		if [ -f "$d/$ASSET" ]; then
			say "using local $d/$ASSET"
			cp "$d/$ASSET" "$TMP/$NAME"
			if [ -f "$d/SHA256SUMS" ]; then verify "$TMP/$NAME" "$d/SHA256SUMS" "$ASSET"
			else warn "no $d/SHA256SUMS; local build trusted as-is"; fi
			return
		fi
	done
	if [ -n "${SERVERADAR_BASE_URL:-}" ] || [ ! -f "$SRC_DIR/go.mod" ]; then
		if [ -n "${SERVERADAR_BASE_URL:-}" ]; then
			base=${SERVERADAR_BASE_URL%/}
			[ -n "${SERVERADAR_VERSION:-}" ] && base="$base/$SERVERADAR_VERSION"
		elif [ -n "${SERVERADAR_VERSION:-}" ]; then
			base="https://github.com/$REPO/releases/download/$SERVERADAR_VERSION"
		else
			base="https://github.com/$REPO/releases/latest/download"
		fi
		case "$base" in https://*) ;; *) die "SERVERADAR_BASE_URL must be https" ;; esac
		say "downloading $base/$ASSET"
		fetch "$base/$ASSET" "$TMP/$NAME"
		fetch "$base/SHA256SUMS" "$TMP/SHA256SUMS" || true
		verify "$TMP/$NAME" "$TMP/SHA256SUMS" "$ASSET"
		return
	fi
	if command -v go >/dev/null 2>&1 && [ -f "$SRC_DIR/go.mod" ]; then
		say "building from source"
		(cd "$SRC_DIR" && env -u GOROOT CGO_ENABLED=0 go build -ldflags '-s -w' -o "$TMP/$NAME" ./cmd/serveradar)
		return
	fi
	die "no binary found: run 'make dist', or set SERVERADAR_BASE_URL"
}

install_all() {
	need_root "$@"
	detect
	obtain
	"$TMP/$NAME" version >/dev/null 2>&1 || die "binary does not run on this host ($ASSET)"

	say "installing $BIN_DIR/$NAME"
	install -d -m 0755 "$BIN_DIR"
	install -m 0755 "$TMP/$NAME" "$BIN_DIR/$NAME"

	install -d -m 0700 "$CONF_DIR" "$DATA_DIR" "$DATA_DIR/reports"
	if [ ! -f "$CONF_DIR/config.json" ]; then
		say "writing default $CONF_DIR/config.json"
		umask 077
		cat > "$CONF_DIR/config.json" <<'EOF'
{
  "profile": "standard",
  "timeout_sec": 30,
  "concurrency": 6,
  "project_roots": ["/srv", "/opt", "/var/www", "/home", "/root"],
  "project_max_depth": 4,
  "exclude_paths": ["node_modules", ".cache", "vendor", ".venv", "venv"],
  "nginx_roots": ["/etc/nginx"],
  "cert_dirs": ["/etc/letsencrypt/live"],
  "cert_warn_days": 21,
  "disabled_collectors": [],
  "use_nginx_dump": true,
  "show_env_values": false
}
EOF
		chmod 0600 "$CONF_DIR/config.json"
	else
		say "keeping existing $CONF_DIR/config.json"
	fi

	# manifest of owned files for clean uninstall
	printf '%s\n' "$BIN_DIR/$NAME" "$CONF_DIR/config.json" > "$DATA_DIR/.installed"
	chmod 0600 "$DATA_DIR/.installed"
	case ":$PATH:" in *":$BIN_DIR:"*) ;; *) warn "$BIN_DIR not in PATH — add: export PATH=\"$BIN_DIR:\$PATH\"" ;; esac
	[ "$(id -u)" -ne 0 ] && warn "user install: run with sudo for full visibility (sockets, /proc/*/io, cron spools, firewall)"

	say "installed: $("$BIN_DIR/$NAME" version)"
	cat <<EOF

  $NAME                      # TUI (sudo for full data)
  sudo $NAME scan            # terminal summary
  sudo $NAME report --format md --output $DATA_DIR/reports/\$(hostname).md
  $NAME doctor               # tools & permissions

EOF
	missing=""
	for t in ss ip ps docker nginx git systemctl; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
	[ -n "$missing" ] && warn "optional tools missing:$missing (related sections will be partial)"
	return 0
}

uninstall_all() {
	need_root "$@"
	say "removing Serveradar-owned files only"
	rm -f "$BIN_DIR/$NAME"
	if [ -f "$CONF_DIR/config.json" ]; then
		printf 'remove %s/config.json? [y/N] ' "$CONF_DIR"
		read -r a </dev/tty 2>/dev/null || a=n
		[ "$a" = y ] && rm -f "$CONF_DIR/config.json" && rmdir "$CONF_DIR" 2>/dev/null || true
	fi
	rm -f "$DATA_DIR/.installed"
	rmdir "$DATA_DIR/reports" "$DATA_DIR" 2>/dev/null || warn "$DATA_DIR kept (contains reports)"
	say "done. Discovered services were not touched."
}

case "${1:-}" in
	--uninstall|uninstall) uninstall_all "$@" ;;
	-h|--help) sed -n '2,15p' "$0" ;;
	*) install_all "$@" ;;
esac
