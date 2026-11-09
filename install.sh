#!/usr/bin/env bash
#
# opensnell installer
#
#   curl -fsSL https://raw.githubusercontent.com/missuo/opensnell-rust/main/install.sh | sudo bash
#
# Run with "help" for commands and options.
#
# Project: https://github.com/missuo/opensnell-rust
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

REPO="missuo/opensnell-rust"
INSTALL_DIR="${OPENSNELL_INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="/etc/opensnell"
ENV_FILE="${CONFIG_DIR}/server.env"
SERVICE_NAME="opensnell"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
BINARIES=(opensnell-server opensnell-client)
TMP_DIR=""
trap '[ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"' EXIT

# ============================================================================
# Output
# ============================================================================
if [ -t 1 ]; then
    RED=$'\033[0;31m' GREEN=$'\033[0;32m' YELLOW=$'\033[1;33m' CYAN=$'\033[0;36m' BOLD=$'\033[1m' NC=$'\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' NC=''
fi
ok()   { echo "${GREEN}[OK]${NC} $*"; }
info() { echo "${CYAN}[INFO]${NC} $*"; }
warn() { echo "${YELLOW}[WARN]${NC} $*" >&2; }
die()  { echo "${RED}[ERROR]${NC} $*" >&2; exit 1; }

usage() {
    cat <<EOF
usage: install.sh [command] [options]

commands:
  install [options]    install the latest release and, on Linux, a systemd
                       service running opensnell-server (default)
  update               update the binaries and restart the service
  uninstall [--purge]  remove the service and binaries (--purge: also the config)
  start | stop | restart | status
  info                 show the server's connection details
  help

install options:
  --version v4|v5|v6                    protocol version [v6]
  --mode default|unshaped|unsafe-raw    v6 encryption mode [default]
  --port <port>                         listen port [random free port]
  --listen <addr:port>                  listen address [0.0.0.0:<port>]
  --psk <psk>                           pre-shared key [random]
  --binaries-only                       only install the binaries

environment: OPENSNELL_INSTALL_DIR [/usr/local/bin], OPENSNELL_RELEASE [latest]
EOF
}

# ============================================================================
# Preflight
# ============================================================================
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required"; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "run as root (e.g. curl -fsSL ... | sudo bash)"
}

has_systemd() { [ "$(uname -s)" = Linux ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

detect_target() {
    local os arch
    case "$(uname -s)" in
        Linux) os=unknown-linux-musl ;;
        Darwin) os=apple-darwin ;;
        *) die "unsupported OS $(uname -s); Windows builds are on https://github.com/${REPO}/releases" ;;
    esac
    case "$(uname -m)" in
        x86_64 | amd64) arch=x86_64 ;;
        aarch64 | arm64) arch=aarch64 ;;
        *) die "unsupported architecture $(uname -m)" ;;
    esac
    echo "${arch}-${os}"
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'
}

# ============================================================================
# Download
# ============================================================================
latest_tag() {
    # The releases/latest redirect needs no API token and has no rate limit.
    local url
    url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest") \
        || die "cannot reach GitHub"
    case "$url" in
        */releases/tag/*) echo "${url##*/}" ;;
        *) die "no release found at https://github.com/${REPO}/releases" ;;
    esac
}

# install_binaries: download, verify and install the release binaries.
install_binaries() {
    need curl
    need tar
    local tag target name tmp want got
    tag="${OPENSNELL_RELEASE:-$(latest_tag)}"
    target=$(detect_target)
    name="opensnell-${tag}-${target}"
    TMP_DIR=$(mktemp -d)
    tmp="$TMP_DIR"

    info "Downloading ${name}.tar.gz"
    local base="https://github.com/${REPO}/releases/download/${tag}"
    curl -fsSL -o "${tmp}/${name}.tar.gz" "${base}/${name}.tar.gz" || die "download failed: ${base}/${name}.tar.gz"
    curl -fsSL -o "${tmp}/SHA256SUMS" "${base}/SHA256SUMS" || die "download failed: ${base}/SHA256SUMS"
    want=$(awk -v f="${name}.tar.gz" '$2 == f || $2 == "*"f {print $1}' "${tmp}/SHA256SUMS")
    got=$(sha256 "${tmp}/${name}.tar.gz")
    [ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch for ${name}.tar.gz"
    ok "Checksum verified"

    tar -xzf "${tmp}/${name}.tar.gz" -C "$tmp"
    mkdir -p "$INSTALL_DIR"
    for bin in "${BINARIES[@]}"; do
        install -m 0755 "${tmp}/${name}/${bin}" "${INSTALL_DIR}/${bin}"
    done
    ok "Installed ${BINARIES[*]} ${tag} to ${INSTALL_DIR}"
}

# ============================================================================
# Server configuration
# ============================================================================
gen_psk() {
    local psk=""
    # 32 alphanumeric characters from the kernel CSPRNG.
    while [ "${#psk}" -lt 32 ]; do
        psk+=$(head -c 64 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')
    done
    echo "${psk:0:32}"
}

port_in_use() {
    if command -v ss >/dev/null 2>&1; then
        ss -Htuln "sport = :$1" 2>/dev/null | grep -q .
    else
        return 1
    fi
}

pick_port() {
    local port
    for _ in $(seq 1 50); do
        port=$((RANDOM % 50000 + 10000))
        port_in_use "$port" || { echo "$port"; return; }
    done
    die "no free port found; pass --port"
}

write_config() {
    local version="$1" mode="$2" listen="$3" psk="$4"
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    (
        umask 077
        cat >"$ENV_FILE" <<EOF
# opensnell-server settings, read by ${SERVICE_FILE}.
OPENSNELL_LISTEN=${listen}
OPENSNELL_PSK=${psk}
OPENSNELL_VERSION=${version}
OPENSNELL_MODE=${mode}
EOF
    )
    ok "Wrote ${ENV_FILE}"
}

write_service() {
    cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=opensnell Snell server
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_DIR}/opensnell-server --listen \${OPENSNELL_LISTEN} --psk \${OPENSNELL_PSK} --version \${OPENSNELL_VERSION} --mode \${OPENSNELL_MODE}
Restart=on-failure
RestartSec=3s
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    ok "Wrote ${SERVICE_FILE}"
}

public_ip() {
    curl -fsS -4 --max-time 5 https://ip.sb 2>/dev/null \
        || curl -fsS -4 --max-time 5 https://ifconfig.me 2>/dev/null \
        || echo "<server-ip>"
}

show_info() {
    [ -r "$ENV_FILE" ] || die "no server config at ${ENV_FILE}; run install first"
    local OPENSNELL_LISTEN OPENSNELL_PSK OPENSNELL_VERSION OPENSNELL_MODE
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    local port="${OPENSNELL_LISTEN##*:}" host version line
    host=$(public_ip | tr -d '[:space:]')
    version="${OPENSNELL_VERSION#v}"
    line="snell, ${host}, ${port}, psk=${OPENSNELL_PSK}, version=${version}, reuse=true"

    echo
    echo "${BOLD}Server${NC}    ${host}:${port}"
    echo "${BOLD}PSK${NC}       ${OPENSNELL_PSK}"
    echo "${BOLD}Version${NC}   ${OPENSNELL_VERSION} (${OPENSNELL_MODE})"
    echo
    echo "${BOLD}Surge${NC}"
    echo "  Proxy = ${line}"
    if [ "$OPENSNELL_MODE" != default ]; then
        echo "  (the client must also use mode ${OPENSNELL_MODE})"
    fi
    echo
    echo "${BOLD}opensnell-client${NC}"
    echo "  opensnell-client --server ${host}:${port} --psk ${OPENSNELL_PSK} --version ${OPENSNELL_VERSION} --mode ${OPENSNELL_MODE}"
    echo
}

# ============================================================================
# Subcommands
# ============================================================================
cmd_install() {
    local version=v6 mode=default port="" listen="" psk="" binaries_only=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --version) version="${2:?}"; shift 2 ;;
            --mode) mode="${2:?}"; shift 2 ;;
            --port) port="${2:?}"; shift 2 ;;
            --listen) listen="${2:?}"; shift 2 ;;
            --psk) psk="${2:?}"; shift 2 ;;
            --binaries-only) binaries_only=1; shift ;;
            *) die "unknown option $1 (see: install.sh help)" ;;
        esac
    done
    case "$version" in
        v4 | v5) [ "$mode" = default ] || die "--mode is a v6 option" ;;
        v6) case "$mode" in default | unshaped | unsafe-raw) ;; *) die "unknown mode $mode" ;; esac ;;
        *) die "unknown version $version (v4, v5 or v6)" ;;
    esac
    [ -z "$psk" ] && psk=$(gen_psk)
    if [ "$version" = v6 ] && { [ "${#psk}" -lt 12 ] || [ "${#psk}" -gt 255 ]; }; then
        die "a v6 PSK must be 12-255 characters"
    fi
    case "$psk" in *[[:space:]]* | *\"* | *\'* | *\$* | *\\*) die "the PSK must not contain whitespace, quotes, \$ or \\" ;; esac

    [ -w "$INSTALL_DIR" ] || [ ! -e "$INSTALL_DIR" ] || require_root
    if [ "$binaries_only" = 1 ] || ! has_systemd; then
        install_binaries
        has_systemd || info "No systemd here: binaries only. Run: opensnell-server --help"
        return
    fi
    require_root
    install_binaries
    if [ -z "$listen" ]; then
        [ -z "$port" ] && port=$(pick_port)
        listen="0.0.0.0:${port}"
    fi
    write_config "$version" "$mode" "$listen" "$psk"
    write_service
    systemctl enable --now "$SERVICE_NAME" >/dev/null 2>&1
    sleep 1
    systemctl is-active --quiet "$SERVICE_NAME" \
        || die "the service did not start; see: journalctl -u ${SERVICE_NAME}"
    ok "Service ${SERVICE_NAME} is running"
    show_info
    info "Open TCP port ${listen##*:} in your firewall if one is active."
}

cmd_update() {
    [ -w "$INSTALL_DIR" ] || require_root
    install_binaries
    if has_systemd && systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl restart "$SERVICE_NAME"
        ok "Restarted ${SERVICE_NAME}"
    fi
}

cmd_uninstall() {
    local purge=0
    [ "${1:-}" = --purge ] && purge=1
    require_root
    if has_systemd && [ -f "$SERVICE_FILE" ]; then
        systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        ok "Removed the ${SERVICE_NAME} service"
    fi
    for bin in "${BINARIES[@]}"; do rm -f "${INSTALL_DIR:?}/${bin}"; done
    ok "Removed ${BINARIES[*]}"
    if [ "$purge" = 1 ]; then
        rm -rf "$CONFIG_DIR"
        ok "Removed ${CONFIG_DIR}"
    elif [ -d "$CONFIG_DIR" ]; then
        info "Kept ${CONFIG_DIR} (use --purge to remove it)"
    fi
}

cmd_service() {
    has_systemd || die "systemd is required for '$1'"
    [ "$1" = status ] || require_root
    systemctl "$1" "$SERVICE_NAME"
}

main() {
    local cmd="${1:-install}"
    [ $# -gt 0 ] && shift
    case "$cmd" in
        --*) cmd_install "$cmd" "$@" ;; # options without a subcommand
        install) cmd_install "$@" ;;
        update) cmd_update ;;
        uninstall) cmd_uninstall "$@" ;;
        start | stop | restart | status) cmd_service "$cmd" ;;
        info) show_info ;;
        help | -h) usage ;;
        *) die "unknown command $cmd (see: install.sh help)" ;;
    esac
}

main "$@"
