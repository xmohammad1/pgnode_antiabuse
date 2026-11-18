#!/usr/bin/env bash
# ==============================================================================
# pgnode anti-abuse firewall (UFW) - v2
# For busy PasarGuard / Xray nodes (host networking) on Hetzner.
#
#   inbound : deny by default; SSH (rate-limited), proxy ports, node API
#   outbound: on the public NIC only, reject what produces Hetzner abuse
#             reports (private/bogon destinations = "NetScan", known sensor
#             ranges, SMTP/telnet/SMB) and throttle brute-force fan-out.
#
# Usage : sudo bash v2.sh
# Env   : PANEL_IPS="1.2.3.4 2a01::1"  only these may reach the node API port
#         WAN_IF=eth0                    public NIC (default: auto-detect)
#         SSH_LIMIT=0                    plain allow instead of rate limit
#         DRY_RUN=1                      print the plan, change nothing
# ==============================================================================
set -Eeuo pipefail

# ------------------------------- configuration --------------------------------

PANEL_IPS="${PANEL_IPS:-}"
NODE_API_PORT="${NODE_API_PORT:-62050}"
WAN_IF="${WAN_IF:-}"
SSH_LIMIT="${SSH_LIMIT:-1}"
DRY_RUN="${DRY_RUN:-0}"

# Public proxy ports: "443" opens tcp+udp, "443/tcp" only tcp.
# 53 and 123 are left out on purpose: outbound DNS/NTP need no inbound rule
# (replies come back as ESTABLISHED). An open 53/123 only matters when a real
# DNS/NTP daemon listens, and that is exactly what gets "open resolver" abuse
# reports. Add them only for an Xray inbound on those ports.
ALLOWED_PORTS=(
    80 443 2096 8443 8080 42542 42538 3350 2083
    8880 2052 2082 2086 2095 2053 2087 3131
)

# Must never leave the public NIC (Hetzner "NetScan" reports).
BOGONS_V4=(
    0.0.0.0/8 10.0.0.0/8 25.0.0.0/8 100.64.0.0/10 172.16.0.0/12
    192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15
    198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
)
BOGONS_V6=(fc00::/7 fec0::/10 2001:db8::/32)

# Sensor / honeypot ranges taken from abuse reports. Append the destination
# ranges of every new Hetzner abuse mail here.
SENSOR_NETS=(
    102.65.81.0/24 102.130.88.0/24 102.192.167.0/24 102.193.10.0/24
    102.195.124.0/24 102.197.178.0/24 102.214.134.0/24 151.139.128.0/24
    185.121.225.0/24 205.185.208.0/24 216.218.185.0/24 5.79.71.0/24
    89.35.131.0/24 93.88.205.0/24
)

# Outbound ports end users never need but spammers and worms do.
BLOCKED_OUT=(25/tcp 23/tcp 2323/tcp 135:139/tcp 135:139/udp 445/tcp)

# Brute-force targets: new outbound connections are throttled, not blocked.
BF_PORTS="21,22,2222,3389,5900,5555,1433,3306,5432,6379,27017,8291"
BF_TARGET_RATE="20/minute"; BF_TARGET_BURST=40   # per destination ip:port
BF_PORT_RATE="60/minute";   BF_PORT_BURST=120    # per port, all destinations

# A public non-proxy listener on one of these is an amplification reflector.
REFLECTION_PORTS=" 19 53 111 123 161 389 1900 11211 "
PROXY_PROC_RE='"(xray|sing-box|hysteria|tuic-server)"'

THROTTLE_FILES=(/etc/ufw/before.rules /etc/ufw/before6.rules)

# --------------------------------- helpers ------------------------------------

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[+]${NC} $*"; }
step() { echo -e "${YELLOW}[*]${NC} $*"; }
warn() { echo -e "${RED}[!]${NC} $*" >&2; }
die()  { warn "$*"; exit 1; }

trap 'warn "aborted at line $LINENO ($BASH_COMMAND). UFW may be left disabled: fix and re-run."' ERR

# ufw with stdout silenced; in dry-run only print the command.
ufw_q() {
    if [ "$DRY_RUN" = 1 ]; then echo "    ufw $*"; else ufw "$@" >/dev/null; fi
}

# Any other state-changing command.
run() {
    if [ "$DRY_RUN" = 1 ]; then echo "    $*"; else "$@"; fi
}

is_v6()      { [[ $1 == *:* ]]; }
valid_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

# default_route_field <word> <-4|-6>: the token after <word> in the default route
default_route_field() {
    ip -o "$2" route show default 2>/dev/null \
        | awk -v k="$1" '{for (i = 1; i < NF; i++) if ($i == k) {print $(i + 1); exit}}'
}

# -------------------------------- detection -----------------------------------

detect_network() {
    [ -n "$WAN_IF" ] || WAN_IF="$(default_route_field dev -4 || true)"
    [ -n "$WAN_IF" ] || WAN_IF="$(default_route_field dev -6 || true)"
    [ -n "$WAN_IF" ] || die "cannot detect the public interface; re-run with WAN_IF=<iface>"
    if [ ! -e "/sys/class/net/$WAN_IF" ]; then
        [ "$DRY_RUN" = 1 ] || die "interface '$WAN_IF' does not exist"
        warn "interface '$WAN_IF' not found (dry-run, continuing)"
    fi
    GW4="$(default_route_field via -4 || true)"
    HAS_V6=0
    if [ -d /proc/sys/net/ipv6 ]; then HAS_V6=1; fi
    # Upstream resolvers stay reachable even if they sit in a private range.
    DNS_SERVERS="$(cat /etc/resolv.conf /run/systemd/resolve/resolv.conf 2>/dev/null \
        | awk '$1 == "nameserver" {print $2}' \
        | grep -vE '^(127\.|::1$|fe80:)' | sort -u | tr '\n' ' ' || true)"
}

# Every port sshd really serves, so enabling UFW can never lock us out.
detect_ssh_ports() {
    local raw p lo=32768 hi=60999
    read -r lo hi 2>/dev/null </proc/sys/net/ipv4/ip_local_port_range || true
    raw="$( {
        sshd -T 2>/dev/null | awk '$1 == "port" {print $2}'
        # Ubuntu 24.04+ socket activation: the port lives in ssh.socket
        systemctl show -p Listen ssh.socket sshd.socket 2>/dev/null \
            | sed -nE 's/.*:([0-9]+) \(Stream\).*/\1/p'
        # listening sockets plus the sessions open right now (ours included);
        # ephemeral ports are skipped, those are `ssh -D/-L` forwards
        ss -Hltnp 2>/dev/null; ss -Htnp state established 2>/dev/null
    } 2>/dev/null | awk -v lo="$lo" -v hi="$hi" '
        /^[0-9]+$/ {print; next}
        /"sshd/ {for (i = 1; i <= NF; i++) if ($i ~ /:[0-9]+$/) {
            n = split($i, a, ":"); p = a[n] + 0
            if (p < lo || p > hi) print p
            break
        }}' || true )"
    if [ -n "${SSH_CONNECTION:-}" ]; then raw+=" ${SSH_CONNECTION##* }"; fi
    SSH_PORTS=()
    for p in $raw; do
        valid_port "$p" || continue
        p=$((10#$p))
        [[ " ${SSH_PORTS[*]} " == *" $p "* ]] || SSH_PORTS+=("$p")
    done
    if [ ${#SSH_PORTS[@]} -eq 0 ]; then
        SSH_PORTS=(22)
        warn "SSH port not detected, assuming 22"
    fi
}

# Outbound rules live in the OUTPUT chain; a Docker-bridged xray skips it.
check_xray_netns() {
    local pid
    pid="$(pgrep -xo xray 2>/dev/null || true)"
    if [ -z "$pid" ]; then
        warn "xray is not running; cannot verify it uses host networking"
        return 0
    fi
    if [ "$(readlink "/proc/$pid/ns/net" 2>/dev/null)" != "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then
        warn "xray (pid $pid) runs in its own network namespace (Docker bridge?)."
        warn "Its traffic bypasses every outbound rule here: use network_mode: host."
    fi
    return 0
}

# Public, non-proxy listeners on port $1 (empty output = safe to open).
risky_listeners() {
    ss -Hlntup 2>/dev/null | awk -v p="$1" '{
        for (i = 1; i <= NF; i++) if ($i ~ (":" p "$")) {
            if ($i ~ /^(127\.|\[::1\]|::1:|\[::ffff:127\.)/) next
            print; next
        }
    }' | grep -vE "$PROXY_PROC_RE" || true
}

# --------------------------------- actions ------------------------------------

install_ufw() {
    command -v ufw >/dev/null 2>&1 && return 0
    command -v apt-get >/dev/null 2>&1 || die "ufw is missing and apt-get is unavailable"
    step "Installing ufw"
    run apt-get update -qq
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw
}

set_ufw_defaults() {
    local d=/etc/default/ufw
    [ -f "$d" ] || return 0
    if [ "$HAS_V6" = 1 ]; then run sed -i 's/^IPV6=.*/IPV6=yes/' "$d"; fi
    # v1 made ufw re-apply /etc/sysctl.conf on start; keep that, but never
    # point ufw at a file that does not exist (fresh Debian 13 has none).
    if [ -f /etc/sysctl.conf ]; then
        run sed -i 's|^IPT_SYSCTL=.*|IPT_SYSCTL=/etc/sysctl.conf|' "$d"
    else
        run sed -i 's|^IPT_SYSCTL=.*|IPT_SYSCTL=/etc/ufw/sysctl.conf|' "$d"
    fi
}

apply_inbound() {
    local p entry ip
    step "Inbound: deny by default"
    for p in "${SSH_PORTS[@]}"; do
        if [ "$SSH_LIMIT" = 1 ]; then ufw_q limit "$p/tcp"; else ufw_q allow "$p/tcp"; fi
        info "SSH $p/tcp"
    done
    if [ -n "$PANEL_IPS" ]; then
        for ip in $PANEL_IPS; do
            if is_v6 "$ip" && [ "$HAS_V6" != 1 ]; then warn "skip $ip: IPv6 is off"; continue; fi
            ufw_q allow proto tcp from "$ip" to any port "$NODE_API_PORT"
            info "node API $NODE_API_PORT/tcp from $ip only"
        done
    else
        ufw_q allow "$NODE_API_PORT/tcp"
        warn "node API $NODE_API_PORT/tcp is open to the world: set PANEL_IPS"
    fi
    for entry in "${ALLOWED_PORTS[@]}"; do
        p="${entry%%/*}"
        if [[ $REFLECTION_PORTS == *" $p "* ]] && [ -n "$(risky_listeners "$p")" ]; then
            warn "NOT opening $entry: a non-proxy service listens on it publicly (reflector)"
            continue
        fi
        ufw_q allow "$entry"
    done
    info "proxy ports: ${ALLOWED_PORTS[*]}"
}

apply_outbound() {
    local net e ns
    step "Outbound on $WAN_IF: allow by default, reject abuse traffic"
    # Hetzner Cloud's gateway / DHCP server is 172.31.1.1, inside 172.16.0.0/12.
    if [ -n "$GW4" ]; then ufw_q allow out on "$WAN_IF" to "$GW4"; fi
    for ns in $DNS_SERVERS; do
        if is_v6 "$ns" && [ "$HAS_V6" != 1 ]; then continue; fi
        ufw_q allow out on "$WAN_IF" to "$ns" port 53
    done
    # reject (not deny): xray gets an instant error instead of a socket
    # hanging in SYN_SENT until its dial timeout, thousands of times a minute.
    for net in "${BOGONS_V4[@]}" "${SENSOR_NETS[@]}"; do
        ufw_q reject out on "$WAN_IF" to "$net"
    done
    if [ "$HAS_V6" = 1 ]; then
        for net in "${BOGONS_V6[@]}"; do ufw_q reject out on "$WAN_IF" to "$net"; done
    fi
    for e in "${BLOCKED_OUT[@]}"; do
        ufw_q reject out on "$WAN_IF" to any port "${e%/*}" proto "${e#*/}"
    done
    info "rejected: ${#BOGONS_V4[@]} bogon v4, ${#BOGONS_V6[@]} bogon v6, ${#SENSOR_NETS[@]} sensor nets, ports ${BLOCKED_OUT[*]}"
}

# iptables-restore lines for ufw's before*.rules ($1 = ufw | ufw6).
throttle_block() {
    local c="$1-before-output" t=pgaa_tgt g=pgaa_port m
    if [ "$1" = ufw6 ]; then t=pgaa_tgt6; g=pgaa_port6; fi
    m="-o $WAN_IF -p tcp -m multiport --dports $BF_PORTS -m conntrack --ctstate NEW"
    m+=" -m hashlimit --hashlimit-htable-max 65536 --hashlimit-htable-expire 300000"
    cat <<EOF
# pgnode-antiabuse BEGIN: throttle outbound brute-force / scan fan-out
-A $c $m --hashlimit-name $t --hashlimit-mode dstip,dstport --hashlimit-above $BF_TARGET_RATE --hashlimit-burst $BF_TARGET_BURST -j REJECT --reject-with tcp-reset
-A $c $m --hashlimit-name $g --hashlimit-mode dstport --hashlimit-above $BF_PORT_RATE --hashlimit-burst $BF_PORT_BURST -j REJECT --reject-with tcp-reset
# pgnode-antiabuse END
EOF
}

# ufw reset restores stock before*.rules, so inserting again is idempotent.
inject_throttle() {
    local f chain
    step "Outbound throttle on tcp/{$BF_PORTS}: $BF_TARGET_RATE per target, $BF_PORT_RATE per port"
    for f in "${THROTTLE_FILES[@]}"; do
        chain=ufw
        if [[ $f == *6.rules ]]; then chain=ufw6; fi
        if [ "$chain" = ufw6 ] && [ "$HAS_V6" != 1 ]; then continue; fi
        if [ "$DRY_RUN" = 1 ]; then
            echo "    insert before COMMIT in $f:"
            throttle_block "$chain" | sed 's/^/      /'
            continue
        fi
        if [ ! -f "$f" ]; then warn "$f missing, throttle skipped"; continue; fi
        cp -p "$f" "$f.pgaa-orig"
        BLOCK="$(throttle_block "$chain")" awk '
            /^# pgnode-antiabuse BEGIN/ {skip = 1}
            skip {if (/^# pgnode-antiabuse END/) skip = 0; next}
            !done && /^COMMIT/ {print ENVIRON["BLOCK"]; done = 1}
            {print}' "$f.pgaa-orig" >"$f"
        grep -q '^# pgnode-antiabuse BEGIN' "$f" || warn "no COMMIT line in $f, throttle not added"
    done
}

restore_throttle() {
    local f
    for f in "${THROTTLE_FILES[@]}"; do
        if [ -f "$f.pgaa-orig" ]; then cp -p "$f.pgaa-orig" "$f"; fi
    done
}

enable_ufw() {
    step "Enabling UFW"
    if [ "$DRY_RUN" = 1 ]; then echo "    ufw --force enable"; return 0; fi
    if ! ufw --force enable >/dev/null; then
        warn "UFW refused the throttle rules; enabling without them"
        restore_throttle
        ufw --force enable >/dev/null
    fi
    systemctl enable ufw >/dev/null 2>&1 || true
}

# A full conntrack table drops new connections for every user, silently.
tune_conntrack() {
    local mem_mb target cur
    mem_mb="$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null || true)"
    [ -n "$mem_mb" ] || return 0
    target=$(( mem_mb * 128 ))
    (( target >= 262144 )) || target=262144
    (( target <= 2097152 )) || target=2097152
    cur="$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)"
    (( cur < target )) || return 0
    step "Raising nf_conntrack_max $cur -> $target (~300 B per used entry)"
    if [ "$DRY_RUN" = 1 ]; then return 0; fi
    echo nf_conntrack >/etc/modules-load.d/pgnode-antiabuse.conf
    echo "net.netfilter.nf_conntrack_max = $target" >/etc/sysctl.d/90-pgnode-antiabuse.conf
    sysctl -q -w "net.netfilter.nf_conntrack_max=$target" \
        || warn "could not set nf_conntrack_max now; it applies after reboot"
}

# ----------------------------------- main -------------------------------------

main() {
    if [ "$DRY_RUN" = 1 ]; then
        warn "DRY RUN: nothing will be changed"
    elif [ "$EUID" -ne 0 ]; then
        die "run as root: sudo bash $0"
    fi
    install_ufw
    detect_network
    detect_ssh_ports
    check_xray_netns
    info "public NIC   : $WAN_IF (gateway ${GW4:-none}, IPv6 $([ "$HAS_V6" = 1 ] && echo on || echo off))"
    info "SSH port(s)  : ${SSH_PORTS[*]}"
    info "DNS upstream : ${DNS_SERVERS:-none}"

    set_ufw_defaults
    step "Resetting UFW (old rules are backed up in /etc/ufw)"
    ufw_q --force reset
    ufw_q default deny incoming
    ufw_q default allow outgoing
    apply_inbound
    apply_outbound
    ufw_q logging off   # a busy node would flood the kernel log
    inject_throttle
    enable_ufw
    tune_conntrack

    info "Done. Keep this SSH session open and test a NEW login before closing it."
    if [ "$DRY_RUN" != 1 ]; then ufw status verbose; fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
