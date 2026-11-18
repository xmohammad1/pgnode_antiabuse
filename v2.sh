#!/usr/bin/env bash
# ==============================================================================
# pgnode anti-abuse firewall (UFW) - v2
# For busy PasarGuard / Xray nodes (pg-node, Docker host networking) on Hetzner.
#
#   inbound : deny by default; SSH (rate-limited), proxy ports (list below +
#             every port the running xray serves), pg-node API ports
#   outbound: on the public NIC only, reject what produces Hetzner abuse
#             reports (private/bogon destinations = "NetScan", known sensor
#             ranges, SMTP/telnet/SMB) and throttle brute-force fan-out.
#   conntrack: sized and timed so tracking every flow never drops or stalls one.
#
# Usage : sudo bash v2.sh
# Env   : PANEL_IPS="1.2.3.4 2a01::1"  only these may reach the node API ports
#         NODE_API_PORTS="62050 62051"   default: SERVICE_PORT / API_PORT read
#                                        from /opt/*/.env (pg-node), else 62050
#         EXTRA_PORTS="51820/udp 9000"   more inbound ports ("p" = tcp+udp)
#         AUTO_PORTS=0                   don't open the ports xray listens on
#         WAN_IF=eth0                    public NIC (default: auto-detect)
#         SSH_LIMIT=0                    plain allow instead of rate limit
#         DRY_RUN=1                      print the plan, change nothing
# ==============================================================================
set -Eeuo pipefail

# ------------------------------- configuration --------------------------------

PANEL_IPS="${PANEL_IPS:-}"
NODE_API_PORTS="${NODE_API_PORTS:-${NODE_API_PORT:-}}"
EXTRA_PORTS="${EXTRA_PORTS:-}"
AUTO_PORTS="${AUTO_PORTS:-1}"
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
# Every user leaves through the node's IP, so both budgets are node-wide.
BF_PORTS="${BF_PORTS:-21,22,2222,3389,5900,5555,1433,3306,5432,6379,27017,8291}"
BF_PORT_RATE="${BF_PORT_RATE:-60/minute}"      # per port, all destinations
BF_PORT_BURST="${BF_PORT_BURST:-120}"
BF_TARGET_RATE="${BF_TARGET_RATE:-20/minute}"  # per destination ip:port
BF_TARGET_BURST="${BF_TARGET_BURST:-40}"

# A public non-proxy listener on one of these is an amplification reflector.
REFLECTION_PORTS=" 19 53 111 123 161 389 1900 11211 "
PROXY_PROC_RE='"(xray|sing-box|hysteria|tuic-server)"'

THROTTLE_FILES=(/etc/ufw/before.rules /etc/ufw/before6.rules)
GUARD_CHAIN=pgaa-guard
CT_PROC=/proc/sys/net/netfilter
CT_HASHSIZE=/sys/module/nf_conntrack/parameters/hashsize
SYSCTL_FILE=/etc/sysctl.d/90-pgnode-antiabuse.conf
MODULES_FILE=/etc/modules-load.d/pgnode-antiabuse.conf
MODPROBE_FILE=/etc/modprobe.d/pgnode-antiabuse.conf

# --------------------------------- helpers ------------------------------------

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
# Printing never fails the run: it must go on even if the SSH session drops.
say()  { printf '%b\n' "$*" 2>/dev/null || true; }
info() { say "${GREEN}[+]${NC} $*"; }
step() { say "${YELLOW}[*]${NC} $*"; }
warn() { say "${RED}[!]${NC} $*" >&2 || true; }   # even with stderr closed
die()  { warn "$*"; exit 1; }

UFW_DOWN=0   # 1 from `ufw reset` until UFW runs again
GUARD_UP=0
on_exit() {
    [ "$UFW_DOWN" = 1 ] || return 0
    warn "UFW is NOT running: inbound traffic is unfiltered. Fix the error above and re-run."
    if [ "$GUARD_UP" = 1 ]; then
        warn "Egress to bogon/sensor networks stays rejected meanwhile (iptables chain $GUARD_CHAIN)."
    fi
}
trap on_exit EXIT
trap 'warn "failed at line $LINENO: $BASH_COMMAND"' ERR

# ufw with its output captured (shown only on failure); dry-run just prints.
ufw_q() {
    local out
    if [ "$DRY_RUN" = 1 ]; then say "    ufw $*"; return 0; fi
    out="$(ufw "$@" 2>&1)" && return 0
    warn "ufw $* failed: ${out//$'\n'/ }"
    return 1
}

# For rules whose failure must not abort the run: one missing port or reject
# beats leaving the node with no firewall at all.
ufw_try() { ufw_q "$@" || true; }

# Any other state-changing command.
run() {
    if [ "$DRY_RUN" = 1 ]; then say "    $*"; else "$@"; fi
}

is_v6()      { [[ $1 == *:* ]]; }
valid_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
valid_ip() {
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] ||
        [[ $1 == *:* && $1 =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]]
}

# Inbound entry: "443" (tcp+udp), "443/tcp", "1000:2000/udp" (ufw wants a
# protocol on ranges).
valid_entry() {
    local p="${1%/*}" proto=
    if [[ $1 == */* ]]; then proto="${1#*/}"; fi
    [[ -z $proto || $proto == tcp || $proto == udp ]] || return 1
    if [[ $p != *:* ]]; then valid_port "$p"; return; fi
    [ -n "$proto" ] && valid_port "${p%%:*}" && valid_port "${p#*:}" &&
        (( 10#${p%%:*} < 10#${p#*:} ))
}

# add_unique <array-name> <value>
add_unique() {
    local -n _arr="$1"
    [[ " ${_arr[*]-} " == *" $2 "* ]] || _arr+=("$2")
}

# default_route_field <word> <-4|-6>: the token after <word> in the default route
default_route_field() {
    ip -o "$2" route show default 2>/dev/null \
        | awk -v k="$1" '{for (i = 1; i < NF; i++) if ($i == k) {print $(i + 1); exit}}'
}

# Bad input must stop the run before `ufw reset`, not half-way through it.
preflight() {
    local - x
    set -f   # split the lists below, never glob them
    PANEL_IPS="${PANEL_IPS//,/ }"
    for x in $PANEL_IPS; do valid_ip "$x" || die "PANEL_IPS: '$x' is not an IP or CIDR"; done
    for x in ${NODE_API_PORTS//,/ }; do valid_port "$x" || die "NODE_API_PORTS: bad port '$x'"; done
    for x in ${EXTRA_PORTS//,/ }; do
        valid_entry "$x" || die "EXTRA_PORTS: bad entry '$x' (use 443, 443/tcp or 1000:2000/udp)"
    done
    [[ $BF_PORTS =~ ^[0-9]{1,5}(,[0-9]{1,5}){0,14}$ ]] || die "BF_PORTS: 1-15 comma-separated ports"
    for x in "$BF_PORT_RATE" "$BF_TARGET_RATE"; do
        [[ $x =~ ^[0-9]+/(second|minute|hour|day)$ ]] || die "bad rate '$x' (e.g. 60/minute)"
    done
    for x in "$BF_PORT_BURST" "$BF_TARGET_BURST"; do
        [[ $x =~ ^[0-9]+$ ]] || die "bad burst '$x'"
    done
    for x in SSH_LIMIT AUTO_PORTS DRY_RUN; do
        [[ ${!x} == [01] ]] || die "$x must be 0 or 1"
    done
}

# -------------------------------- detection -----------------------------------

detect_network() {
    local - ns
    set -f
    [ -n "$WAN_IF" ] || WAN_IF="$(default_route_field dev -4 || true)"
    [ -n "$WAN_IF" ] || WAN_IF="$(default_route_field dev -6 || true)"
    [ -n "$WAN_IF" ] || die "cannot detect the public interface; re-run with WAN_IF=<iface>"
    [[ $WAN_IF =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || die "bad interface name '$WAN_IF'"
    if [ ! -e "/sys/class/net/$WAN_IF" ]; then
        [ "$DRY_RUN" = 1 ] || die "interface '$WAN_IF' does not exist"
        warn "interface '$WAN_IF' not found (dry-run, continuing)"
    fi
    GW4="$(default_route_field via -4 || true)"
    if [ -n "$GW4" ] && ! valid_ip "$GW4"; then GW4=; fi
    HAS_V6=0
    if [ -d /proc/sys/net/ipv6 ]; then HAS_V6=1; fi
    # Upstream resolvers stay reachable even if they sit in a private range.
    DNS_SERVERS=
    for ns in $(cat /etc/resolv.conf /run/systemd/resolve/resolv.conf 2>/dev/null \
            | awk '$1 == "nameserver" {print $2}' \
            | grep -vE '^(127\.|::1$|fe80:)' | sort -u || true); do
        if valid_ip "$ns"; then DNS_SERVERS+="$ns "; fi
    done
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
        # L: what sshd listens on. Only `ssh -R` forwards listen besides the
        # real ports, and they bind loopback.
        ss -Hltnp 2>/dev/null | sed 's/^/L /'
        # E: sessions open right now, ours included. The local end of an
        # `ssh -D/-L` forward is an ephemeral port: skipped. (An optimizer's
        # 1024-65535 range skips every session; L and sshd -T still count.)
        ss -Htnp state established 2>/dev/null | sed 's/^/E /'
    } 2>/dev/null | awk -v lo="$lo" -v hi="$hi" '
        /^[0-9]+$/ {print; next}
        !/"sshd/ {next}
        {
            for (i = 2; i <= NF; i++) if ($i ~ /:[0-9]+$/) break
            if (i > NF) next
            n = split($i, a, ":"); p = a[n] + 0
            if ($1 == "L") {
                if ($i !~ /^(127\.|\[::1\]|::1:|\[::ffff:127\.)/) print p
            } else if (p < lo || p > hi) print p
        }' || true )"
    if [ -n "${SSH_CONNECTION:-}" ]; then raw+=" ${SSH_CONNECTION##* }"; fi
    SSH_PORTS=()
    for p in $raw; do
        if valid_port "$p"; then add_unique SSH_PORTS "$((10#$p))"; fi
    done
    if [ ${#SSH_PORTS[@]} -eq 0 ]; then
        SSH_PORTS=(22)
        warn "SSH port not detected, assuming 22"
    fi
}

# Ports the panel connects to: SERVICE_PORT (pg-node) and API_PORT
# (node-serviced) of every install, /opt/<name>/ (`pg-node install --name`).
# XRAY_API_PORT covers Marzban-style nodes.
detect_node_ports() {
    local f key v
    NODE_PORTS=()
    if [ -n "$NODE_API_PORTS" ]; then
        for v in ${NODE_API_PORTS//,/ }; do add_unique NODE_PORTS "$((10#$v))"; done
        return 0
    fi
    for f in /opt/*/.env /opt/*/docker-compose.yml; do
        [ -r "$f" ] || continue
        for key in SERVICE_PORT API_PORT XRAY_API_PORT; do
            v="$(sed -nE "s/^[[:space:]]*(export[[:space:]]+|-[[:space:]]*)?$key[[:space:]]*[=:][[:space:]]*[\"']?([0-9]{1,5})[\"']?[[:space:]]*(#.*)?\$/\2/p" \
                "$f" 2>/dev/null | tail -n 1 || true)"
            # a file without SERVICE_PORT is not a node's
            if [ "$key" = SERVICE_PORT ] && [ -z "$v" ]; then continue 2; fi
            if valid_port "${v:-x}"; then add_unique NODE_PORTS "$((10#$v))"; fi
        done
    done
    if [ ${#NODE_PORTS[@]} -eq 0 ]; then NODE_PORTS=(62050); fi
}

# Inbounds a running proxy core serves publicly: whatever the panel set up,
# even ports missing from ALLOWED_PORTS. A TCP listener is always an inbound;
# an unconnected UDP socket in the ephemeral range may be an outbound one.
detect_proxy_ports() {
    local lo=32768 hi=60999
    read -r lo hi 2>/dev/null </proc/sys/net/ipv4/ip_local_port_range || true
    EPHEMERAL="$lo-$hi"
    PROXY_PORTS=()
    [ "$AUTO_PORTS" = 1 ] || return 0
    mapfile -t PROXY_PORTS < <( {
        ss -Hltnp 2>/dev/null | sed 's/^/tcp /' || true
        ss -Hlunp 2>/dev/null | sed 's/^/udp /' || true
    } | awk -v re="$PROXY_PROC_RE" -v lo="$lo" -v hi="$hi" '
        $0 !~ re {next}
        {
            for (i = 2; i <= NF; i++) if ($i ~ /:[0-9]+$/) break
            if (i > NF || $i ~ /^(127\.|\[::1\]|::1:|\[::ffff:127\.)/) next
            n = split($i, a, ":"); p = a[n] + 0
            if (p < 1 || ($1 == "udp" && p >= lo && p <= hi)) next
            print p "/" $1
        }' | sort -t/ -k1,1n -k2,2 -u || true )
}

# Outbound rules live in the OUTPUT chain; a Docker-bridged xray skips it.
check_xray_netns() {
    local pid ns host_ns found=0
    host_ns="$(readlink /proc/1/ns/net 2>/dev/null || true)"
    for pid in $(pgrep -x xray 2>/dev/null || true); do
        found=1
        ns="$(readlink "/proc/$pid/ns/net" 2>/dev/null || true)"
        if [ -n "$ns" ] && [ "$ns" != "$host_ns" ]; then
            warn "xray (pid $pid) runs in its own network namespace (Docker bridge?)."
            warn "Its traffic bypasses every outbound rule here: use network_mode: host."
        fi
    done
    if [ "$found" = 0 ]; then
        warn "xray is not running (pg-node starts it once the panel connects): only"
        warn "  ALLOWED_PORTS/EXTRA_PORTS get opened. Re-run once the node is up."
    fi
    return 0
}

# pg-node's WireGuard backend forwards its clients (with its own FORWARD
# accepts), so their traffic never meets the OUTPUT rules here, and its UDP
# port comes from the panel.
check_wireguard() {
    local ifs
    ifs="$(ip -o link show type wireguard 2>/dev/null \
        | awk -F': ' '{sub(/@.*/, "", $2); printf "%s ", $2}' || true)"
    [ -n "$ifs" ] || return 0
    warn "WireGuard interface(s): ${ifs% }. If pg-node's WireGuard backend runs here,"
    warn "  open its UDP port (EXTRA_PORTS=\"<port>/udp\"); its forwarded traffic is"
    warn "  not covered by the outbound rules (they filter xray, the OUTPUT chain)."
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

# port_covered <port>/<proto>: is it already opened by an INBOUND entry?
port_covered() {
    local p="${1%/*}" proto="${1#*/}" e r
    for e in "${INBOUND[@]}"; do
        if [[ $e == */* && ${e#*/} != "$proto" ]]; then continue; fi
        r="${e%/*}"
        if (( 10#$p >= 10#${r%%:*} && 10#$p <= 10#${r#*:} )); then return 0; fi
    done
    return 1
}

# The inbound list: ALLOWED_PORTS + EXTRA_PORTS + proxy ports not yet covered.
plan_inbound() {
    local e
    INBOUND=()
    AUTO_OPENED=()
    for e in "${ALLOWED_PORTS[@]}" ${EXTRA_PORTS//,/ }; do add_unique INBOUND "$e"; done
    for e in "${PROXY_PORTS[@]}"; do
        if ! port_covered "$e"; then
            INBOUND+=("$e")
            AUTO_OPENED+=("$e")
        fi
    done
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
    local d=/etc/default/ufw sc=
    [ -f "$d" ] || return 0
    if [ "$HAS_V6" = 1 ]; then run sed -i 's/^IPV6=.*/IPV6=yes/' "$d"; fi
    # UFW must leave the built-in chains alone: Docker and pg-node's
    # WireGuard backend keep their FORWARD rules there, and so does the guard.
    run sed -i 's/^MANAGE_BUILTINS=.*/MANAGE_BUILTINS=no/' "$d"
    # UFW re-applies IPT_SYSCTL on every start, and its stock file forces
    # strict rp_filter=1 (drops asymmetric / policy-routed traffic). Use the
    # admin's /etc/sysctl.conf as v1 did, or nothing where that file is gone.
    if [ -f /etc/sysctl.conf ]; then sc=/etc/sysctl.conf; fi
    run sed -i "s|^IPT_SYSCTL=.*|IPT_SYSCTL=$sc|" "$d"
}

# From `ufw reset` to `ufw enable` (~30 s of ufw calls) nothing filters egress.
# This chain, which UFW leaves alone (MANAGE_BUILTINS=no), keeps the NetScan
# rejects up meanwhile, and stays if the run dies half-way.
guard_rules() {   # $1 = 4 | 6
    local net ns
    if [ "$1" = 4 ] && [ -n "$GW4" ]; then echo "-A $GUARD_CHAIN -d $GW4 -j RETURN"; fi
    for ns in $DNS_SERVERS; do
        if [ "$1" = 6 ] && is_v6 "$ns"; then echo "-A $GUARD_CHAIN -d $ns -j RETURN"; fi
        if [ "$1" = 4 ] && ! is_v6 "$ns"; then echo "-A $GUARD_CHAIN -d $ns -j RETURN"; fi
    done
    if [ "$1" = 4 ]; then
        for net in "${BOGONS_V4[@]}" "${SENSOR_NETS[@]}"; do
            echo "-A $GUARD_CHAIN -d $net -j REJECT"
        done
    else
        for net in "${BOGONS_V6[@]}"; do echo "-A $GUARD_CHAIN -d $net -j REJECT"; done
    fi
}

guard_up() {
    local v exe
    if [ "$DRY_RUN" = 1 ]; then
        say "    iptables chain $GUARD_CHAIN rejects bogon/sensor egress while UFW is rebuilt"
        return 0
    fi
    guard_down
    for v in 4 6; do
        exe=iptables
        if [ "$v" = 6 ]; then
            [ "$HAS_V6" = 1 ] || continue
            exe=ip6tables
        fi
        if { printf '*filter\n:%s - [0:0]\n' "$GUARD_CHAIN"
             guard_rules "$v"
             printf -- '-I OUTPUT 1 -o %s -m conntrack --ctstate NEW -j %s\nCOMMIT\n' \
                 "$WAN_IF" "$GUARD_CHAIN"
           } | "$exe-restore" -w -n >/dev/null 2>&1; then
            if [ "$v" = 4 ]; then GUARD_UP=1; fi
        else
            warn "could not add the temporary egress guard ($exe), continuing without it"
        fi
    done
}

guard_down() {
    local exe spec
    if [ "$DRY_RUN" = 1 ]; then return 0; fi
    for exe in iptables ip6tables; do
        command -v "$exe" >/dev/null 2>&1 || continue
        while read -r spec; do
            # spec is an argument list ("-A OUTPUT -o eth0 ..."): split on purpose
            "$exe" -w ${spec/#-A/-D} >/dev/null 2>&1 || true
        done < <("$exe" -w -S OUTPUT 2>/dev/null | grep -e "-j $GUARD_CHAIN\$" || true)
        "$exe" -w -F "$GUARD_CHAIN" >/dev/null 2>&1 || true
        "$exe" -w -X "$GUARD_CHAIN" >/dev/null 2>&1 || true
    done
    GUARD_UP=0
}

apply_inbound() {
    local p e ip n
    step "Inbound: deny by default"
    # SSH rules must not fail: a failure here aborts before UFW is enabled.
    for p in "${SSH_PORTS[@]}"; do
        if [ "$SSH_LIMIT" = 1 ]; then ufw_q limit "$p/tcp"; else ufw_q allow "$p/tcp"; fi
        info "SSH $p/tcp"
    done
    for p in "${NODE_PORTS[@]}"; do
        if [ -z "$PANEL_IPS" ]; then
            ufw_try allow "$p/tcp"
            warn "node API $p/tcp is open to the world: set PANEL_IPS"
            continue
        fi
        n=0
        for ip in $PANEL_IPS; do
            if is_v6 "$ip" && [ "$HAS_V6" != 1 ]; then warn "skip $ip: IPv6 is off"; continue; fi
            ufw_try allow proto tcp from "$ip" to any port "$p"
            n=$((n + 1))
        done
        if [ "$n" = 0 ]; then
            warn "node API $p/tcp: no usable PANEL_IPS, the panel cannot reach this node"
        else
            info "node API $p/tcp from $PANEL_IPS only"
        fi
    done
    for e in "${INBOUND[@]}"; do
        p="${e%%/*}"
        if [[ $REFLECTION_PORTS == *" $p "* ]] && [ -n "$(risky_listeners "$p")" ]; then
            warn "NOT opening $e: a non-proxy service listens on it publicly (reflector)"
            continue
        fi
        ufw_try allow "$e"
    done
    info "proxy ports: ${INBOUND[*]}"
    if [ ${#AUTO_OPENED[@]} -gt 0 ]; then
        info "  served by xray but not in ALLOWED_PORTS: ${AUTO_OPENED[*]}"
    fi
}

apply_outbound() {
    local net e ns
    step "Outbound on $WAN_IF: allow by default, reject abuse traffic"
    # Hetzner Cloud's gateway / DHCP server is 172.31.1.1, inside 172.16.0.0/12.
    if [ -n "$GW4" ]; then ufw_try allow out on "$WAN_IF" to "$GW4"; fi
    for ns in $DNS_SERVERS; do
        if is_v6 "$ns" && [ "$HAS_V6" != 1 ]; then continue; fi
        ufw_try allow out on "$WAN_IF" to "$ns" port 53
    done
    # reject (not deny): xray gets an instant error instead of a socket
    # hanging in SYN_SENT until its dial timeout, thousands of times a minute.
    for net in "${BOGONS_V4[@]}" "${SENSOR_NETS[@]}"; do
        ufw_try reject out on "$WAN_IF" to "$net"
    done
    if [ "$HAS_V6" = 1 ]; then
        for net in "${BOGONS_V6[@]}"; do ufw_try reject out on "$WAN_IF" to "$net"; done
    fi
    for e in "${BLOCKED_OUT[@]}"; do
        ufw_try reject out on "$WAN_IF" to any port "${e%/*}" proto "${e#*/}"
    done
    info "rejected: ${#BOGONS_V4[@]} bogon v4, ${#BOGONS_V6[@]} bogon v6, ${#SENSOR_NETS[@]} sensor nets, ports ${BLOCKED_OUT[*]}"
}

# iptables-restore lines for ufw's before*.rules ($1 = ufw | ufw6).
# Per-port first: a sweep is cut there, so it never reaches the per-target
# table. That table must not fill up, since a full hashlimit table silently
# drops every new connection that needs an entry (a SYN stall for users).
throttle_block() {
    local c="$1-before-output" t=pgaa_tgt g=pgaa_port m
    if [ "$1" = ufw6 ]; then t=pgaa_tgt6; g=pgaa_port6; fi
    m="-o $WAN_IF -p tcp -m multiport --dports $BF_PORTS -m conntrack --ctstate NEW"
    m+=" -m hashlimit --hashlimit-htable-max 65536 --hashlimit-htable-expire 300000"
    cat <<EOF
# pgnode-antiabuse BEGIN: throttle outbound brute-force / scan fan-out
-A $c $m --hashlimit-name $g --hashlimit-mode dstport --hashlimit-above $BF_PORT_RATE --hashlimit-burst $BF_PORT_BURST -j REJECT --reject-with tcp-reset
-A $c $m --hashlimit-name $t --hashlimit-mode dstip,dstport --hashlimit-above $BF_TARGET_RATE --hashlimit-burst $BF_TARGET_BURST -j REJECT --reject-with tcp-reset
# pgnode-antiabuse END
EOF
}

# hashlimit is the one match UFW itself never uses, and a before*.rules the
# kernel rejects makes `ufw enable` fail: check for it first.
hashlimit_ok() {   # $1 = iptables | ip6tables
    local exe="$1" c=pgaa-probe ok=0
    "$exe" -w -N "$c" >/dev/null 2>&1 || "$exe" -w -F "$c" >/dev/null 2>&1 || return 1
    if "$exe" -w -A "$c" -m hashlimit --hashlimit-above 1/minute \
            --hashlimit-name pgaa_probe -j RETURN >/dev/null 2>&1; then
        ok=1
    fi
    "$exe" -w -F "$c" >/dev/null 2>&1 || true
    "$exe" -w -X "$c" >/dev/null 2>&1 || true
    [ "$ok" = 1 ]
}

# ufw reset restores stock before*.rules, so inserting again is idempotent.
inject_throttle() {
    local f chain exe
    step "Outbound throttle on tcp/{$BF_PORTS}: $BF_PORT_RATE per port, $BF_TARGET_RATE per target"
    for f in "${THROTTLE_FILES[@]}"; do
        chain=ufw; exe=iptables
        if [[ $f == *6.rules ]]; then chain=ufw6; exe=ip6tables; fi
        if [ "$chain" = ufw6 ] && [ "$HAS_V6" != 1 ]; then continue; fi
        if [ "$DRY_RUN" = 1 ]; then
            say "    insert before COMMIT in $f:"
            throttle_block "$chain" | sed 's/^/      /'
            continue
        fi
        rm -f "$f.pgaa-orig"
        if [ ! -f "$f" ]; then warn "$f missing, throttle skipped"; continue; fi
        if ! hashlimit_ok "$exe"; then
            warn "the kernel has no hashlimit match for $exe: throttle skipped"
            continue
        fi
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
    if [ "$DRY_RUN" = 1 ]; then say "    ufw --force enable"; return 0; fi
    if ! ufw_q --force enable; then
        # A failed start leaves a half-loaded ruleset (no loopback or
        # ESTABLISHED accept) that a second `enable` takes for a running
        # firewall ("already started"). Unload it before retrying.
        warn "UFW failed to start; retrying without the outbound throttle"
        ufw --force disable >/dev/null 2>&1 || true
        restore_throttle
        if ! ufw_q --force enable; then
            ufw --force disable >/dev/null 2>&1 || true
            die "UFW failed to start even without the throttle"
        fi
    fi
    UFW_DOWN=0
    systemctl enable ufw >/dev/null 2>&1 || true
}

# UFW makes the kernel track every flow; tracking must never be what drops or
# stalls one:
#  - a full table silently drops new connections, for every user
#  - with too few hash buckets every packet walks long chains (raising the
#    max alone, as before, made that worse); one bucket per entry is the
#    kernel's own default ratio. The one-time resize briefly stalls new
#    connections (tens of ms on a big table): run the script off-peak.
#  - SYN_SENT and TIME_WAIT entries (120 s each) pile up on a busy proxy, and
#    scans add SYN_SENT ones by the thousand; xray gives a dial up after 16 s
#  - be_liberal: segments outside the tracked TCP window (loss, reordering,
#    middleboxes) are no longer marked INVALID, which UFW drops; the TCP
#    stack still checks them itself
# A value an optimizer already set stronger is kept.
tune_conntrack() {
    local mem_mb max spec key val mode cur buckets want
    local lines=() changes=()
    if [ ! -r "$CT_PROC/nf_conntrack_max" ]; then
        if [ "$DRY_RUN" = 1 ]; then
            step "conntrack: tuned once UFW has loaded nf_conntrack"
        else
            warn "nf_conntrack is not loaded: conntrack tuning skipped"
        fi
        return 0
    fi
    mem_mb="$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null || true)"
    max=$(( ${mem_mb:-0} * 128 ))
    if (( max < 262144 )); then max=262144; fi
    if (( max > 2097152 )); then max=2097152; fi
    for spec in "nf_conntrack_max $max raise" \
                "nf_conntrack_tcp_timeout_syn_sent 30 lower" \
                "nf_conntrack_tcp_timeout_time_wait 30 lower" \
                "nf_conntrack_tcp_be_liberal 1 raise"; do
        read -r key val mode <<<"$spec"
        cur="$(cat "$CT_PROC/$key" 2>/dev/null || true)"
        [[ $cur =~ ^[0-9]+$ ]] || continue
        if [ "$mode" = raise ] && (( cur > val )); then val=$cur; fi
        if [ "$mode" = lower ] && (( cur < val )); then val=$cur; fi
        if [ "$key" = nf_conntrack_max ]; then max=$val; fi
        lines+=("net.netfilter.$key = $val")
        if [ "$cur" != "$val" ]; then changes+=("${key#nf_conntrack_} $cur->$val"); fi
    done
    buckets="$(cat "$CT_PROC/nf_conntrack_buckets" 2>/dev/null || true)"
    [[ $buckets =~ ^[0-9]+$ ]] || buckets=0
    want=$(( max < 2097152 ? max : 2097152 ))
    if (( buckets > want )); then want=$buckets; fi
    if [ "$buckets" != "$want" ]; then changes+=("buckets $buckets->$want"); fi

    if [ ${#changes[@]} -eq 0 ]; then
        step "conntrack: already tuned"
    else
        step "conntrack: ${changes[*]}"
    fi
    if [ "$DRY_RUN" = 1 ]; then return 0; fi
    echo nf_conntrack >"$MODULES_FILE"
    echo "options nf_conntrack hashsize=$want" >"$MODPROBE_FILE"
    {
        echo "# pgnode-antiabuse (v2.sh): UFW tracks every flow, keep conntrack roomy"
        printf '%s\n' "${lines[@]}"
    } >"$SYSCTL_FILE"
    if [ "$buckets" != "$want" ]; then
        echo "$want" 2>/dev/null >"$CT_HASHSIZE" \
            || warn "could not resize the conntrack hash now; it applies after reboot"
    fi
    sysctl -q -p "$SYSCTL_FILE" >/dev/null 2>&1 \
        || warn "part of $SYSCTL_FILE could not be applied now; it applies after reboot"
}

# ----------------------------------- main -------------------------------------

main() {
    preflight
    if [ "$DRY_RUN" = 1 ]; then
        warn "DRY RUN: nothing will be changed"
    elif [ "$EUID" -ne 0 ]; then
        die "run as root: sudo bash $0"
    fi
    # Once `ufw reset` has run, stopping half-way leaves the node without a
    # firewall: survive a dropped SSH session (say() ignores write errors).
    trap '' HUP PIPE

    install_ufw
    detect_network
    detect_ssh_ports
    detect_node_ports
    detect_proxy_ports
    check_xray_netns
    check_wireguard
    plan_inbound
    info "public NIC   : $WAN_IF (gateway ${GW4:-none}, IPv6 $([ "$HAS_V6" = 1 ] && echo on || echo off))"
    info "SSH port(s)  : ${SSH_PORTS[*]}"
    info "node API     : ${NODE_PORTS[*]} (from ${PANEL_IPS:-anywhere})"
    info "DNS upstream : ${DNS_SERVERS:-none}"
    if [ "$AUTO_PORTS" = 1 ]; then
        info "xray serves  : ${PROXY_PORTS[*]:-nothing detected} (udp in $EPHEMERAL not auto-detected)"
    fi

    set_ufw_defaults
    guard_up
    step "Resetting UFW (old rules are backed up in /etc/ufw)"
    if [ "$DRY_RUN" != 1 ]; then UFW_DOWN=1; fi
    ufw_q --force reset
    ufw_q default deny incoming
    ufw_q default allow outgoing
    apply_inbound
    apply_outbound
    ufw_try logging off   # a busy node would flood the kernel log
    inject_throttle
    enable_ufw
    guard_down
    tune_conntrack

    info "Done. Keep this SSH session open and test a NEW login before closing it."
    if [ "$DRY_RUN" != 1 ]; then ufw status verbose 2>/dev/null || true; fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
