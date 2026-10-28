#!/usr/bin/env bash
#
# scan-guard: stop VPN users from running network scans / brute-force through this server.
#
# On the internet-facing interface only:
#   * On ports scanners and brute-forcers love (SSH, FTP, Telnet, DNS, SMB, RTSP, RDP, VNC),
#     limits how many NEW destinations can be contacted per minute, per port. Destinations
#     contacted within the last hour pass freely, so normal use of these ports keeps working.
#   * Blocks TCP/UDP to private and reserved ranges (10/8, 172.16/12, 192.168/16, 100.64/10,
#     169.254/16, ...), which hosting providers also report as scanning.
#
# Covers proxies running on the host (xray, sing-box, Marzban/PasarGuard nodes with host
# networking) and routed VPNs (WireGuard, OpenVPN, Docker bridge). The rules live in their
# own nftables table, so UFW, Docker and other firewall rules are left untouched.
#
# Written for Hetzner (Cloud and dedicated). On other providers, check that nothing the
# server itself needs lives in a private/link-local range, and add it to ALLOW_DST if so.
#
# Usage:  ./scan-guard.sh [install|status|check|render|uninstall]     (default: install)
#   install    apply the rules now and on every boot (safe to re-run to change settings)
#   status     show how much has been blocked
#   check      validate the rules for this server without applying anything
#   render     print the generated nftables rules
#   uninstall  remove everything
#
# Settings (environment variables, read by install/check/render):
#   TCP_PORTS   guarded TCP ports                          (default 21,22,23,53,445,554,3389,5900)
#   UDP_PORTS   guarded UDP ports, may be empty            (default 53,554)
#   RATE        new destinations per minute, per port      (default 6)
#   BURST       short burst allowance                      (default 12)
#   REMEMBER    how long a used destination stays allowed  (default 1h)
#   WAN_IF      internet-facing interface                  (default: from the default route)
#   ALLOW_DST   extra destinations the server itself needs, comma-separated
#
# Example:  RATE=10 ./scan-guard.sh install
set -euo pipefail

TCP_PORTS="${TCP_PORTS:-21,22,23,53,445,554,3389,5900}"
UDP_PORTS="${UDP_PORTS-53,554}"
RATE="${RATE:-6}"
BURST="${BURST:-12}"
REMEMBER="${REMEMBER:-1h}"
WAN_IF="${WAN_IF:-}"
ALLOW_DST="${ALLOW_DST:-}"

CONF_DIR=/etc/scan-guard
RULES="$CONF_DIR/scan-guard.nft"
UNIT=/etc/systemd/system/scan-guard.service

RESERVED4="0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4"
RESERVED6="fc00::/7, fe80::/10, 2001:db8::/32, ff00::/8"
# Big public DNS resolvers never count against the port-53 budget, so a scanner can't starve them.
TRUSTED4="1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 149.112.112.112, 208.67.222.222, 208.67.220.220, 185.12.64.1, 185.12.64.2"
TRUSTED6="2606:4700:4700::1111, 2606:4700:4700::1001, 2001:4860:4860::8888, 2001:4860:4860::8844, 2620:fe::fe, 2620:fe::9, 2a01:4ff:ff00::add:1, 2a01:4ff:ff00::add:2"

die() { echo "scan-guard: $*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "must be run as root"; }

validate() {
  [[ $TCP_PORTS =~ ^[0-9]+(,[0-9]+)*$ ]] || die "invalid TCP_PORTS: '$TCP_PORTS'"
  [[ $UDP_PORTS =~ ^([0-9]+(,[0-9]+)*)?$ ]] || die "invalid UDP_PORTS: '$UDP_PORTS'"
  [[ $RATE =~ ^[1-9][0-9]*$ ]] || die "invalid RATE: '$RATE'"
  [[ $BURST =~ ^[1-9][0-9]*$ ]] || die "invalid BURST: '$BURST'"
  [[ $REMEMBER =~ ^[1-9][0-9]*[smhd]$ ]] || die "invalid REMEMBER: '$REMEMBER' (e.g. 30m, 1h, 1d)"
}

ensure_nft() {
  command -v nft >/dev/null && return
  command -v apt-get >/dev/null || die "nft not found; install the nftables package first"
  echo "Installing nftables..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq nftables >/dev/null || { apt-get update -qq && apt-get install -y -qq nftables >/dev/null; }
}

default_route_dev() {
  # awk reads all input (no early exit) so the pipe never breaks under pipefail
  ip "$1" route show default 2>/dev/null | awk '!d { for (i = 1; i < NF; i++) if ($i == "dev") d = $(i + 1) } END { if (d) print d }'
}

detect_wan() {
  [[ -n $WAN_IF ]] || WAN_IF=$(default_route_dev -4)
  [[ -n $WAN_IF ]] || WAN_IF=$(default_route_dev -6)
  [[ -n $WAN_IF ]] || die "could not detect the internet-facing interface; set WAN_IF"
}

# Destinations the server itself needs: cloud metadata/DNS/NTP (169.254.169.0/24 on Hetzner,
# AWS, GCP, Oracle), the system's DNS resolvers, and anything in ALLOW_DST.
build_exempt() {
  local resolv=/etc/resolv.conf ip nameservers=""
  [[ -r /run/systemd/resolve/resolv.conf ]] && resolv=/run/systemd/resolve/resolv.conf
  [[ -r $resolv ]] && nameservers=$(awk '$1 == "nameserver" { print $2 }' "$resolv")
  EXEMPT4="169.254.169.0/24"
  EXEMPT6=""
  for ip in $nameservers ${ALLOW_DST//,/ }; do
    ip=${ip%%\%*}
    case $ip in
      127.* | ::1) ;;
      *:*) EXEMPT6+="${EXEMPT6:+, }$ip" ;;
      *) EXEMPT4+=", $ip" ;;
    esac
  done
}

render() {
  local exempt6_elements="" udp_rule=""
  [[ -n $EXEMPT6 ]] && exempt6_elements="elements = { $EXEMPT6 }"
  [[ -n $UDP_PORTS ]] && udp_rule="udp dport { $UDP_PORTS } jump new_destination"
  cat <<EOF
# Generated by scan-guard.sh. Change settings by re-running "scan-guard.sh install",
# not by editing this file.
table inet scanguard
delete table inet scanguard
table inet scanguard {
	# Private/reserved ranges: providers report traffic to these as scanning.
	set reserved4 { type ipv4_addr; flags interval; auto-merge; elements = { $RESERVED4 } }
	set reserved6 { type ipv6_addr; flags interval; auto-merge; elements = { $RESERVED6 } }

	# Destinations the server itself needs (bypass everything, host traffic only).
	set exempt4 { type ipv4_addr; flags interval; auto-merge; elements = { $EXEMPT4 } }
	set exempt6 { type ipv6_addr; flags interval; auto-merge; $exempt6_elements }

	set trusted4 { type ipv4_addr; elements = { $TRUSTED4 } }
	set trusted6 { type ipv6_addr; elements = { $TRUSTED6 } }

	# Destinations recently contacted on guarded ports; these pass freely.
	set known4 { type ipv4_addr; size 65535; flags dynamic, timeout; timeout $REMEMBER; }
	set known6 { type ipv6_addr; size 65535; flags dynamic, timeout; timeout $REMEMBER; }

	# Per-port budget for contacting new destinations.
	set budget { type inet_service; size 1024; flags dynamic; }

	chain output {
		type filter hook output priority -10; policy accept;
		oifname != "$WAN_IF" accept
		ct state != new accept
		ip daddr @exempt4 accept
		ip6 daddr @exempt6 accept
		jump guard
	}

	chain forward {
		type filter hook forward priority -10; policy accept;
		oifname != "$WAN_IF" accept
		ct state != new accept
		jump guard
	}

	chain guard {
		udp dport { 67, 547 } accept comment "DHCP"
		meta l4proto { tcp, udp } ip daddr @reserved4 counter jump refuse comment "reserved"
		meta l4proto { tcp, udp } ip6 daddr @reserved6 counter jump refuse comment "reserved"
		tcp dport { $TCP_PORTS } jump new_destination
		$udp_rule
	}

	chain new_destination {
		ip daddr @trusted4 accept
		ip6 daddr @trusted6 accept
		ip daddr @known4 update @known4 { ip daddr } accept
		ip6 daddr @known6 update @known6 { ip6 daddr } accept
		add @budget { th dport limit rate over $RATE/minute burst $BURST packets } counter jump refuse comment "scan"
		meta nfproto ipv4 update @known4 { ip daddr }
		meta nfproto ipv6 update @known6 { ip6 daddr }
	}

	# Refuse instead of silently dropping, so the proxy fails fast instead of waiting on timeouts.
	chain refuse {
		meta l4proto tcp reject with tcp reset
		reject with icmpx type admin-prohibited
	}
}
EOF
}

write_unit() {
  local nft
  nft=$(command -v nft)
  cat >"$UNIT" <<EOF
[Unit]
Description=scan-guard: limit outbound scanning through this VPN server
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$nft -f $RULES
ExecReload=$nft -f $RULES
ExecStop=-$nft delete table inet scanguard

[Install]
WantedBy=sysinit.target
EOF
}

cmd_install() {
  need_root
  validate
  ensure_nft
  detect_wan
  ip link show "$WAN_IF" >/dev/null 2>&1 || die "interface '$WAN_IF' not found; set WAN_IF"
  build_exempt
  mkdir -p "$CONF_DIR"
  render >"$RULES.new"
  if ! nft -c -f "$RULES.new"; then
    rm -f "$RULES.new"
    die "nft rejected the generated rules; nothing was changed"
  fi
  mv "$RULES.new" "$RULES"
  write_unit
  systemctl daemon-reload
  systemctl enable --quiet scan-guard
  systemctl reload-or-restart scan-guard
  echo "scan-guard installed: $WAN_IF, tcp ${TCP_PORTS}${UDP_PORTS:+ udp $UDP_PORTS}, $RATE new destinations/min per port (burst $BURST), remembered for $REMEMBER"
  cmd_status
}

rule_packets() { # chain comment -> summed packet counter of rules with that comment
  nft list chain inet scanguard "$1" | awk -v c="comment \"$2\"" 'index($0, c) { for (i = 1; i < NF; i++) if ($i == "packets") s += $(i + 1) } END { print s + 0 }'
}

set_size() {
  nft list set inet scanguard "$1" | awk '{ n += gsub(/expires/, "") } END { print n + 0 }'
}

cmd_status() {
  need_root
  if ! nft list table inet scanguard >/dev/null 2>&1; then
    echo "scan-guard: not active"
    return 1
  fi
  local wan
  wan=$(nft list chain inet scanguard output | awk '/oifname/ && !w { gsub(/"/, "", $3); w = $3 } END { print w }')
  echo "scan-guard: active on $wan (service: $(systemctl is-active scan-guard 2>/dev/null || true), boot: $(systemctl is-enabled scan-guard 2>/dev/null || true))"
  echo "  scan attempts blocked:          $(rule_packets new_destination scan)"
  echo "  private/reserved blocked:       $(rule_packets guard reserved)"
  echo "  destinations remembered:        $(($(set_size known4) + $(set_size known6)))"
}

cmd_check() {
  need_root
  validate
  command -v nft >/dev/null || die "nft not found (install will install the nftables package)"
  detect_wan
  build_exempt
  local tmp
  tmp=$(mktemp)
  render >"$tmp"
  if nft -c -f "$tmp"; then
    echo "OK: rules are valid for interface '$WAN_IF' (nothing was applied)"
  else
    rm -f "$tmp"
    die "nft rejected the generated rules"
  fi
  rm -f "$tmp"
}

cmd_uninstall() {
  need_root
  systemctl disable --now --quiet scan-guard 2>/dev/null || true
  nft delete table inet scanguard 2>/dev/null || true
  rm -f "$UNIT"
  rm -rf "$CONF_DIR"
  systemctl daemon-reload
  echo "scan-guard removed"
}

case "${1:-install}" in
  install) cmd_install ;;
  status) cmd_status ;;
  check) cmd_check ;;
  render) validate; detect_wan; build_exempt; render ;;
  uninstall) cmd_uninstall ;;
  -h | --help | help) sed -n '3,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' ;;
  *) die "unknown command '$1' (use install, status, check, render or uninstall)" ;;
esac
