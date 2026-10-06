#!/bin/sh
# AISM reference host firewall (iptables, DOCKER-USER chain) – EXAMPLE, review before use.
# Same rules as aism-egress.nft, for hosts where Docker manages iptables (default).
# Usage: sudo ./docker-user.sh apply | remove | show
# Run after the Docker daemon has started (it creates DOCKER-USER), e.g. via the systemd unit
# in this folder. Rules are applied for IPv4 and, if ip6tables is available, IPv6.
# Use the same iptables variant as the Docker daemon (check `iptables -S DOCKER-USER` vs.
# `iptables-legacy -S DOCKER-USER`); override with IPTABLES=iptables-legacy IP6TABLES=ip6tables-legacy.
set -eu
CHAIN=AISM-EGRESS
IPTABLES=${IPTABLES:-iptables}
IP6TABLES=${IP6TABLES:-ip6tables}

apply_one() {
  ipt=$1
  $ipt -w -N "$CHAIN" 2>/dev/null || $ipt -w -F "$CHAIN"
  $ipt -w -A "$CHAIN" -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
  $ipt -w -A "$CHAIN" -i aism-frontend -o aism-frontend -j RETURN
  $ipt -w -A "$CHAIN" -i aism-frontend -m comment --comment "AISM: no internet egress from frontend" -j DROP
  $ipt -w -A "$CHAIN" -i aism-backend ! -o aism-backend -m comment --comment "AISM: backend stays internal" -j DROP
  # Optional hardening for the egress network (HTTPS/HTTP only):
  # $ipt -w -A "$CHAIN" -i aism-egress ! -o aism-egress -p tcp -m multiport --dports 80,443 -j RETURN
  # $ipt -w -A "$CHAIN" -i aism-egress ! -o aism-egress -j DROP
  $ipt -w -A "$CHAIN" -j RETURN
  $ipt -w -N DOCKER-USER 2>/dev/null || true      # normally created by Docker
  $ipt -w -C DOCKER-USER -j "$CHAIN" 2>/dev/null || $ipt -w -I DOCKER-USER 1 -j "$CHAIN"
}

remove_one() {
  ipt=$1
  while $ipt -w -D DOCKER-USER -j "$CHAIN" 2>/dev/null; do :; done
  $ipt -w -F "$CHAIN" 2>/dev/null || true
  $ipt -w -X "$CHAIN" 2>/dev/null || true
}

for ipt in "$IPTABLES" "$IP6TABLES"; do
  command -v "$ipt" >/dev/null 2>&1 || continue
  case "${1:-}" in
    apply)  apply_one "$ipt" ;;
    remove) remove_one "$ipt" ;;
    show)   $ipt -w -S "$CHAIN" 2>/dev/null || echo "$ipt: $CHAIN not present" ;;
    *) echo "usage: $0 apply|remove|show" >&2; exit 2 ;;
  esac
done
