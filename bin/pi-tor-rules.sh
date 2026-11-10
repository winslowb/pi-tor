#!/usr/bin/env bash
# pi-tor-rules.sh
# helper that wires the usb gadget interface through the Tor
# transparent proxy (TransPort/DNSPort) exposed by the docker-compose stack,
# plus the optional Wi-Fi AP (guest) path: apply-ap / flush-ap.

set -euo pipefail

ACTION="${1:-apply}"
CHAIN="${PI_TOR_CHAIN:-PI_TOR_REDIRECT}"
INTERFACE="${PI_TOR_INTERFACE:-usb0}"
SUBNET="${PI_TOR_SUBNET:-10.12.194.0/24}"
GATEWAY_IP="${PI_TOR_GATEWAY:-10.12.194.1}"
TOR_TRANS_PORT="${PI_TOR_TRANS_PORT:-9040}"
TOR_DNS_PORT="${PI_TOR_DNS_PORT:-5353}"
SUBNET_BITS="${SUBNET#*/}"
if [[ "$SUBNET_BITS" == "$SUBNET" ]]; then
  SUBNET_BITS=24
fi
GATEWAY_CIDR="${GATEWAY_IP}/${SUBNET_BITS}"

# Wi-Fi AP (guest) mode, driven by bin/pi-tor-ap. Off unless an interface name
# is given, so every tether-only call is unchanged. These rules DNAT rather
# than REDIRECT: REDIRECT rewrites the destination to the incoming interface's
# own address, where neither Pi-hole (:53) nor TransPort (:9040) is bound.
# DNAT to the Pi's tether address reaches both listeners without widening
# either one (Pi-hole keeps its SINGLE-interface policy).
AP_INTERFACE="${PI_TOR_AP_INTERFACE:-}"
AP_CHAIN="${PI_TOR_AP_CHAIN:-PI_TOR_AP_REDIRECT}"
AP_IN_CHAIN="${PI_TOR_AP_IN_CHAIN:-PI_TOR_AP_IN}"
AP_SUBNET="${PI_TOR_AP_SUBNET:-10.12.195.0/24}"
AP_GATEWAY="${PI_TOR_AP_GATEWAY:-10.12.195.1}"
PIHOLE_PORT="${PI_TOR_PIHOLE_PORT:-53}"

# Protected hosts: IPv4 addresses traffic to which must never be diverted
# into tor (SSH :22, Pi-hole :80 and the config UI :8080 live on this host).
# Comma- or space-separated; unset/empty falls back to the gateway IP.
PROTECTED_HOSTS="${PI_TOR_PROTECTED_HOSTS:-${GATEWAY_IP}}"
read -r -a PROTECTED_ARR <<< "${PROTECTED_HOSTS//,/ }"
if [[ ${#PROTECTED_ARR[@]} -eq 0 ]]; then
  PROTECTED_ARR=("$GATEWAY_IP")
fi

validate_protected_hosts() {
  local h
  for h in "${PROTECTED_ARR[@]}"; do
    if [[ ! "$h" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      echo "[pi-tor] protected host '$h' is not an IPv4 address (PI_TOR_PROTECTED_HOSTS)" >&2
      exit 64
    fi
  done
}

chain_rules() {
  # The nat chain rules in apply order; show-rules prints the same list so
  # the order can be inspected without root. The -j RETURN entries must
  # come first: traffic to the protected hosts leaves the chain untouched
  # before the catch-all tcp REDIRECT can grab it.
  local h
  for h in "${PROTECTED_ARR[@]}"; do
    printf '%s\n' "-d $h -j RETURN"
  done
  printf '%s\n' "-p udp --dport 53 -j REDIRECT --to-ports $TOR_DNS_PORT"
  printf '%s\n' "-p tcp --dport 53 -j REDIRECT --to-ports $TOR_DNS_PORT"
  printf '%s\n' "-p tcp -j REDIRECT --to-ports $TOR_TRANS_PORT"
}

filter_rules() {
  # The tether-side filter rules in apply order; show-rules prints them with
  # the nat list so the whole picture is reviewable without root.
  #
  # Rationale: TCP and DNS are REDIRECTed into tor, but UDP is not, so QUIC
  # would either go direct (unprotected) or hang; dropping non-DNS UDP makes
  # browsers fall back to TCP. This also kills mDNS and any other UDP
  # arriving on the tether, which is intended.
  #
  # Order matters. The DNSPort ACCEPT must precede the drop: nat REDIRECT
  # rewrites tethered udp/53 to udp/$TOR_DNS_PORT before the filter table
  # sees it, so the blanket non-DNS drop would otherwise kill tethered DNS.
  # Both must precede the subnet ACCEPTs (added after these), which would
  # otherwise white-list every tethered packet first.
  printf '%s\n' "-i $INTERFACE -p udp --dport $TOR_DNS_PORT -j ACCEPT"
  printf '%s\n' "-i $INTERFACE -p udp ! --dport 53 -j DROP"
}

ap_chain_rules() {
  # No RETURN rules here, unlike the tether chain: a RETURN for the gateway
  # would let a guest reach the Pi's own services by IP (Pi-hole admin on :80,
  # this UI on :8080). The AP input chain's final DROP is what keeps it
  # guest-only.
  printf '%s\n' "-p udp --dport $PIHOLE_PORT -j DNAT --to-destination ${GATEWAY_IP}:${PIHOLE_PORT}"
  printf '%s\n' "-p tcp --dport $PIHOLE_PORT -j DNAT --to-destination ${GATEWAY_IP}:${PIHOLE_PORT}"
  printf '%s\n' "-p tcp -j DNAT --to-destination ${GATEWAY_IP}:${TOR_TRANS_PORT}"
}

ap_filter_rules() {
  # The ACCEPTs are the only exits from this chain; the trailing DROP catches
  # QUIC and every other non-DNS UDP, ICMP, mDNS, a guest reaching the Pi's
  # admin ports, and any protocol that is neither TCP nor DNS. DHCP is udp/67
  # on this interface only (bin/pi-tor-ap's dnsmasq binds nowhere else).
  #
  # Every ACCEPT pins the guest subnet as source. Without -s a guest can spoof
  # a LAN address (192.168.0.5) and have the replies delivered over the LAN --
  # an unfiltered path around tor that no destination match would catch. DHCP
  # is the one exception, because a client with no lease has no address yet; it
  # is pinned to DHCP's own address pair and port pair instead.
  printf '%s\n' "-i $AP_INTERFACE -s $AP_SUBNET -p udp -d $GATEWAY_IP --dport $PIHOLE_PORT -j ACCEPT"
  printf '%s\n' "-i $AP_INTERFACE -s $AP_SUBNET -p tcp -d $GATEWAY_IP --dport $PIHOLE_PORT -j ACCEPT"
  printf '%s\n' "-i $AP_INTERFACE -s 0.0.0.0/32 -p udp -d 255.255.255.255 --sport 68 --dport 67 -j ACCEPT"
  printf '%s\n' "-i $AP_INTERFACE -s $AP_SUBNET -p udp -d $AP_GATEWAY --sport 68 --dport 67 -j ACCEPT"
  printf '%s\n' "-i $AP_INTERFACE -s $AP_SUBNET -p tcp -d $GATEWAY_IP --dport $TOR_TRANS_PORT -j ACCEPT"
  printf '%s\n' "-i $AP_INTERFACE -j DROP"
}

show_ap_rules() {
  [[ -n "$AP_INTERFACE" ]] || return 0
  local ipt="${IPTABLES_BIN:-iptables}" ip6t="${IP6TABLES_BIN:-ip6tables}" rule
  echo "# AP mode (${AP_INTERFACE}): guest DNS and TCP leave through the Pi's own listeners, everything else is dropped"
  while IFS= read -r rule; do
    printf '%s\n' "$ipt -t nat -A $AP_CHAIN $rule"
  done < <(ap_chain_rules)
  printf '%s\n' "$ipt -t nat -I PREROUTING 1 -i $AP_INTERFACE -j $AP_CHAIN"
  while IFS= read -r rule; do
    printf '%s\n' "$ipt -t filter -A $AP_IN_CHAIN $rule"
  done < <(ap_filter_rules)
  printf '%s\n' "$ipt -t filter -I INPUT 1 -i $AP_INTERFACE -j $AP_IN_CHAIN"
  printf '%s\n' "$ipt -t filter -I FORWARD 1 -i $AP_INTERFACE -j DROP"
  printf '%s\n' "$ip6t -t filter -I INPUT 1 -i $AP_INTERFACE -j DROP"
  printf '%s\n' "$ip6t -t filter -I FORWARD 1 -i $AP_INTERFACE -j DROP"
}

show_rules() {
  local ipt="${IPTABLES_BIN:-iptables}"
  echo "# bin/pi-tor-rules.sh would apply (no changes made); protected hosts never enter tor"
  while IFS= read -r rule; do
    printf '%s\n' "$ipt -t nat -A $CHAIN $rule"
  done < <(chain_rules)
  printf '%s\n' "$ipt -t nat -A PREROUTING -i $INTERFACE -j $CHAIN"
  local chain rule
  for chain in INPUT FORWARD; do
    while IFS= read -r rule; do
      printf '%s\n' "$ipt -t filter -A $chain $rule"
    done < <(filter_rules)
    printf '%s\n' "$ipt -t filter -A $chain -i $INTERFACE -s $SUBNET -j ACCEPT"
  done
  printf '%s\n' "$ipt -t filter -A FORWARD -o $INTERFACE -d $SUBNET -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
  show_ap_rules
}

resolve_iptables() {
  if command -v iptables-nft >/dev/null 2>&1; then
    command -v iptables-nft
  elif command -v iptables >/dev/null 2>&1; then
    command -v iptables
  else
    echo "iptables(8) not found" >&2
    exit 1
  fi
}

resolve_ip6tables() {
  if command -v ip6tables-nft >/dev/null 2>&1; then
    command -v ip6tables-nft
  elif command -v ip6tables >/dev/null 2>&1; then
    command -v ip6tables
  else
    # Fail closed: without ip6tables a guest keeps its link-local address and
    # any IPv6 path the rest of the network offers would bypass the v4 rules.
    echo "[pi-tor] refusing to apply AP rules: ip6tables(8) not found, so guest IPv6 could not be blocked" >&2
    exit 1
  fi
}

IPTABLES_BIN="${IPTABLES_BIN:-}"
IP6TABLES_BIN="${IP6TABLES_BIN:-}"

log() { printf '[pi-tor] %s\n' "$*"; }

require_root() {
  # PI_TOR_FAKE_ROOT=1 is a test-suite hook, used only together with a stub
  # IPTABLES_BIN that simulates a ruleset in a temp dir; it can never touch
  # a real ruleset because the binary it pairs with is not iptables.
  if [[ $EUID -ne 0 && "${PI_TOR_FAKE_ROOT:-}" != "1" ]]; then
    echo "This script must run as root (sudo pi-tor-rules.sh ${ACTION})." >&2
    exit 1
  fi
}

# Applying without the gateway in the protected list redirects the Pi's own
# traffic into tor and locks the operator out of SSH, Pi-hole and this UI
# — including the UI flush endpoint that would undo it.
refuse_unprotected_gateway() {
  local h
  for h in "${PROTECTED_ARR[@]}"; do
    [[ "$h" == "$GATEWAY_IP" ]] && return 0
  done
  echo "[pi-tor] refusing to apply: $GATEWAY_IP is missing from PI_TOR_PROTECTED_HOSTS (${PROTECTED_HOSTS}); applying would redirect the Pi's own traffic into tor and lock you out of SSH, Pi-hole and this UI" >&2
  exit 64
}

add_rule_if_missing() {
  local table="$1"; shift
  if ! "$IPTABLES_BIN" -t "$table" -C "$@" >/dev/null 2>&1; then
    "$IPTABLES_BIN" -t "$table" -A "$@" >/dev/null
  fi
}

delete_rule_if_present() {
  local table="$1"; shift
  while "$IPTABLES_BIN" -t "$table" -C "$@" >/dev/null 2>&1; do
    "$IPTABLES_BIN" -t "$table" -D "$@" >/dev/null || true
  done
}

# Insert at position 1, never append: a broad ACCEPT already installed by
# Docker, a distro firewall or a legacy run would otherwise match first and
# bypass the guest chain entirely (IPv6 FORWARD even defaults to ACCEPT).
insert_rule_if_missing() { # <table> <chain> <rule...>
  local table="$1" chain="$2"; shift 2
  if ! "$IPTABLES_BIN" -t "$table" -C "$chain" "$@" >/dev/null 2>&1; then
    "$IPTABLES_BIN" -t "$table" -I "$chain" 1 "$@" >/dev/null
  fi
}

insert6_rule_if_missing() { # <table> <chain> <rule...>
  local table="$1" chain="$2"; shift 2
  if ! "$IP6TABLES_BIN" -t "$table" -C "$chain" "$@" >/dev/null 2>&1; then
    "$IP6TABLES_BIN" -t "$table" -I "$chain" 1 "$@" >/dev/null
  fi
}

delete6_rule_if_present() {
  local table="$1"; shift
  while "$IP6TABLES_BIN" -t "$table" -C "$@" >/dev/null 2>&1; do
    "$IP6TABLES_BIN" -t "$table" -D "$@" >/dev/null || true
  done
}

chain_reset() { # <table> <chain>: create it, or empty it in place
  if ! "$IPTABLES_BIN" -t "$1" -L "$2" >/dev/null 2>&1; then
    "$IPTABLES_BIN" -t "$1" -N "$2"
  else
    "$IPTABLES_BIN" -t "$1" -F "$2"
  fi
}

chain_drop() { # <table> <chain>: remove a chain this script created, if present
  if "$IPTABLES_BIN" -t "$1" -L "$2" >/dev/null 2>&1; then
    "$IPTABLES_BIN" -t "$1" -F "$2"
    "$IPTABLES_BIN" -t "$1" -X "$2"
  fi
}

apply_rules() {
  require_root
  # No sysctl writes here: this script now runs inside the ui container on
  # the host's network namespace, where sysctl -w cannot touch the host's
  # tunables anyway. And none of them are needed: a nat PREROUTING REDIRECT
  # makes the packet local on the Pi itself (nothing is forwarded, so
  # ip_forward is irrelevant; ICMP is not redirected at all).

  log "Configuring NAT redirect chain (${CHAIN})"
  chain_reset nat "$CHAIN"

  log "Protecting ${PROTECTED_HOSTS} from the redirect (RETURN first)"
  while IFS= read -r rule; do
    "$IPTABLES_BIN" -t nat -A "$CHAIN" $rule
  done < <(chain_rules)

  add_rule_if_missing nat PREROUTING -i "$INTERFACE" -j "$CHAIN"

  # The UDP rules go in before the subnet ACCEPTs: an ACCEPT first would
  # white-list every tethered packet and the drop underneath would never fire.
  log "Dropping non-DNS UDP arriving on ${INTERFACE} (tcp and DNS are redirected into tor; QUIC would go direct or hang without this, and mDNS/other tether UDP are killed too, which is intended)"
  local chain
  for chain in INPUT FORWARD; do
    # ACCEPT first: nat REDIRECT rewrites tethered udp/53 to udp/$TOR_DNS_PORT
    # before the filter table sees it, so the blanket drop would kill tethered DNS
    add_rule_if_missing filter "$chain" -i "$INTERFACE" -p udp --dport "$TOR_DNS_PORT" -j ACCEPT
    add_rule_if_missing filter "$chain" -i "$INTERFACE" -p udp '!' --dport 53 -j DROP
  done

  log "Allowing ${SUBNET} on ${INTERFACE}"
  add_rule_if_missing filter INPUT -i "$INTERFACE" -s "$SUBNET" -j ACCEPT
  add_rule_if_missing filter FORWARD -i "$INTERFACE" -s "$SUBNET" -j ACCEPT
  add_rule_if_missing filter FORWARD -o "$INTERFACE" -d "$SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  if ip link show "$INTERFACE" >/dev/null 2>&1; then
    log "Publishing ${GATEWAY_IP} on ${INTERFACE}"
    # capture first: `grep -q` closes the pipe early and SIGPIPEs `ip`, which
    # under pipefail makes this test lie and re-add an address that is present
    iface_addrs="$(ip addr show "$INTERFACE" 2>/dev/null || true)"
    case "$iface_addrs" in
    *"$GATEWAY_IP"*) : ;;
    *)
      ip addr add "${GATEWAY_CIDR}" dev "$INTERFACE" ;;
    esac
  else
    log "Interface ${INTERFACE} is down; skipping address assignment"
  fi
}

flush_rules() {
  require_root
  log "Removing PREROUTING hook"
  delete_rule_if_present nat PREROUTING -i "$INTERFACE" -j "$CHAIN"
  if "$IPTABLES_BIN" -t nat -L "$CHAIN" >/dev/null 2>&1; then
    "$IPTABLES_BIN" -t nat -F "$CHAIN"
    "$IPTABLES_BIN" -t nat -X "$CHAIN"
  fi

  log "Removing non-DNS UDP drop rules"
  local chain
  for chain in INPUT FORWARD; do
    delete_rule_if_present filter "$chain" -i "$INTERFACE" -p udp '!' --dport 53 -j DROP
    delete_rule_if_present filter "$chain" -i "$INTERFACE" -p udp --dport "$TOR_DNS_PORT" -j ACCEPT
  done

  log "Cleaning ACCEPT rules"
  delete_rule_if_present filter INPUT -i "$INTERFACE" -s "$SUBNET" -j ACCEPT
  delete_rule_if_present filter FORWARD -i "$INTERFACE" -s "$SUBNET" -j ACCEPT
  delete_rule_if_present filter FORWARD -o "$INTERFACE" -d "$SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}

require_ap_interface() {
  if [[ -z "$AP_INTERFACE" ]]; then
    echo "[pi-tor] PI_TOR_AP_INTERFACE is empty: there is no AP interface to $ACTION" >&2
    exit 64
  fi
  if [[ "$AP_INTERFACE" == "$INTERFACE" ]]; then
    echo "[pi-tor] PI_TOR_AP_INTERFACE ($AP_INTERFACE) must differ from PI_TOR_INTERFACE ($INTERFACE): guest rules and tether rules would share one interface" >&2
    exit 64
  fi
}

apply_ap_rules() {
  require_root
  require_ap_interface

  log "AP mode: guest DNS goes to Pi-hole ${GATEWAY_IP}:${PIHOLE_PORT}, guest TCP to tor ${GATEWAY_IP}:${TOR_TRANS_PORT} (${AP_CHAIN})"
  chain_reset nat "$AP_CHAIN"
  local rule
  while IFS= read -r rule; do
    "$IPTABLES_BIN" -t nat -A "$AP_CHAIN" $rule
  done < <(ap_chain_rules)
  insert_rule_if_missing nat PREROUTING -i "$AP_INTERFACE" -j "$AP_CHAIN"

  log "AP mode: ${AP_INTERFACE} is guest-only (DNS, DHCP, tor-TransPort, then DROP; no forwarding, no IPv6)"
  # Reapplying must not open a hole: the jump into AP_IN_CHAIN stays live while
  # the chain is refilled, and INPUT's policy is ACCEPT, so flushing it in
  # place would accept every guest packet in between. Drop guest input ahead of
  # everything for the refill, then take the guard back out.
  insert_rule_if_missing filter INPUT -i "$AP_INTERFACE" -j DROP
  chain_reset filter "$AP_IN_CHAIN"
  while IFS= read -r rule; do
    "$IPTABLES_BIN" -t filter -A "$AP_IN_CHAIN" $rule
  done < <(ap_filter_rules)
  insert_rule_if_missing filter INPUT -i "$AP_INTERFACE" -j "$AP_IN_CHAIN"
  delete_rule_if_present filter INPUT -i "$AP_INTERFACE" -j DROP
  insert_rule_if_missing filter FORWARD -i "$AP_INTERFACE" -j DROP
  # Guests are never routed anywhere by this host: tor captures their TCP.
  insert6_rule_if_missing filter INPUT -i "$AP_INTERFACE" -j DROP
  insert6_rule_if_missing filter FORWARD -i "$AP_INTERFACE" -j DROP
}

flush_ap_rules() {
  require_root
  require_ap_interface

  log "AP mode: removing hooks and chains for ${AP_INTERFACE}"
  delete_rule_if_present nat PREROUTING -i "$AP_INTERFACE" -j "$AP_CHAIN"
  delete_rule_if_present filter INPUT -i "$AP_INTERFACE" -j "$AP_IN_CHAIN"
  delete_rule_if_present filter INPUT -i "$AP_INTERFACE" -j DROP
  delete_rule_if_present filter FORWARD -i "$AP_INTERFACE" -j DROP
  chain_drop nat "$AP_CHAIN"
  chain_drop filter "$AP_IN_CHAIN"

  # Teardown must not need a binary that was never there: only resolve
  # ip6tables when it exists, because a missing one means nothing was added.
  if [[ -z "$IP6TABLES_BIN" ]]; then
    IP6TABLES_BIN="$(command -v ip6tables-nft || command -v ip6tables || true)"
  fi
  if [[ -n "$IP6TABLES_BIN" ]]; then
    delete6_rule_if_present filter INPUT -i "$AP_INTERFACE" -j DROP
    delete6_rule_if_present filter FORWARD -i "$AP_INTERFACE" -j DROP
  fi
}

case "$ACTION" in
  apply)
    validate_protected_hosts
    refuse_unprotected_gateway
    [[ -n "$IPTABLES_BIN" ]] || IPTABLES_BIN="$(resolve_iptables)"
    apply_rules
    ;;
  apply-ap)
    [[ -n "$IPTABLES_BIN" ]] || IPTABLES_BIN="$(resolve_iptables)"
    [[ -n "$IP6TABLES_BIN" ]] || IP6TABLES_BIN="$(resolve_ip6tables)"
    apply_ap_rules
    ;;
  flush-ap)
    [[ -n "$IPTABLES_BIN" ]] || IPTABLES_BIN="$(resolve_iptables)"
    flush_ap_rules
    ;;
  flush)
    [[ -n "$IPTABLES_BIN" ]] || IPTABLES_BIN="$(resolve_iptables)"
    flush_rules
    ;;
  show-rules)
    validate_protected_hosts
    show_rules
    ;;
  *)
    echo "Usage: $0 [apply|flush|apply-ap|flush-ap|show-rules]" >&2
    exit 64
    ;;
esac
