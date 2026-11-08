#!/usr/bin/env bash
# pi-tor-rules.sh
# helper that wires the usb gadget interface through the Tor
# transparent proxy (TransPort/DNSPort) exposed by the docker-compose stack.

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

IPTABLES_BIN="${IPTABLES_BIN:-}"

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

apply_rules() {
  require_root
  # No sysctl writes here: this script now runs inside the ui container on
  # the host's network namespace, where sysctl -w cannot touch the host's
  # tunables anyway. And none of them are needed: a nat PREROUTING REDIRECT
  # makes the packet local on the Pi itself (nothing is forwarded, so
  # ip_forward is irrelevant; ICMP is not redirected at all).

  log "Configuring NAT redirect chain (${CHAIN})"
  if ! "$IPTABLES_BIN" -t nat -L "$CHAIN" >/dev/null 2>&1; then
    "$IPTABLES_BIN" -t nat -N "$CHAIN"
  else
    "$IPTABLES_BIN" -t nat -F "$CHAIN"
  fi

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

case "$ACTION" in
  apply)
    validate_protected_hosts
    refuse_unprotected_gateway
    [[ -n "$IPTABLES_BIN" ]] || IPTABLES_BIN="$(resolve_iptables)"
    apply_rules
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
    echo "Usage: $0 [apply|flush|show-rules]" >&2
    exit 64
    ;;
esac
