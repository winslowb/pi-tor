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

show_rules() {
  local ipt="${IPTABLES_BIN:-iptables}"
  echo "# bin/pi-tor-rules.sh would apply (no changes made); protected hosts never enter tor"
  while IFS= read -r rule; do
    printf '%s\n' "$ipt -t nat -A $CHAIN $rule"
  done < <(chain_rules)
  printf '%s\n' "$ipt -t nat -A PREROUTING -i $INTERFACE -j $CHAIN"
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

  log "Allowing ${SUBNET} on ${INTERFACE}"
  add_rule_if_missing filter INPUT -i "$INTERFACE" -s "$SUBNET" -j ACCEPT
  add_rule_if_missing filter FORWARD -i "$INTERFACE" -s "$SUBNET" -j ACCEPT
  add_rule_if_missing filter FORWARD -o "$INTERFACE" -d "$SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  if ip link show "$INTERFACE" >/dev/null 2>&1; then
    log "Publishing ${GATEWAY_IP} on ${INTERFACE}"
    if ! ip addr show "$INTERFACE" | grep -q "$GATEWAY_IP"; then
      ip addr add "${GATEWAY_CIDR}" dev "$INTERFACE"
    fi
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
