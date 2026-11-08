#!/bin/sh
# pi-tor uplink gate — refuses to start tor without a usable uplink.
# Exits non-zero with one clear line (docker logs tor shows it and the
# container restart-loops until the uplink works). pi-hole and the config
# UI are NOT gated by this, so the dashboard stays up to explain why tor
# is down. Read-only: /sys, /proc, plus `ip` when present.
#
# The tor image is debian:bookworm-slim (no iproute2, no bash), so `ip` is
# optional here: without it the fallback parses /proc/net/route, which
# reflects the host network namespace the container shares.
set -u

IF="${PI_TOR_UPLINK:-wlan0}"

fail() { echo "[pi-tor] uplink $IF $1" >&2; exit 1; }

[ -d "/sys/class/net/$IF" ] || fail "does not exist"

if command -v ip >/dev/null 2>&1; then
  if ! ip -4 -o addr show dev "$IF" 2>/dev/null | grep -q inet; then
    fail "has no IPv4 lease; tor cannot bootstrap"
  fi
  # match the exact interface word, not e.g. wlan0 inside wlan00
  if ! ip -4 route show default 2>/dev/null |
      awk -v IF="$IF" '$0 ~ ("(^|[^-a-zA-Z0-9_.:])dev " IF "([^a-zA-Z0-9_.:-]|$)") { ok=1 } END { exit !ok }'; then
    fail "carries no default route; tor cannot bootstrap"
  fi
else
  # /proc/net/route: Iface Destination Gateway ... (hex, little-endian).
  # A directly connected non-default route (Gateway=00000000) proves an
  # assigned IPv4 address; down/no-lease interfaces have no rows.
  if ! awk -v IF="$IF" '$1 == IF && $2 != "00000000" && $3 == "00000000" { ok=1 } END { exit !ok }' /proc/net/route; then
    fail "has no IPv4 lease; tor cannot bootstrap"
  fi
  if ! awk -v IF="$IF" '$1 == IF && $2 == "00000000" { ok=1 } END { exit !ok }' /proc/net/route; then
    fail "carries no default route; tor cannot bootstrap"
  fi
fi

# Optional bounded wait: the gadget-address listeners in torrc (Trans/DNS on
# PI_TOR_GATEWAY's subnet) can only bind once the address is assigned, and tor
# exits instead of retrying a failed bind. Addresses are scraped from the
# mounted torrc so they cannot drift from the rendered config; assigned-ness
# is read from /proc/net/fib_trie (the tor image has no iproute2, and fib_trie
# needs no `ip`).
have_addr() { # <ip> <fib_trie>
  # awk exits 0 at EOF even with no match, so the verdict must be explicit;
  # fib_trie prints host rows as "|-- <ip>" (some builds: "|--<ip>")
  awk -v gw="$1" '
    { sub(/^[ \t]+/, "") }
    ($1 == "|--" && $2 == gw) || ($1 == ("|--" gw)) {
      getline
      if ($0 ~ /host LOCAL/) { found = 1; exit }
    }
    END { exit !found }' "$2" 2>/dev/null
}

wait_gadget_addrs() { # <maxsecs> <torrc> <fib_trie>
  GW=$(grep -E '^(SocksPort|TransPort|DNSPort) [0-9.]+:[0-9]+' "$2" 2>/dev/null |
       sed -E 's/^[^ ]+ ([0-9.]+):[0-9]+.*/\1/' |
       grep -vx -e 127.0.0.1 -e 0.0.0.0 | sort -u)
  [ -n "$GW" ] || return 0
  i=0
  while :; do
    miss=
    for g in $GW; do have_addr "$g" "$3" || miss="$miss $g"; done
    [ -z "$miss" ] && return 0
    if [ "$i" -ge "$1" ]; then
      echo "[pi-tor] gadget address$miss still unassigned after ${1}s; tor binds them and cannot start" >&2
      exit 1
    fi
    i=$((i + 1)); sleep 1
    echo "[pi-tor] waiting ${i}s/$1s for gadget address$miss"
  done
}

wait_gadget_addrs 30 /etc/tor/torrc /proc/net/fib_trie

echo "[pi-tor] uplink $IF ready (IPv4 + default route)"
