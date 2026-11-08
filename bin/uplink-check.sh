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

echo "[pi-tor] uplink $IF ready (IPv4 + default route)"
