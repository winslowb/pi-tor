#!/bin/sh
# pi-tor gadget RX watchdog — reloads g_ether on the Pi only when the USB
# tether is genuinely stalled on the receive side. Measured on the device:
# the Pi keeps transmitting (tx_packets climbs, ARPs flow out) while
# rx_packets freezes and every probe dies, and `modprobe -r g_ether &&
# modprobe g_ether` restores RX in seconds. rx_packets stagnating alone
# proves nothing (an idle-even-if-healthy host stays silent), so a reload
# runs only when BOTH signals agree across one probe window:
#   - the end-to-end probe to the host failed WATCH_FAIL_THRESHOLD times
#     in a row (probes separated by the probe interval), and
#   - rx_packets did not advance across the window while tx_packets did.
# A host that is not tethered (no lladdr for it in the neighbour table) or
# a missing gadget interface is skipped silently: those are attach, detach
# and reseat moments, not stalls, and re-enumerating then would fight the
# host's interface manager. A healthy tether produces no output at all.
#
# Every state change and decision emits one [gadget-watchdog] line on
# stdout. Reloads are capped per hour window, with a growing sleep between
# attempts, and the cap state lives in WATCH_STATE_FILE so it survives a
# restart (a crash-looping service cannot bypass the cap). After a reload
# the watchdog waits, bounded, for the interface and the Pi's gadget
# address to return before probing again.
#
# Test hooks — everything that touches the real gadget is injectable:
#   WATCH_SYSFS       fixture root for the interface counters
#   WATCH_NEIGH_CMD   neighbour-table command (default: ip neigh show)
#   WATCH_PROBE_CMD   end-to-end probe (default: ping -c1 -W1 <host>)
#   WATCH_RELOAD_CMD  the reload itself (default: the modprobe pair)
#   WATCH_STATE_FILE  where the cap/backoff bookkeeping is persisted
#   WATCH_FIB_TRIE    route table for the post-reload self-address check
#                     (same source as bin/uplink-check.sh uses)
#   WATCH_MAX_CYCLES  0 = run forever; N = stop after N host-check cycles
# ponytail: the backoff sleep does not re-probe before reloading — a stall
# that self-heals during it wastes one reload inside the cap.

set -u

IF=${PI_TOR_GADGET_IF:-usb0}
HOST=${PI_TOR_HOST_ADDR:-10.12.194.2}
SELF_ADDR=${PI_TOR_GATEWAY:-10.12.194.1}
INTERVAL=${WATCH_PROBE_INTERVAL:-30}
THRESHOLD=${WATCH_FAIL_THRESHOLD:-2}
MAX_RELOADS=${WATCH_MAX_RELOADS_PER_HOUR:-3}
WINDOW_SECS=3600
RECOVER_SECS=${WATCH_RECOVER_SECONDS:-20}
STATE=${WATCH_STATE_FILE:-/var/lib/pi-tor-gadget-watchdog/state}
SYSFS=${WATCH_SYSFS:-/sys}
FIB=${WATCH_FIB_TRIE:-/proc/net/fib_trie}
NEIGH_CMD=${WATCH_NEIGH_CMD:-ip neigh show}
PROBE_CMD=${WATCH_PROBE_CMD:-ping -c1 -W1 $HOST}
RELOAD_CMD=${WATCH_RELOAD_CMD:-modprobe -r g_ether && sleep 1 && modprobe g_ether}
MAX_CYCLES=${WATCH_MAX_CYCLES:-0}

is_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; }
is_uint "$INTERVAL"     || INTERVAL=30
is_uint "$THRESHOLD"    || THRESHOLD=2
is_uint "$MAX_RELOADS"  || MAX_RELOADS=3
is_uint "$RECOVER_SECS" || RECOVER_SECS=20
is_uint "$MAX_CYCLES"   || MAX_CYCLES=0

log() { printf '[gadget-watchdog] %s\n' "$*"; }

iface_ok() {
  [ -r "$SYSFS/class/net/$IF/statistics/rx_packets" ] &&
  [ -r "$SYSFS/class/net/$IF/statistics/tx_packets" ]
}

read_cnt() { cat "$SYSFS/class/net/$IF/statistics/$1" 2>/dev/null; }

# host attached = the neighbour entry for HOST carries a link-layer address;
# an INCOMPLETE entry has none and means mid-attach or gone. The trailing
# space keeps "10.12.194.2" from matching "10.12.194.21" (same idea as the
# exact-interface-word match in bin/uplink-check.sh).
host_present() {
  printf '%s\n' "$(eval "$NEIGH_CMD" 2>/dev/null)" |
    grep -F -- "$HOST " | grep -q lladdr
}

probe_ok() { eval "$PROBE_CMD" >/dev/null 2>&1; }

# /proc/net/fib_trie shape as in bin/uplink-check.sh: host rows appear as
# "|-- <ip>" (or "|--<ip>") followed by "/32 host LOCAL"; the explicit
# exit beats awk's success-at-EOF.
have_addr() { # <ip> <fib_trie>
  awk -v gw="$1" '
    { sub(/^[ \t]+/, "") }
    ($1 == "|--" && $2 == gw) || ($1 == ("|--" gw)) {
      getline
      if ($0 ~ /host LOCAL/) { found = 1; exit }
    }
    END { exit !found }' "$2" 2>/dev/null
}

# our own k='v' state format (same convention as bin/usb_route), tmp+mv
save_state() {
  d=$(dirname "$STATE") || true
  if mkdir -p "$d" 2>/dev/null &&
     printf "RELOADS='%s'\nWINDOW_START='%s'\nCAP_LOGGED='%s'\n" \
       "$RELOADS" "$WINDOW_START" "$CAP_LOGGED" > "$STATE.tmp" 2>/dev/null &&
     mv -f "$STATE.tmp" "$STATE" 2>/dev/null; then
    return 0
  fi
  log "WARNING: cannot persist reload state to $STATE; the hourly cap will not survive a restart"
}

after_reload() {
  # bounded wait for the interface and the Pi's gadget address; the host
  # side re-enumeration (NM etc.) may still be settling even once ours is
  i=0
  while [ "$i" -lt "$RECOVER_SECS" ]; do
    if iface_ok && have_addr "$SELF_ADDR" "$FIB"; then
      log "$IF is back with $SELF_ADDR after ${i}s; resuming probes"
      return 0
    fi
    i=$((i + 1)); sleep 1
  done
  log "$IF or $SELF_ADDR still absent after ${RECOVER_SECS}s; resuming probes anyway"
}

maybe_reload() { # caller passes the window counters in RX1/TX1 RX2/TX2
  now=$(date +%s)
  if [ "$WINDOW_START" -gt 0 ] &&
     [ $((now - WINDOW_START)) -ge "$WINDOW_SECS" ]; then
    RELOADS=0; WINDOW_START=0; CAP_LOGGED=0
  fi
  if [ "$RELOADS" -ge "$MAX_RELOADS" ]; then
    if [ "$CAP_LOGGED" -eq 0 ]; then
      log "reload cap reached ($RELOADS/$MAX_RELOADS in the current hour window; rx $RX1→$RX2 tx $TX1→$TX2): suspending reloads until the window clears"
      CAP_LOGGED=1
      save_state
    fi
    return 0
  fi
  # 0, 60, 180 between attempts; raising the cap past 3 keeps the 180 s sleep
  case "$RELOADS" in
    1) sleep 60 ;;
    2) sleep 180 ;;
  esac
  log "stall confirmed: probes $THRESHOLD/$THRESHOLD failed to $HOST, rx $RX1→$RX2 stationary, tx $TX1→$TX2 advanced; reload attempt $((RELOADS + 1))"
  if eval "$RELOAD_CMD" >/dev/null 2>&1; then :; else
    log "reload command failed (rc=$?); monitoring continues"
  fi
  RELOADS=$((RELOADS + 1))
  [ "$WINDOW_START" -eq 0 ] && WINDOW_START=$now
  save_state
  after_reload
}

# one host-check cycle: returns silently skipped, logs otherwise.
# STALLED, RX1/TX1, RX2/TX2, RELOADS, WINDOW_START, CAP_LOGGED are global.
one_cycle() {
  if ! iface_ok || ! host_present; then return 1; fi
  RX1=$(read_cnt rx_packets); TX1=$(read_cnt tx_packets)
  if probe_ok; then
    if [ "$STALLED" -ne 0 ]; then
      STALLED=0
      log "recovered: $HOST answers the probe (rx $RX1 tx $TX1)"
    fi
    return 1
  fi
  STALLED=1
  log "probe 1/$THRESHOLD to $HOST failed (rx $RX1 tx $TX1)"
  k=2
  while [ "$k" -le "$THRESHOLD" ]; do
    sleep "$INTERVAL"
    if ! iface_ok || ! host_present; then
      log "$IF or $HOST left during the probe window; discarding this window"
      return 1
    fi
    RX2=$(read_cnt rx_packets); TX2=$(read_cnt tx_packets)
    if probe_ok; then
      STALLED=0
      log "recovered: $HOST answers probe $k/$THRESHOLD (rx $RX2 tx $TX2)"
      return 1
    fi
    log "probe $k/$THRESHOLD to $HOST failed (rx $RX2 tx $TX2)"
    k=$((k + 1))
  done
  # all probes failed: this counter read closes the window
  RX2=$(read_cnt rx_packets); TX2=$(read_cnt tx_packets)
  # RX2=RX1 (stagnant) AND TX2>TX1 (still transmitting) is the stall pair
  if [ "$RX2" = "$RX1" ] && [ "$TX2" -gt "$TX1" ] 2>/dev/null; then
    maybe_reload
  else
    log "no reload: $THRESHOLD/$THRESHOLD probes to $HOST failed but the counters disagree (rx $RX1→$RX2, tx $TX1→$TX2; needs stationary rx AND advancing tx)"
  fi
  return 0
}

RELOADS=0; WINDOW_START=0; CAP_LOGGED=0; STALLED=0; CYCLES=0
load_state() { RELOADS=0; WINDOW_START=0; CAP_LOGGED=0; [ -f "$STATE" ] && . "$STATE"; return 0; }
load_state

log "watchdog on $IF: host $HOST, interval ${INTERVAL}s, $THRESHOLD probes, cap $MAX_RELOADS/$WINDOW_SECS s"

while :; do
  one_cycle
  if [ "$MAX_CYCLES" -gt 0 ]; then
    CYCLES=$((CYCLES + 1))
    [ "$CYCLES" -ge "$MAX_CYCLES" ] && break
  fi
  sleep "$INTERVAL"
done
