#!/usr/bin/env bash
# collect_pi_support.sh - Pi Zero (USB gadget) diagnostics bundle (verbose + fail-safe)
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-${SCRIPT_DIR}}"
OUT_DIR="${OUT_DIR:-${PROJECT_ROOT}/support}"
BUNDLE_TAG="$(date -u +'%Y%m%dT%H%M%SZ')"
TMP_DIR="$(mktemp -d "/tmp/pi-support.${BUNDLE_TAG}.XXXX")"
BUNDLE_PATH="${OUT_DIR}/pi_support_${BUNDLE_TAG}.tar.gz"

SUDO=""; [[ $EUID -ne 0 ]] && SUDO="sudo"

log(){ printf "[%s] %s\n" "$(date -u +'%H:%M:%SZ')" "$*"; }
save(){ local name="$1"; shift; { echo "## $name"; "$@"; } > "${TMP_DIR}/${name}.txt" 2>&1 || true; }
grab(){
  local src="$1" dst="$2" dstdir="${TMP_DIR}/$(dirname "$dst")"
  mkdir -p "$dstdir" || true
  if [[ -e "$src" ]]; then
    $SUDO cp -a "$src" "${TMP_DIR}/${dst}" 2>/dev/null || true
  else
    echo "MISSING: $src" > "${TMP_DIR}/${dst}.missing" 2>/dev/null || true
  fi
}

trap 'rc=$?; log "ERROR: failed at line $LINENO (exit $rc). Partial bundle in ${TMP_DIR}"; exit $rc' ERR

log "Starting Pi diagnostics → ${TMP_DIR}"
mkdir -p "${OUT_DIR}"

# --- System ---
log "Collecting system info..."
save uname            uname -a
save os-release       bash -lc 'cat /etc/os-release'
save uptime           uptime
save date_utc         date -u +"%Y-%m-%dT%H:%M:%SZ"
save lsblk            lsblk -o NAME,MAJ:MIN,RM,SIZE,RO,TYPE,MOUNTPOINT
save df               df -hT

# --- Networking ---
log "Collecting networking state..."
save ip_addr          ip -4 addr show
save ip_route         ip -4 route show table main
save sysctl_forward   bash -lc '$SUDO sysctl net.ipv4.ip_forward'
save sysctl_rpf       bash -lc '$SUDO sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.usb0.rp_filter'
save ss_listen        ss -lntu
save iptables_filter  bash -lc '$SUDO iptables -S'
save iptables_nat     bash -lc '$SUDO iptables -t nat -S'
save nft_ruleset      bash -lc '$SUDO nft list ruleset || true'
save nmcli_device     bash -lc 'nmcli -g GENERAL.DEVICE,GENERAL.STATE,IP4.ADDRESS,IP4.GATEWAY device show || true'
save resolv_conf      bash -lc 'cat /etc/resolv.conf || true'

# --- Project files ---
log "Grabbing project files..."
grab "${PROJECT_ROOT}/docker-compose.yml" "project/docker-compose.yml"
grab "${PROJECT_ROOT}/bin/pi-tor-rules.sh" "project/bin/pi-tor-rules.sh"
grab "${PROJECT_ROOT}/tor/torrc"          "project/tor/torrc"
if [[ -d "${PROJECT_ROOT}/tor/tor-data" ]]; then
  bash -lc "$SUDO find '${PROJECT_ROOT}/tor/tor-data' -maxdepth 2 -printf '%M %u:%g %p\n'" > "${TMP_DIR}/project/tor/tor-data.perms.txt" 2>/dev/null || true
fi

# --- Docker state ---
log "Collecting Docker state..."
save docker_ps            bash -lc '$SUDO docker ps -a'
save docker_info          bash -lc '$SUDO docker info || true'
save docker_networks      bash -lc '$SUDO docker network ls || true'
save docker_compose_cfg   bash -lc "cd '${PROJECT_ROOT}' && docker compose config || true"

for svc in pihole tor; do
  if docker ps --format '{{.Names}}' | grep -q "^${svc}\$"; then
    log "Collecting logs for ${svc}..."
    save "logs_${svc}"        bash -lc "$SUDO docker logs --tail=500 ${svc}"
    save "inspect_${svc}"     bash -lc "$SUDO docker inspect ${svc}"
    save "health_${svc}"      bash -lc "$SUDO docker inspect --format='{{json .State.Health}}' ${svc} || true"
  fi
done

# --- Pi-hole internals ---
log "Pi-hole internals..."
grab "/etc/pihole"              "pihole/etc-pihole"
grab "/etc/dnsmasq.d"           "pihole/etc-dnsmasq.d"
save pihole_status              bash -lc '$SUDO docker exec pihole pihole status || true'
save pihole_gravity_count       bash -lc '$SUDO docker exec pihole bash -lc '\''sqlite3 /etc/pihole/gravity.db "select count(*) from gravity;"'\''' || true

# --- Tor sanity ---
log "Tor sanity..."
save tor_ports                  bash -lc "$SUDO ss -lntu | grep -E ':(9040|9050|5353)' || true"
save tor_resolve                bash -lc "$SUDO docker exec tor sh -lc 'tor-resolve example.com 127.0.0.1:9050 && echo OK' || true"

# --- NM shared overrides ---
grab "/etc/NetworkManager/dnsmasq-shared.d" "networkmanager/dnsmasq-shared.d"

# --- Optional short capture on usb0 (5s) ---
if command -v tcpdump >/dev/null 2>&1; then
  log "Capturing 5s DNS on usb0..."
  $SUDO timeout 5 tcpdump -ni usb0 -c 50 -vvv -w "${TMP_DIR}/pcap_usb0_5s.pcap" || true
  $SUDO chmod 0644 "${TMP_DIR}/pcap_usb0_5s.pcap" || true
fi

# --- Pack ---
log "Packing bundle..."
tar -C "${TMP_DIR}" -czf "${BUNDLE_PATH}" .
log "PI SUPPORT BUNDLE: ${BUNDLE_PATH}"
echo "${BUNDLE_PATH}"
