#!/usr/bin/env bash
# deploy-pi-tor-pihole.sh
# Places all project files and data under /home/bill/.docker/$PROJECT

set -euo pipefail

PROJECT="pi-tor-pihole"
BASE="/home/bill/.docker/${PROJECT}"
USER_HOME="/home/bill"
PI_USER="bill"

# Ensure base layout
mkdir -p "${BASE}"/{tor,pihole/etc-pihole,pihole/etc-dnsmasq.d,bin,systemd}

############################
# docker-compose.yml
############################
cat > "${BASE}/docker-compose.yml" <<'YAML'
version: "3.8"

services:
  tor:
    build: ./tor
    container_name: tor
    network_mode: "host"
    restart: unless-stopped
    volumes:
      - ./tor/torrc:/etc/tor/torrc:ro
      - ./tor/tor-data:/var/lib/tor
    cap_add:
      - NET_ADMIN
    healthcheck:
      test: ["CMD-SHELL", "pgrep -f /usr/bin/tor || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "5m"
        max-file: "2"

  pihole:
    image: pihole/pihole:latest
    container_name: pihole
    network_mode: "host"
    restart: unless-stopped
        environment:
      TZ: "UTC"
      WEBPASSWORD: "changeme"
      DNS1: "127.0.0.1#5353"
      DNS2: "127.0.0.1#5353"
      DNSMASQ_LISTENING: "all"
      PIHOLE_DNS_: "127.0.0.1#5353"
      DNS_QUERY_LOGGING: "false"
      ServerIP: "0.0.0.0"
dns:
      - 127.0.0.1
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS --max-time 3 http://127.0.0.1/admin || exit 1"]
      interval: 40s
      timeout: 5s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "5m"
        max-file: "2"
YAML

############################
# tor/Dockerfile
############################
cat > "${BASE}/tor/Dockerfile" <<'DOCKER'
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends tor ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/lib/tor && chown -R debian-tor:debian-tor /var/lib/tor
COPY torrc /etc/tor/torrc
EXPOSE 9050 9040 5353
CMD ["/usr/bin/tor", "-f", "/etc/tor/torrc"]
DOCKER

############################
# tor/torrc + data dir
############################
cat > "${BASE}/tor/torrc" <<'TORRC'
RunAsDaemon 0
Log notice stdout
SocksPort 9050
TransPort 9040
DNSPort 5353
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
CacheDNS 0
AvoidDiskWrites 1
# ExitNodes {us} StrictNodes 1   # optional
TORRC
mkdir -p "${BASE}/tor/tor-data"

############################
# pihole minimal FTL retention
############################
cat > "${BASE}/pihole/etc-pihole/pihole-FTL.conf" <<'FTL'
MAXDBDAYS=7
MAXLOGAGE=7
FTL

############################
# iptables rules (kept under project tree)
############################
cat > "${BASE}/bin/pi-tor-rules.sh" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

IN_IF="usb0"       # host plugs into Pi here
UP_IF="wlan0"      # Pi's upstream interface (Wi-Fi/LAN)
TOR_TRANS_PORT="9040"
TOR_DNS_PORT="5353"

# Determine Pi IP on usb0 for exclusion rules
PI_IP="$(ip -4 addr show dev ${IN_IF} | awk '/inet /{print $2}' | cut -d/ -f1)"
: "${PI_IP:=10.0.0.1}"

echo "Applying iptables rules: IN_IF=${IN_IF}, UP_IF=${UP_IF}, PI_IP=${PI_IP}"

# Enable IPv4 forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Flush and rebuild NAT rules in a controlled way
iptables -t nat -F
iptables -F

# Do not redirect traffic destined to the Pi itself (admin UI, SSH, etc.)
iptables -t nat -A PREROUTING -i ${IN_IF} -d ${PI_IP} -j RETURN

# Force DNS to Tor's DNSPort for anything arriving via usb0
iptables -t nat -A PREROUTING -i ${IN_IF} -p udp --dport 53 -j REDIRECT --to-ports ${TOR_DNS_PORT}
iptables -t nat -A PREROUTING -i ${IN_IF} -p tcp --dport 53 -j REDIRECT --to-ports ${TOR_DNS_PORT}

# Redirect all new TCP connections from usb0 to Tor TransPort
iptables -t nat -A PREROUTING -i ${IN_IF} -p tcp -m tcp --syn -j REDIRECT --to-ports ${TOR_TRANS_PORT}

# Allow selective direct ports from usb0 if needed (example: SSH). Uncomment to allow.
# iptables -t nat -A PREROUTING -i ${IN_IF} -p tcp --dport 22 -j RETURN

# Masquerade outbound from Pi if needed for non-Tor traffic leaving via wlan0
iptables -t nat -A POSTROUTING -o ${UP_IF} -j MASQUERADE

echo "iptables rules applied."
BASH
chmod +x "${BASE}/bin/pi-tor-rules.sh"

############################
# systemd unit for iptables rules
############################
cat > "${BASE}/systemd/pi-tor-rules.service" <<SYSTEMD
[Unit]
Description=Apply iptables rules for Pi Tor transparent proxy
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${BASE}/bin/pi-tor-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SYSTEMD

############################
# systemd unit for docker compose stack
############################
cat > "${BASE}/systemd/pi-tor-stack.service" <<SYSTEMD
[Unit]
Description=pi-tor-pihole docker compose stack
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${BASE}
ExecStart=/usr/bin/docker-compose up -d --build
ExecStop=/usr/bin/docker-compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
SYSTEMD

############################
# Symlink units into /etc/systemd/system
############################
sudo ln -sf "${BASE}/systemd/pi-tor-rules.service" /etc/systemd/system/pi-tor-rules.service
sudo ln -sf "${BASE}/systemd/pi-tor-stack.service"  /etc/systemd/system/pi-tor-stack.service

# Ownership so you can edit as bill; docker will still run as root
sudo chown -R "${PI_USER}:${PI_USER}" "${BASE}"

echo "Building and starting stack..."
cd "${BASE}"
sudo /usr/bin/docker-compose up -d --build

echo "Applying iptables rules..."
sudo "${BASE}/bin/pi-tor-rules.sh"

echo "Enabling services..."
sudo systemctl daemon-reload
sudo systemctl enable --now pi-tor-stack.service
sudo systemctl enable --now pi-tor-rules.service

echo "Done."
echo "Project home: ${BASE}"
echo "Pi-hole admin: http://<pi-wlan0-ip>/admin and http://<pi-usb0-ip>/admin"

