# pi-tor

A minimal Docker stack for a USB-gadget Raspberry Pi that runs Pi-hole as the DNS edge and forwards every query through a locally hosted Tor daemon. Plug the Pi Zero into a laptop, share the `usb0` interface, and your DNS + TCP traffic is transparently proxied through Tor.

## What you get

- Hardened Tor container (Debian slim base) with dedicated `torrc`
- Pi-hole configured to listen only on gadget + loopback interfaces and to use
  Tor as its upstream resolver
- Idempotent iptables helper (`bin/pi-tor-rules.sh`) that turns the Pi into a
  transparent proxy for the gadget interface
- Optional systemd units for auto-starting the stack and the firewall rules
- A diagnostic bundle script (`collect_pi_support.sh`) for quick triage

## Requirements

- Raspberry Pi OS (or any Debian-based distro) with the USB gadget interface
  exposed as `usb0`
- Docker Engine 24+ with the Compose plugin (`docker compose`)
- A dedicated IPv4 gadget subnet (defaults to `10.12.194.0/24`)
- `iptables-nft` (or legacy `iptables`)


## First things first
Ensure you've updated both config.txt and cmdline.txt with the right stuff to make your raspberry pi zero work in gadget mode. (this shoudl actually work on a pi 4 or 5 as well) 
Also...lot's of stuff on the internet on how to do this correctly, but note Debian Trixie has made this a little less trivial than it once was. Also, there is a rpi-usb-gadget binary you can use from raspberry pi repo (it should turn 'it' on). Here is my stuff;

```

bill@raspberrypi:/boot $ tail firmware/config.txt 
.... 
[all]
 enable_uart=1 #serial console stuff...ignore this
dtoverlay=spi0-1cs #serial console stuff...ignore this too
dtoverlay=dwc2,dr_mode=peripheral #THIS IS THE IMPORTANT...DO THIS

bill@raspberrypi:/boot $ cat firmware/cmdline.txt 
console=serial0,115200 console=tty1 root=PARTUUID=4a85462b-02 rootfstype=ext4 fsck.repair=yes rootwait quiet splash plymouth.ignore-serial-consoles

```


## Quick start

1. Clone and enter the repo:
   ```bash
   git clone https://github.com/your-user/pi-tor.git
   cd pi-tor
   ```
2. Copy the environment file and adjust the values you care about:
   ```bash
   cp .env.example .env
   $EDITOR .env                     # change TZ, Pi-hole password, logging, …
   ```
3. Ensure the bind-mounted data directories exist (they stay empty in git):
   ```bash
   mkdir -p pihole/etc-pihole tor/tor-data
   ```
4. Apply the iptables rules (run as root). Adjust `PI_TOR_*` env vars if your
   gadget interface or subnet differs:
   ```bash
   sudo PI_TOR_INTERFACE=usb0 bin/pi-tor-rules.sh apply
   ```
5. Start the stack:
   ```bash
   docker compose up -d --build
   ```
6. Point your tethered workstation at the gadget IP (`10.12.194.1` by default)
   for DNS and default gateway. Browse to `http://10.12.194.1/admin` to reach
   the Pi-hole UI.

Stop everything by running `docker compose down` followed by
`sudo bin/pi-tor-rules.sh flush`.

## Customisation checklist

The repo defaults assume `usb0` with subnet `10.12.194.0/24`. Update the
following files if your gadget interface or network differs:

- `pihole/etc-dnsmasq.d/02-listen.conf` – listen addresses
- `pihole/etc-dnsmasq.d/02-usb0.conf` – interface name + EDNS size
- `tor/torrc` – `SocksPort`, `TransPort`, `DNSPort`, ACLs
- `.env` – Pi-hole timezone/password/logging
- `systemd/pi-tor.env.example` / `bin/pi-tor-rules.sh` env vars – interface and
  subnet controls

## Systemd (optional)

1. Copy `systemd/pi-tor.env.example` to `/etc/default/pi-tor` and update
   `PROJECT_DIR` plus any `PI_TOR_*` overrides.
2. Copy the service files:
   ```bash
   sudo cp systemd/pi-tor-*.service /etc/systemd/system/
   ```
3. `sudo systemctl daemon-reload`
4. Enable + start:
   ```bash
   sudo systemctl enable --now pi-tor-rules.service
   sudo systemctl enable --now pi-tor-stack.service
   ```

The `pi-tor-rules` unit wires up iptables; `pi-tor-stack` runs
`docker compose up -d --build` from `PROJECT_DIR` on boot.

## Diagnostics

Run `./collect_pi_support.sh` to capture system state, docker details,
Pi-hole dumps, Tor status, and networking info into `support/` for sharing.

## Repository layout

```
docker-compose.yml        # Tor + Pi-hole stack
pihole/etc-dnsmasq.d/     # Pi-hole dnsmasq overrides (tracked)
pihole/etc-pihole/.gitkeep# bind mount placeholder (data ignored)
tor/                      # Dockerfile + torrc + data dir placeholder
bin/pi-tor-rules.sh       # iptables helper
systemd/                  # optional unit files + env example
collect_pi_support.sh     # diagnostics helper
```

Everything else (Pi-hole gravity DB, Tor keys, support bundles, .env) stays
locally and is gitignored so the GitHub repo only contains what new users need.
