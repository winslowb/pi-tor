# pi-tor

A minimal Docker stack for a USB-gadget Raspberry Pi that runs Pi-hole as the DNS edge and forwards every query through a locally hosted Tor daemon. Plug the Pi Zero into a laptop, share the `usb0` interface, and your DNS + TCP traffic is transparently proxied through Tor.

## What you get

- Hardened Tor container (Debian slim base) with dedicated `torrc`
- Pi-hole configured to listen only on gadget + loopback interfaces and to use
  Tor as its upstream resolver
- Idempotent iptables helper (`bin/pi-tor-rules.sh`) that turns the Pi into a
  transparent proxy for the gadget interface. `PI_TOR_PROTECTED_HOSTS`
  (default: the gateway IP) keeps traffic to the Pi itself out of the
  redirect, so SSH, Pi-hole and the config UI keep working; `show-rules`
  prints the exact rule list without touching the firewall. The **ui
  container applies the rules itself** — once when it starts (idempotent)
  and on demand from the dashboard — and refuses to apply a config whose
  protected hosts omit the gateway, because that would lock you out
- `bin/uplink-check.sh` gates **only** the tor container: tor refuses to
  start when the uplink interface has no IPv4 lease or no default route.
  Pi-hole and the UI still start so the dashboard can explain why tor is
  down. The config UI shows a read-only per-interface uplink panel. Before
  tor starts, the same container also briefly waits (bounded to 30 s, one
  log line per second, addresses scraped from the mounted `torrc`) for the
  gadget-subnet binds to become assignable, so a `usb0` that is attached
  but not yet addressed does not crash-loop tor
- Optional systemd unit for auto-starting the stack on boot (the firewall
  rules are applied by the ui container when it starts, so there is no
  separate rules unit to enable or remember)
- A small configuration web UI (`ui/`) that renders every config file from
  one validated schema, previews diffs, applies with backup + restart, and
  can roll back — see [ui/README.md](ui/README.md). Note: the ui container
  mounts the docker socket, which is root-equivalent on the host; the HTTP
  Basic password is the only boundary in front of it.
- A diagnostic bundle script (`collect_pi_support.sh`) for quick triage

## Requirements

- Raspberry Pi OS (or any Debian-based distro) with the USB gadget interface
  exposed as `usb0`
- Docker Engine 24+ with the Compose plugin (`docker compose`)
- A dedicated IPv4 gadget subnet (defaults to `10.12.194.0/24`)
- iptables is not needed on the host: the ui image ships it (nft backend,
  matching Raspberry Pi OS 12+; a legacy backend is detected and refused)


## First things first
Ensure you've updated both config.txt and cmdline.txt with the right stuff to make your raspberry pi zero work in gadget mode. (this should actually work on a pi 4 or 5 as well) 
Also...lot's of stuff on the internet on how to do this correctly, but note Debian Trixie has made this a little less trivial than it once was. Also, there is a rpi-usb-gadget binary you can use from raspberry pi repo (it should turn 'it' on). Here is my stuff;

```

bill@raspberrypi:/boot $ tail firmware/config.txt 
.... 
[all]
enable_uart=1 #serial console stuff...ignore this
dtoverlay=spi0-1cs #serial console stuff...ignore this too
dtoverlay=dwc2,dr_mode=peripheral #THIS IS THE IMPORTANT STUFF MAN...DO THIS

bill@raspberrypi:/boot $ cat firmware/cmdline.txt 
console=serial0,115200 console=tty1 root=PARTUUID=4a85462b-02 rootfstype=ext4 fsck.repair=yes rootwait quiet splash plymouth.ignore-serial-consoles #THIS TOO...DO THIS

```
And also...don't forget to enable ssh on the pi and add your keys

### some snark
it should look like this when your ready to go;
![this thing](doc/PXL_20251112_185810485.MP.jpg)


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
4. Start the stack — this is the whole bring-up. The ui container applies
   the iptables rules itself when it starts (and re-applies on every boot,
   idempotently):
   ```bash
   docker compose up -d --build
   ```
5. Point your tethered workstation at the gadget IP (`10.12.194.1` by default)
   for DNS and default gateway. Browse to `http://10.12.194.1/admin` to reach
   the Pi-hole UI and `http://10.12.194.1:8080` to reach the config UI.

Stop everything by running `docker compose down` followed by
`sudo bin/pi-tor-rules.sh flush` (or the *Flush firewall rules* button in
the config UI while the stack is up — HTTP to the Pi's own address stays
reachable because the RETURN rule keeps it out of the redirect).

## Customisation checklist

The repo defaults assume `usb0` with subnet `10.12.194.0/24`. Update the
following files if your gadget interface or network differs:

- `pihole/etc-dnsmasq.d/02-listen.conf` – listen addresses
- `pihole/etc-dnsmasq.d/02-usb0.conf` – interface name + EDNS size
- `tor/torrc` – `SocksPort`, `TransPort`, `DNSPort`, ACLs
- `.env` – Pi-hole timezone/password/logging
- `systemd/pi-tor.env.example` / `bin/pi-tor-rules.sh` env vars – interface and
  subnet controls
- `bin/usb_route` / `bin/usb_route_undo` – tether the workstation through the
  Pi over the gadget link. Interface-agnostic: they detect the gadget (`enx*`/
  `usb*`, preferring the one on the `PI_TOR_SUBNET` subnet when several exist),
  detect the primary interface (whatever holds the default route — wired or
  Wi-Fi), then save that exact state and restore exactly it. Nothing is taken
  down: the gadget's metric-5 default simply outranks the DHCP default
  (100 wired / 600 Wi-Fi), and if a primary ever advertises metric ≤ 5 the
  tether lowers its own metric below it instead. Requires systemd-resolved.
  Start with `bin/usb_route --dry-run`, then re-run without it; undo with
  `bin/usb_route_undo` (which refuses if the saved state is missing). State
  lives in `${XDG_STATE_HOME:-$HOME/.local/state}/pi-tor/tether.conf`;
  overrides: `PI_TOR_SUBNET`, `PI_TOR_GATEWAY`, `PI_TOR_STATE_DIR`.
- `PI_TOR_UPLINK` – the interface tor must bootstrap through (default
  `wlan0`; set in `.env` before `docker compose up`, or `PI_TOR_UPLINK=`
  on the compose shell env). The UI validates it but never configures the
  link itself — joining a Wi-Fi network stays your job
- `PI_TOR_PROTECTED_HOSTS` – IPv4 addresses never diverted into tor
  (default: the gateway IP)

## Systemd (optional)

The firewall rules need no unit of their own: the ui container applies
them on start, so `docker compose up` is the only bring-up step. To have
the stack come up on boot:

1. Copy `systemd/pi-tor.env.example` to `/etc/default/pi-tor` and update
   `PROJECT_DIR` (any `PI_TOR_*` overrides there feed the stack unit).
2. Copy the stack unit:
   ```bash
   sudo cp systemd/pi-tor-stack.service /etc/systemd/system/
   ```
3. `sudo systemctl daemon-reload`
4. Enable + start:
   ```bash
   sudo systemctl enable --now pi-tor-stack.service
   ```

`pi-tor-stack` runs `docker compose up -d --build` from `PROJECT_DIR` on
boot; the ui container inside it applies the firewall rules. For a manual
run of the rules themselves (e.g. flushing after a `compose down`),
`bin/pi-tor-rules.sh apply|flush|show-rules` remains the single
implementation — run it with `sudo` when the stack is not up.

## Diagnostics

Run `./collect_pi_support.sh` to capture system state, docker details,
Pi-hole dumps, Tor status, and networking info into `support/` for sharing.

## Repository layout

```
docker-compose.yml         # Tor + Pi-hole + config-UI stack
pihole/etc-dnsmasq.d/      # Pi-hole dnsmasq overrides (tracked)
pihole/etc-pihole/.gitkeep # bind mount placeholder (data ignored)
tor/                       # Dockerfile + torrc + data dir placeholder
bin/pi-tor-rules.sh        # iptables helper (apply|flush|show-rules),
                           # executed by the ui container, sudo for manual runs
bin/uplink-check.sh        # tor-side uplink gate (IPv4 lease + default route)
systemd/                   # optional stack unit + env example
collect_pi_support.sh      # diagnostics helper
```

## Planned updates
I'll add TailScale at some point.
