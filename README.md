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
  prints the exact nat **and filter** rule list, in apply order, without
  touching the firewall. While applied, it also **drops non-DNS UDP** arriving
  on the gadget interface (INPUT and FORWARD): TCP and DNS are redirected
  into tor but UDP is not, so QUIC would go direct (unprotected) or hang —
  the drop forces the TCP fallback that tor carries. This also kills mDNS
  and any other UDP on the tether, which is intended. The **ui
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
- A gadget RX watchdog (`bin/gadget-watchdog.sh` +
  `systemd/pi-tor-gadget-watchdog.service`) that re-initialises `g_ether`
  when the tether is genuinely stalled on receive (two failed probes +
  stationary `rx_packets` while `tx_packets` still moves, only when a host
  is actually tethered, capped at 3 reloads/hour) — see
  [Gadget RX watchdog](#gadget-rx-watchdog)
- `bin/usb_host_profile` — the tethering host's companion script: one
  static NetworkManager profile (`enx*,usb*` name-glob match) so a
  re-enumeration never leaves the workstation dead
- A host-side tether UI (`hostui/`) that runs on the tethered **workstation**
  (loopback only, stdlib, no build step): on/off toggle for the USB tether,
  a live status panel, and a dead-man revert that restores the host's normal
  routing when the Pi stops answering — see below
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

## Host tether UI (hostui/) — browser toggle + dead-man revert

`hostui/` runs on the tethered **workstation**, not on the Pi: a stdlib-only
`http.server` app (no dependencies, no build step, same Gruvbox look as the
Pi's config UI) at `http://127.0.0.1:8090` with a status panel and one
toggle. Toggling runs `bin/usb_route` / `bin/usb_route_undo` through
`sudo -n` with a fixed argument list, and the UI keeps probing the Pi: if
the Pi stops answering while the tether is up, the host is put back on its
normal routing automatically (friendly dead-man, not a kill switch).

```bash
./hostui/app.py                    # or: python3 hostui/app.py
# PI_TOR_HOSTUI_DRY_RUN=1 ./hostui/app.py       # never executes anything
```

### sudo setup (required for the toggle)

The app never runs with root; it invokes `sudo -n <absolute script path>`.
Without the rule the toggle reports exactly what is missing instead of a
generic error. Permit **only** the two tether scripts for the user running
the app, with the absolute paths of your checkout:

```bash
sudo tee /etc/sudoers.d/pi-tor-tether <<'EOF'
bill ALL=(root) NOPASSWD: /home/bill/pi-tor/bin/usb_route, /home/bill/pi-tor/bin/usb_route_undo
EOF
sudo chmod 440 /etc/sudoers.d/pi-tor-tether && sudo visudo -c
```

Also make sure the two scripts are owned by root and not writable by group/
others, so nothing can rewrite what sudo will execute.

### Keep the dead-man alive (systemd --user + linger)

The dead-man revert **only works while the UI process is running** — if the
process dies while tethered, nothing reverts. Run it as a systemd user unit
and enable linger (so it survives without you):

```bash
mkdir -p ~/.config/systemd/user && cp hostui/pi-tor-hostui.service \
  ~/.config/systemd/user/pi-tor-hostui.service
# adjust the ExecStart path if the repo is not at $HOME/pi-tor
systemctl --user daemon-reload
loginctl enable-linger "$USER"
systemctl --user enable --now pi-tor-hostui.service
```

### Security notes

- Loopback-only bind (`127.0.0.1:8090`); a non-loopback bind is refused at
  startup unless `PI_TOR_HOSTUI_ALLOW_ANY=1` is set explicitly. Loopback
  binds are still attacker-friendly if a malicious page can call
  `http://127.0.0.1:8090`, which is why every mutating request must carry
  the CSRF token the page issues (`X-PiTor-Token` header); a cross-origin
  page can neither read it (same-origin policy) nor set it.
- The app shells out only as `sudo -n <script>` with fixed argv (nothing
  from request data reaches a shell). DNS in the status panel is read from
  `resolvectl dns` (read-only, no sudo) with a resolv.conf fallback.
- The app never writes outside the repo except the dead-man state file:
  `$XDG_RUNTIME_DIR/pi-tor-hostui/dead-man.json` (or
  `~/.cache/pi-tor-hostui/dead-man.json`), overridable with
  `PI_TOR_HOSTUI_STATE`. The tether history is in memory (bounded tail at
  `/api/log`).
- `PI_TOR_HOSTUI_DRY_RUN=1` makes the toggle report what it would run
  without executing anything.

### Knobs

| var | default | meaning |
|---|---|---|
| `PI_TOR_HOSTUI_PORT` | `8090` | listen port |
| `PI_TOR_HOSTUI_BIND` | `127.0.0.1` | bind address (loopback enforced) |
| `PI_TOR_HOSTUI_ALLOW_ANY` | unset | `1` allows a non-loopback bind |
| `PI_TOR_HOSTUI_DRY_RUN` | unset | `1` disables all script execution |
| `PI_TOR_HOSTUI_STATE` | runtime dir (above) | dead-man state file |
| `PI_TOR_PI_ADDR` | `10.12.194.1` | the Pi side of the gadget link |
| `PI_TOR_UI_PORT` | `8080` | Pi config-UI port the dead-man probes |
| `PI_TOR_PROBE_INTERVAL` | `15` | probe cadence in seconds |
| `PI_TOR_REVERT_AFTER` | `90` | seconds of consecutive failures before auto-revert |

The dead-man probes the Pi's config-UI port with a TCP connect (ICMP is not
redirected, so ping alone would be misleading), fires `bin/usb_route_undo`
**once** per tether session after `PI_TOR_REVERT_AFTER` seconds of
consecutive failures, logs the reason, and then stops probing until you
re-enable the tether. State survives a UI restart (the session is re-armed
from the state file); it does not survive a process that is down.

## Gadget RX watchdog

Measured on the device, the Pi Zero 2 W's USB gadget occasionally stalls
**on receive**: the Pi keeps transmitting (its ARPs flow out, so
`tx_packets` climbs) while `rx_packets` freezes and every probe dies, and
the tethered machine goes dead even though reboots "fixed" it — they only
re-initialised the gadget. Reloading the gadget module,
`modprobe -r g_ether && modprobe g_ether`, restores RX within seconds.

`bin/gadget-watchdog.sh` (installed as
`systemd/pi-tor-gadget-watchdog.service`, POSIX `sh`, `Restart=always`)
does exactly that, and **only that** when the conditions really hold:

- It acts **only when a host is tethered**: the neighbour table must show
  a link-layer address for `PI_TOR_HOST_ADDR` (default `10.12.194.2`), and
  `usb0` (`PI_TOR_GADGET_IF`) must exist. No host, no gadget, no log line —
  a healthy or idle tether produces **no output at all** (one startup
  config line per service start).
- Two independent signals must **both** agree across one probe window
  before it reloads: the end-to-end probe (`ping -c1 -W1 $PI_TOR_HOST_ADDR`)
  fails `WATCH_FAIL_THRESHOLD=2` times in a row (probes one
  `WATCH_PROBE_INTERVAL=30` s apart), **and** `rx_packets` did not advance
  across the window while `tx_packets` did. Either alone is not enough —
  an idle-but-healthy host proves nothing by staying silent, and a host
  firewall dropping pings proves nothing either.
- Rate limiting: at most `WATCH_MAX_RELOADS_PER_HOUR=3` reloads per hour
  window, with sleeps of 60 s / 180 s before the 2nd / 3rd attempt. The
  cap bookkeeping persists to
  `/var/lib/pi-tor-gadget-watchdog/state` so a restart cannot reset it;
  past the cap it logs one loud line per window and reloads nothing until
  the window clears. A reload is synchronous with the loop, so two
  reloads can never overlap; after one it waits (bounded
  `WATCH_RECOVER_SECONDS=20`) for `usb0` and `10.12.194.1`
  (`PI_TOR_GATEWAY`) to return before probing again.
- Every state change and decision is one `[gadget-watchdog]` line on
  stdout (the journal) with the counters that justified it.

All of it is fixture-testable (`ui/tests/test_watchdog.py`): counters,
neighbour check, probe, reload and wait sources are injectable via
`WATCH_SYSFS`, `WATCH_NEIGH_CMD`, `WATCH_PROBE_CMD`, `WATCH_RELOAD_CMD`,
`WATCH_STATE_FILE`, `WATCH_FIB_TRIE`, `WATCH_MAX_CYCLES`.

Install on the Pi:

```bash
sudo cp systemd/pi-tor-gadget-watchdog.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pi-tor-gadget-watchdog
```

The unit deliberately does **not** wire the stack's `PI_TOR_INTERFACE` —
the watchdog's own knobs are independent of the torrc rendering. Override
them with `systemctl edit pi-tor-gadget-watchdog` if needed.

### Host side: `bin/usb_host_profile`

A reload re-enumerates the gadget, so on the tethered machine the interface
returns with a **new name and no address** — and NetworkManager's
auto-created "Wired connection N" then DHCP-polls forever and flushes
static addresses, which produced hours of false "the Pi is dead"
diagnoses. `bin/usb_host_profile` (run as root on the tethering host) is
the companion step: it creates one static NM profile —
`10.12.194.2/24` (`PI_TOR_HOST_ADDR`), no gateway, `ipv4.never-default
yes`, empty DNS, autoconnect — that survives re-enumeration by matching
`match.interface-name` globs `enx*,usb*` instead of any single interface
name (the name *shape* is stable across renames; a driver match is not,
because the host-side gadget driver varies: cdc_ether, cdc_ncm, rndis_host,
eem). Requires NetworkManager >= 1.14. `--dry-run` prints the exact
`nmcli` commands without changing anything; it refuses to run when a
profile named `pi-tor-gadget` already exists unless `--force`
(delete + re-add); `--remove` takes the profile back out.

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
bin/usb_route[, _undo]     # host-side tether toggle + saved-state undo
hostui/                    # host tether UI: app.py + pi-tor-hostui.service
systemd/                   # optional stack unit + env example
bin/gadget-watchdog.sh     # Pi-side g_ether RX-stall watchdog (reloads only
                           # on a confirmed stall, capped 3/hour)
bin/usb_host_profile       # host-side static NM profile across re-enumerations
collect_pi_support.sh      # diagnostics helper
```

## Planned updates
I'll add TailScale at some point.
