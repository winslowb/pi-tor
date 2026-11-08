# pi-tor config UI (`ui/`)

A single-page web app in the Python **standard library only** (no pip, no
npm, no build step) that edits the pi-tor configuration through one
validated form and applies it. It exists because the subnet / gateway /
interface / port values were duplicated across `tor/torrc`, three
`pihole/etc-dnsmasq.d/*.conf` files, `bin/pi-tor-rules.sh` env and
`systemd/pi-tor.env.example` with no single source of truth; changing the
subnet by hand silently restart-loops tor and kills dnsmasq. Here, one
schema (`config_schema.py`) renders all targets and validates before any
write.

## Security, plainly

**Mounting `/var/run/docker.sock` into the ui container is root-equivalent
on the host.** The HTTP Basic password is the only boundary in front of it.
There is no session, no IP filter, no rate limit beyond what the OS
provides. Only run this UI on a network you control, and set a real
`PI_TOR_UI_PASSWORD` in `.env`. Do not expose it through the tor proxy.

## Layout

| file | role |
|---|---|
| `config_schema.py` | the ~15 knobs, defaults, types, validation rules |
| `render.py` | parses the config tree and renders every target file |
| `app.py` | HTTP routing/serve (stdlib `http.server`), Basic auth |
| `apply.py` | backup → atomic write → restart-what-changed → health poll |
| `dockerops.py` | minimal stdin HTTP/1.1 client over the docker unix socket + compose/rules subprocess helpers |
| `uplink.py` | read-only host network state: per-interface rows `ip -j addr`/`ip -j route`, `iw` SSID probe, uplink lease verdicts |
| `status.py` | dashboard JSON (services, bootstrap %, exit IP, counters, rules, uplink) |
| `templates/`, `static/` | the page; all assets local, no CDN/webfonts |

## HTTP surface

| route | what |
|---|---|
| `GET /` | dashboard + config form + raw-file viewer |
| `GET /api/config` | parsed values (secrets masked), raw files, validation state |
| `POST /api/preview` | `{values}` → per-file unified diff + errors; writes nothing. A changed `uplink_interface` missing on this host is an **error** (400); missing lease/default route is a **warning** (write not blocked); response carries `warnings` |
| `POST /api/apply` | `{confirm: true, values}` — backup, write, restart only what changed, health poll 90 s; the report echoes uplink `warnings` |
| `POST /api/rollback` | restore newest `ui/backups/<stamp>/` and restart |
| `GET /api/logs?service=tor|pihole&lines=200` | container logs |
| `GET /api/status` | dashboard JSON, incl. the read-only `uplink` panel |

Auth: HTTP Basic, user `pi-tor`, password from `PI_TOR_UI_PASSWORD`
(`.env`), compared with `hmac.compare_digest`. Secrets never leave `/api/config`
masked; a blank/masked secret in a POST means *keep the current value*.

## Apply semantics

1. Files that change are backed up to `ui/backups/<UTC-stamp>/` (relative
   paths preserved) with a `manifest.json` of originals + sha256.
2. All seven render targets plus `.env`/`.env.example` are written
   atomically (`tmp` + `os.replace`, file mode preserved).
3. Restart routing: torrc changed → restart `tor`; dnsmasq confs changed →
   restart `pihole`; `.env` TZ/webpassword/logging changed →
   `docker compose up -d --no-deps pihole` (recreate — a plain restart does
   not re-read env); rules keys changed (interface, subnet, gateway,
   trans/dns ports) → `bin/pi-tor-rules.sh apply` with explicit
   `PI_TOR_*` env overrides (needs the container's CAP_NET_ADMIN).
4. Health is polled for up to 90 s; a failed restart surfaces the last 50
   log lines and points at the Rollback button. **No auto-rollback.**
5. `ui_port`/`ui_password` changes only take effect on the next
   `docker compose up` of the ui service itself.

## Dry run

`PI_TOR_UI_DRY_RUN=1` (compose passes `${PI_TOR_UI_DRY_RUN:-0}`) disables
every docker socket call and every privileged subprocess — the page, config
parsing, preview, backup and file writes still work, so the image can be
exercised on any machine with:

    docker run --rm -p 18080:8080 -e PI_TOR_UI_DRY_RUN=1 \
      -e PI_TOR_UI_PASSWORD=test -v "$PWD":/project pi-tor-ui:test

Two deliberate exceptions keep working in dry run because they are
strictly read-only: the uplink panel (`ip -j addr`, `ip -j route`,
`iw dev <if> link`) and its submission checks. Nothing they run can
change state.

## Uplink panel

The dashboard shows every non-loopback interface (name, operstate, IPv4,
default route) plus a lease badge for the configured uplink: green =
IPv4 + default route, amber = interface present without a lease or
without the default route, red = absent. The Wi-Fi SSID is best effort
via `iw`; when it is unavailable it reads *unknown* — names are never
invented. The uplink panel renders identically in dry run.

## Tests

    python3 -m unittest discover -s ui/tests -v

The test suite needs nothing but the stdlib; `test_render_defaults_are_byte_identical`
proves all rendered files round-trip byte-for-byte against the committed
defaults.

## Known limits (honest)

- Pi-hole counters are best effort: the v5 `api.php` summary is tried
  first, then the v6 auth'd `/api/stats/summary` (two header spellings).
  If both fail the dashboard says so instead of inventing numbers.
- Exit-IP uses a minimal SOCKS5 client through `127.0.0.1:<socks_port>`
  to a plain-HTTP IP echo service; if tor is not bootstrapped it reports
  *unavailable*.
- The ui container must contain `iptables`/`iproute2` for the rules script
  (installed in `Dockerfile`).
- `02-upstream-tor.conf` and `99-tor-upstream.conf` are near-duplicates;
  both are rendered as committed today (the UI does not consolidate them —
  that is a separate, explicit change).
- The compose mount path for docker CLI plugins
  (`/usr/libexec/docker/cli-plugins`) is Debian's default; adjust for your
  host if it differs.
