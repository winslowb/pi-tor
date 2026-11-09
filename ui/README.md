# pi-tor config UI (`ui/`)

A single-page web app in the Python **standard library only** (no pip, no
npm, no build step) that edits the pi-tor configuration through one
validated form and applies it. It exists because the subnet / gateway /
interface / port values were duplicated across `tor/torrc`,
`docker-compose.yml`, `bin/pi-tor-rules.sh` env and
`systemd/pi-tor.env.example` with no single source of truth; changing the
subnet by hand silently restart-loops tor and kills dnsmasq. Here, one
schema (`config_schema.py`) renders all targets and validates before any
write.

## Security, plainly

**Mounting `/var/run/docker.sock` into the ui container is root-equivalent
on the host.** So is applying the firewall rules: the container holds
`CAP_NET_ADMIN` on the host network namespace, and `bin/pi-tor-rules.sh`
run inside it writes the **host's** nat/filter tables — same access as the
socket, one shared implementation. The HTTP Basic password is the only
boundary in front of either. There is no session, no IP filter, no rate
limit beyond what the OS provides. Only run this UI on a network you
control, and set a real `PI_TOR_UI_PASSWORD` in `.env`. Do not expose it
through the tor proxy.

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
| `POST /api/rules/apply` | `{confirm: true}` — re-run `bin/pi-tor-rules.sh apply` against the current parsed config (the one the container runs at start); 400 on validation errors |
| `POST /api/rules/flush` | `{confirm: true}` — remove the redirect: the recovery path |
| `GET /api/logs?service=tor|pihole&lines=200` | container logs |
| `GET /api/status` | dashboard JSON, incl. the read-only `uplink` panel and the `rules` state shown in the dashboard card |

Auth: HTTP Basic, user `pi-tor`, password from `PI_TOR_UI_PASSWORD`
(`.env`), compared with `hmac.compare_digest`. Secrets never leave `/api/config`
masked; a blank/masked secret in a POST means *keep the current value*.

## Tor listener topology (why the binds look like this)

`torrc` binds three kinds of listeners and they differ in what may depend on
the gadget interface:

- `SocksPort 0.0.0.0:<socks>` — the only wildcard bind. It exists so tor can
  bind before `usb0` is addressed (the healthcheck and the workstation both
  go through it), and it is safe only because `SocksPolicy` below it is a
  source ACL tor enforces per connection (`accept 127.0.0.1`, `accept
  <subnet>`, `reject *` last — non-listed sources are accepted by default, so
  the terminator must stay last). A second explicit-loopback `SocksPort` on
  the same port cannot co-exist with the wildcard listener: the kernel
  refuses with EADDRINUSE in either bind order (verified against tor
  0.4.9).
- `TransPort <gateway>:<port>` and `DNSPort <gateway>:<port>` — the service
  path. A nat `PREROUTING` REDIRECT rewrites the destination to the incoming
  interface's own primary address (not loopback; locally-generated packets
  are the ones mapped to 127.0.0.1), so these binds require the gadget
  address. They **must never go wildcard**: neither listener has a source
  ACL, so a wildcard would expose an unauthenticated transparent proxy and
  an open resolver on the Pi's other interfaces (e.g. Wi-Fi). `DNSPort` also
  binds `127.0.0.1` because Pi-hole's upstream
  (`FTLCONF_dns_upstreams`) is `127.0.0.1#<dns>`.

`bin/uplink-check.sh` covers the start-ordering gap: after the uplink gate
passes it waits up to 30 s (one log line per second) until every gadget
address scraped from the mounted `torrc` is assigned to the host; the
addresses come from `torrc` itself so the wait cannot drift from the
rendered config, and it reads `/proc/net/fib_trie` because the tor image has
no `ip`. If the bound is reached the container exits 1 and keeps
restart-looping slowly, with the dashboard still explaining why tor is down.

## Apply semantics

0. On container start the parsed config is validated and the rules are
   applied (`bin/pi-tor-rules.sh apply`, idempotent) — before HTTP serving,
   skipped silently in dry run and with a visible log line for an invalid
   config. On a non-`nf_tables` `iptables -V` output the apply is refused
   with a visible error: a legacy backend would edit a nat ruleset nothing
   on the Pi reads. `docker compose up -d` is therefore the only bring-up
   step; there is no systemd rules unit any more.
1. Files that change are backed up to `ui/backups/<UTC-stamp>/` (relative
   paths preserved) with a `manifest.json` of originals + sha256.
2. All four render targets (`tor/torrc`, `.env`, `.env.example`,
   `systemd/pi-tor.env.example`) are written atomically (`tmp` +
   `os.replace`, file mode preserved).
3. Restart routing: torrc changed → restart `tor`; any `.env` key compose
   passes to Pi-hole (TZ, password, query logging, interface, DNS port, EDNS)
   → `docker compose up -d --no-deps pihole` (recreate — a plain restart does
   not re-read env); rules keys changed (interface, subnet, gateway,
   trans/dns ports) → `bin/pi-tor-rules.sh apply` with explicit
   `PI_TOR_*` env overrides (the container's CAP_NET_ADMIN writes the
   host's tables). `/api/rules/apply` re-runs the same script on demand;
   `/api/rules/flush` is its recovery counterpart — flush never needs the
   redirect: HTTP to the Pi's own address stays alive because the chain's
   RETURN rules keep traffic to the protected hosts out of the redirect,
   which is the property that makes self-applied rules safe to ship. The
   apply path also hard-refuses (script and schema) when `protected_hosts`
   omits the gateway IP — that config would lock the operator out of SSH,
   Pi-hole and this UI in one stroke.
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

The startup rules apply and both `/api/rules/*` endpoints report
`{"skipped": "dry-run"}` instead of touching iptables, and the version
probe is skipped too. Two deliberate exceptions keep working in dry run
because they are strictly read-only: the uplink panel (`ip -j addr`,
`ip -j route`, `iw dev <if> link`) and its submission checks. Nothing they
run can change state.

## Uplink panel & protected hosts

The dashboard shows every non-loopback interface (name, operstate, IPv4,
default route) plus a lease badge for the configured uplink: green =
IPv4 + default route, amber = interface present without a lease or
without the default route, red = absent. The Wi-Fi SSID is best effort
via `iw`; when it is unavailable it reads *unknown* — names are never
invented. The uplink panel renders identically in dry run.

Hosts listed in `PI_TOR_PROTECTED_HOSTS` (schema field `protected_hosts`,
default: the gateway IP) get a `-d <host> -j RETURN` rule at the top of
the `PI_TOR_REDIRECT` chain, before every REDIRECT, so traffic to the Pi
itself is never hijacked into tor. `bin/pi-tor-rules.sh show-rules`
prints the chain rules in apply order without touching the firewall.

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
  (installed in `Dockerfile`); only the nft backend is accepted, checked
  via `iptables -V` before any apply.
- `02-upstream-tor.conf` and `99-tor-upstream.conf` are gone: Pi-hole v6
  takes the upstream from `FTLCONF_dns_upstreams`, so the duplicated
  dnsmasq snippets had no effect and only risked contradicting the FTL keys.
- The compose mount path for docker CLI plugins
  (`/usr/libexec/docker/cli-plugins`) is Debian's default; adjust for your
  host if it differs.
