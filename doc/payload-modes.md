# Payload modes — UAK-class capabilities on the pi-tor gadget

Status: **draft, nothing implemented.** Branch `feat/payload-modes`.

Goal: decide how much of the USB Army Knife feature set
(<https://github.com/i-am-shodan/USBArmyKnife>) belongs on the Zero 2 W gadget, and give
whatever we keep a home that does not compromise the gateway.

## Verdict

| Capability | Feasible on this board | Notes |
|---|---|---|
| USB HID keyboard (DuckyScript) | yes | configfs `hid.usb0` → `/dev/hidg0` |
| Mass storage (drive / CDROM) | yes | `mass_storage.usb0` on a loop image |
| USB NIC | already shipped | pi-tor *is* this |
| USB NIC + PCAP capture | yes | `tcpdump` on `usb0`, exfil over the uplink or the MSD image |
| Web UI + payload runner | yes | extend the existing stdlib UI |
| Agent / serial command channel | no need | the Pi has IP over `usb0`; SSH and SOCKS beat a shipped agent |
| WiFi deauth / evil twin / handshake capture | **no** | one radio, and it is tor's uplink |
| Bluetooth attacks | no | BlueZ is not Marauder; the radio is shared with WiFi |
| Hot mic | no | no mic, and no free USB port |

Why the radio features are out, not deferred:

- The Zero 2 W has a single wireless chip (bcm43436b0) and it carries tor's circuits. Monitor
  mode drops the association, so a deauth tool here is a device with no uplink and no tor.
- There is no spare USB port to bolt a monitor-mode adapter on. The single data port is the
  gadget port itself.
- Nexmon does have a Zero 2 W patch, but it targets Pi OS 5.10-era firmware/driver. This device
  runs trixie, kernel `6.12.56-v7+`, armv7. Unproven, and it would be fighting the uplink anyway.

## Mode model

The gadget is one USB device with one configuration at a time. Compose functions per mode and
rebind the UDC; do not build one always-on gadget with everything enabled.

| Mode | Functions | Endpoints (IN) | tor + Pi-hole |
|---|---|---|---|
| `gateway` (default) | ECM | 2 | running |
| `payload` | ECM + HID | 3 | running |
| `payload-storage` | ECM + HID + MSD | 4 | running |
| `capture` | ECM (+ optional HID) | 2–3 | running |

Endpoint budget is the hard constraint: DWC2 exposes **7** IN endpoints and each function costs
HID 1, MSD 1, ACM 2, ECM 2, RNDIS 2. ECM + RNDIS + HID + MSD + ACM is 8 and will not bind.
Pick per mode, and validate before binding (`Device or resource busy` / `No space left on
device` is the failure signature).

**ECM stays in every mode on purpose.** tor binds `10.12.194.1` (a literal `usb0` address); if a
mode drops ECM, `usb0` disappears, tor fails to bind and restart-loops. Keeping ECM keeps the
tether, the dashboard and tor alive while a payload runs.

**HID is never armed at attach.** Injecting keystrokes into whatever machine the device is
plugged into — including the workstation being tethered — is not a default. Mode switching is
explicit; a freshly attached gadget enumerates as a NIC only.

## Integration costs specific to this repo

1. **`g_ether` must go.** It is a legacy single-function module; HID/MSD require
   `libcomposite` + configfs. That invalidates the cure in `bin/gadget-watchdog.sh`
   (`modprobe -r g_ether && modprobe g_ether`), which is load-bearing for the documented RX
   stall. The watchdog needs an equivalent *rebind* action (unbind `UDC`, re-create the
   functions, bind again) and its two-signal gate and rate cap must survive the change.
2. **Windows enumeration.** ECM binds on Linux and macOS only. A payload device aimed at a
   Windows host needs an RNDIS function plus MS OS descriptors, which changes the endpoint
   arithmetic and is a separate mode. Decide the target OS set before building.
3. **Host-side assumptions.** `bin/usb_host_profile` matches `enx*,usb*` and assigns
   `10.12.194.2/24`; a composite gadget still presents an `enx*` NIC, so that keeps working.
   The HID node appears as a separate input device and needs no host-side configuration.
4. **Branch base.** `feat/config-ui` is 30 commits ahead of `main` and 19 of those are not
   pushed. Payload work reuses the UI's render/apply pattern, so it branches from there — but
   nothing merges until config-ui lands.

## Phases

**P0 — probe (read-only, on the device).** `lsmod` for `libcomposite`/`usb_f_hid`/`usb_f_mass_storage`,
configfs mounted, `ls /sys/class/udc`, kernel `CONFIG_USB_CONFIGFS_F_*`, `iw phy` interface
modes, and the current gadget bring-up path (`02-usb0.conf` vs `modprobe g_ether`).
Acceptance: a written capability report, no changes to the device.

**P1 — configfs bring-up, gateway parity.** Replace `g_ether` with a configfs gadget exposing
ECM only. Acceptance: `usb0` comes up with the same address; the tethered host gets a `/32`
through tor; `bin/gadget-watchdog.sh` recovers a stalled link by rebinding instead of
`modprobe`; the two-signal gate still refuses to act on attach/detach.

**P2 — HID + payload runner.** `hid.usb0` in the `payload` mode, a DuckyScript-subset runner
(`bin/payload-run`, payloads in `payloads/`), `--dry-run` that prints the keystroke plan without
opening `/dev/hidg0`. Acceptance: types a known string into a throwaway VM with the US and GB
layouts; aborts on a bad keycode instead of sending garbage; nothing is sent unless the mode and
a payload file are both given.

**P3 — mass storage.** `mass_storage.usb0` with a loop image, read-only by default, `ro`/`rw`
explicit. Acceptance: host mounts the image; unplugging while mounted is handled (eject before
mode change); a stalled host does not wedge the gadget.

**P4 — capture + UI.** `capture` mode runs `tcpdump` on `usb0`; the dashboard gains a Payloads
tab (mode, current payload, capture list) using the existing auth/CSRF pattern. Acceptance:
pcap reachable over the tether; no new off-loopback listener; the UI cannot switch mode without
the confirm step that `/api/rules/apply` already uses.

## Non-goals

- ESP32 Marauder parity of any kind, on this hardware, in this repo.
- A shipped agent binary. Use SSH/SOCKS over `usb0`.
- Merging attack tooling into the default mode. `gateway` must stay a privacy appliance.

## Prior art worth reading before writing gadget code

- P4wnP1 A.L.O.A. (Zero W only) — HIDScript, RNDIS/ECM, MSD, KARMA; the model for a mode-based layout.
- P4wnP1-O2 — Python-first, retargeted at the Zero 2 W.
- Raspiducky, PiCycle — configfs function composition and DWC2 endpoint accounting.
- iSticktoit "Composite USB Gadgets on the Raspberry Pi Zero" — the canonical configfs walkthrough.

## Open questions

1. Target OS set: Linux-only payload mode (ECM) or also Windows (RNDIS + descriptors)?
2. Does HID shipping in the same repo as the privacy gateway still match how Bill wants to
   describe `pi-tor` publicly?
3. Is the spare Zero W Rev 1.1 the better home for a full UAK clone (P4wnP1 A.L.O.A. targets
   exactly that board, and it cannot run this stack)?
