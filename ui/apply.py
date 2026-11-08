"""Apply and rollback semantics for the config UI.

Apply:
1. back up every file that will change into ui/backups/<UTC-stamp>/ with a
   manifest.json (originals + sha256),
2. write all render targets atomically (tmp + os.replace, mode preserved),
3. restart only what changed (tor via socket restart; pihole via socket for
   dnsmasq changes or compose recreate for env changes; rules script with
   explicit env overrides),
4. poll container health for 90s and surface logs of a failed restart.
No auto-rollback: a visible failure beats a silent revert.

The ui container also owns the firewall: on process start the parsed config
is validated and bin/pi-tor-rules.sh apply runs (idempotent), so a compose
up is the only step needed to bring the rules up.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import config_schema as schema
import dockerops
import render
import uplink

# restart routing, expressed as key -> side effect
PIHOLE_RECREATE_KEYS = ("tz", "pihole_webpassword", "dns_query_logging")
RULES_KEYS = ("interface", "subnet", "gateway_ip", "trans_port", "dns_port",
              "protected_hosts")
UI_NOTE_KEYS = ("ui_port", "ui_password")


def apply_changes(root, posted, dry=None):
    root = Path(root)
    if dry is None:
        dry = dockerops._dry()

    current = render.read_current(root)
    cfg = schema.merge_secrets(schema.normalize_all(posted),
                               current["values"])
    errors, uplink_warnings = _validated(cfg, current["values"])
    if errors:
        return {"ok": False, "errors": errors}

    rendered = render.render(cfg)
    changed = render.changed_files(root, cfg)
    before_values = current["values"]

    report = {
        "ok": True,
        "dry_run": dry,
        "files": {rel: {"changed": rel in changed} for rel in rendered},
        "backup": None,
        "restarts": {},
        "notes": [],
        "errors": [],
        "warnings": uplink_warnings,
    }

    if changed:
        backup_dir = _backup(root, rendered, changed)
        report["backup"] = str(backup_dir)

    _write_all(root, rendered)

    restart_tor = "tor/torrc" in changed
    restart_pihole = any(rel.startswith("pihole/etc-dnsmasq.d/") and
                         rel in changed for rel in rendered)

    diffed_env_keys = [k for k in schema.FIELDS
                       if before_values.get(k) != cfg[k] and
                       k not in schema.SECRET_KEYS]
    recreate_pihole = bool(set(diffed_env_keys) & set(PIHOLE_RECREATE_KEYS))
    rules_needed = bool(set(diffed_env_keys) & set(RULES_KEYS))
    ui_note = bool(set(diffed_env_keys) & set(UI_NOTE_KEYS))

    if restart_tor:
        report["restarts"]["tor"] = _restart_with_health("tor")
    if recreate_pihole:
        report["restarts"]["pihole"] = dockerops.compose_up(["pihole"], root)
        if "error" not in report["restarts"]["pihole"]:
            report["restarts"]["pihole_health"] = \
                _restart_with_health("pihole", started=False)
    elif restart_pihole:
        report["restarts"]["pihole"] = _restart_with_health("pihole")
    if rules_needed:
        report["restarts"]["rules"] = dockerops.run_rules(root, cfg)
    if ui_note:
        report["notes"].append(
            "ui_port/pi config password changes take effect on the next "
            "'docker compose up' of the ui service.")

    return report


def _validated(cfg, current_values):
    """Schema errors plus the host-aware uplink check (errors, warnings)."""
    errors = schema.validate(cfg)
    u_errors, u_warnings = uplink.submission(cfg, current_values)
    return errors + u_errors, u_warnings


def startup_rules_apply(root, dry=None):
    """Container-start firewall apply: skip in dry run, skip on an invalid
    parsed config (with a visible line for both), then run the same script
    the apply endpoint uses. Run_rules refuses a non-nf_tables backend."""
    if dry is None:
        dry = dockerops._dry()
    if dry:
        return {"skipped": "dry-run"}
    values = render.read_current(root)["values"]
    errors = schema.validate(values)
    if errors:
        summary = "; ".join(f"{e['key']}: {e['message']}" for e in errors)
        sys.stderr.write(
            "[pi-tor-ui] startup rules apply skipped: invalid config: "
            f"{summary}\n")
        return {"skipped": "invalid config", "errors": errors}
    sys.stderr.write("[pi-tor-ui] applying firewall rules (bin/pi-tor-rules.sh apply)\n")
    res = dockerops.run_rules(root, values)
    if "error" in res:
        sys.stderr.write(f"[pi-tor-ui] startup rules apply failed: {res['error']}\n")
    return res


def _restart_with_health(name, started=True):
    res = {}
    res["restart"] = dockerops.restart(name)
    if "error" in res["restart"]:
        res["error"] = res["restart"]["error"]
        res["logs"] = dockerops.logs(name, 50)
        return res
    health = dockerops.poll_health(name, 90)
    res["health"] = health
    if not health.get("healthy"):
        res["error"] = f"{name} did not become healthy after restart"
        res["logs"] = dockerops.logs(name, 50)
        res["note"] = "use the Rollback button to restore the previous config"
    return res


def _backup(root, rendered, changed):
    import datetime
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ")
    backup_dir = root / "ui" / "backups" / stamp
    manifest = {"created_utc": stamp,
                "rendered_but_unchanged": [r for r in rendered if r not in changed],
                "originals": {}}
    for rel in changed:
        src = Path(root) / rel
        dst = backup_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        data = src.read_bytes()
        dst.write_bytes(data)
        _copy_mode(src, dst, default=0o644)
        manifest["originals"][rel] = {
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    backup_dir.mkdir(parents=True, exist_ok=True)
    (backup_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return backup_dir


def restore_latest_backup(root, dry=None):
    root = Path(root)
    if dry is None:
        dry = dockerops._dry()
    backups = root / "ui" / "backups"
    if not backups.is_dir():
        return {"ok": False, "error": "no ui/backups directory"}
    stamps = sorted((d.name for d in backups.iterdir() if d.is_dir()),
                    reverse=True)
    if not stamps:
        return {"ok": False, "error": "no backups exist yet"}
    stamp = stamps[0]
    source = backups / stamp
    restored = []
    for p in sorted(source.rglob("*")):
        if not p.is_file() or p.name == "manifest.json":
            continue
        rel = p.relative_to(source)
        dst = Path(root) / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        _atomic_replace(p, dst)
        restored.append(str(rel))
    if not restored:
        return {"ok": False, "error": f"backup {stamp} contains no files"}

    restarts = {}
    current = render.read_current(root)
    values = current["values"]
    if any(r == "tor/torrc" for r in restored):
        restarts["tor"] = _restart_with_health("tor")
    if any(r.startswith("pihole/etc-dnsmasq.d/") for r in restored):
        restarts["pihole"] = _restart_with_health("pihole")
    if any(r == ".env" for r in restored) and not dry:
        # env changes need recreate; rules re-applied with restored values
        restarts.setdefault("pihole_recreate_note",
                            "restore of .env may need 'docker compose up -d pihole'")
        restarts["rules"] = dockerops.run_rules(root, values)
    return {"ok": True, "backup": str(source), "restored": restored,
            "dry_run": dry, "restarts": restarts}


def _write_all(root, rendered):
    for rel, new_bytes in rendered.items():
        dst = Path(root) / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(dst, new_bytes)


def _atomic_write(dst, data):
    tmp = dst.with_name(dst.name + ".ui-tmp")
    tmp.write_bytes(data)
    _copy_mode(dst, tmp, default=0o644)
    os.replace(tmp, dst)


def _atomic_replace(src, dst):
    tmp = dst.with_name(dst.name + ".ui-tmp")
    tmp.write_bytes(src.read_bytes())
    _copy_mode(dst, tmp, default=0o644)
    os.replace(tmp, dst)


def _copy_mode(src, dst, default=0o644):
    try:
        mode = src.stat().st_mode & 0o7777
    except OSError:
        mode = default
    try:
        os.chmod(dst, mode)
    except OSError:
        pass
