// pi-tor config UI — no frameworks, no external URLs.
"use strict";

const MASK = "********";
let MASKED_KEYS = [];

function $(id) { return document.getElementById(id); }

async function api(path, opts) {
  const res = await fetch(path, opts || {});
  if (res.status === 401) {
    throw new Error("401 Unauthorized — check the user/password");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw Object.assign(new Error("request failed"), {status: res.status, data});
  }
  return data;
}

function setStatus(msg, ok) {
  const el = $("message");
  el.textContent = typeof msg === "string" ? msg : "";
  el.classList.toggle("ok-message", ok === true);
  if (typeof msg !== "string") {
    el.innerHTML = msg;
  }
}

// ---------------- dashboard ----------------

function card(k, v, cls) {
  return `<div class="card ${cls || ""}"><div class="k">${k}</div>` +
    `<div class="v">${v}</div></div>`;
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, c =>
    ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}[c]));
}

async function loadStatus() {
  const st = await api("/api/status");
  const div = $("status");
  if (st.dry_run) {
    div.innerHTML = '<div class="card"><div class="k">mode</div>' +
      '<div class="v">DRY RUN — docker calls and subprocesses disabled</div></div>';
    renderUplink(st.uplink);
    return;
  }
  const bits = [];
  for (const name of Object.keys(st.services || {})) {
    const s = st.services[name] || {};
    const state = s.error ? `error: ${s.error}` :
      `${s.running ? "running" : "down"}` +
      (s.health ? ` (${s.health})` : "");
    bits.push(card(name, esc(state), s.running ? "ok" : "bad"));
  }
  bits.push(card("tor bootstrap", esc(st.tor?.bootstrap || "not bootstrapped yet"),
    st.tor?.bootstrap === "100%" ? "ok" : ""));
  bits.push(card("exit IP", esc(st.tor?.exit_ip || "unavailable")));
  const c = st.pihole?.counters;
  if (c && c.api) {
    bits.push(card("pihole queries (24h)", esc(c.queries_today ?? "?")));
    bits.push(card("pihole blocked (24h)", esc(c.blocked_today ?? "?")));
  } else {
    bits.push(card("pihole counters", esc("unavailable — see admin UI")));
  }
  bits.push(card("firewall rules", esc(st.rules?.state || "unknown")));
  div.innerHTML = bits.join("");
  renderUplink(st.uplink);
}

// ---------------- uplink panel (read-only) ----------------

function leaseBadge(lease) {
  const map = {
    "ok": ["ok", "lease ok"],
    "no_ipv4": ["warn", "no lease"],
    "no_route": ["warn", "no default route"],
    "absent": ["bad", "absent"],
    "unknown": ["warn", "unknown"],
  };
  const [cls, text] = map[lease] || ["warn", lease || "unknown"];
  return `<span class="badge ${cls}">${esc(text)}</span>`;
}

function renderUplink(u) {
  const div = $("uplink-panel");
  if (!u || !u.interfaces) {
    div.innerHTML = '<span class="muted">uplink data unavailable</span>';
    return;
  }
  const rows = u.interfaces.map(i =>
    `<tr><td>${esc(i.name)}</td><td>${esc(i.operstate || "?")}</td>` +
    `<td>${esc((i.ipv4 || []).join(", ") || (i.ipv4 === null ? "unknown" : "—"))}</td>` +
    `<td>${i.default_route ? "yes" : (i.default_route === null ? "?" : "—")}</td></tr>`
  ).join("");
  div.innerHTML =
    `<div class="uplink-summary">${leaseBadge(u.lease)} ${esc(u.message || "")}` +
    (u.ssid ? ` · ssid: ${esc(u.ssid)}` : "") + `</div>` +
    `<table class="iftable"><thead><tr><th>interface</th><th>state</th>` +
    `<th>IPv4</th><th>default route</th></tr></thead><tbody>${rows}</tbody></table>`;
}

// ---------------- config form ----------------

function fieldLabel(key, spec) {
  return `<span class="lbl">${esc(spec.label || key)}</span>`;
}

async function loadConfig() {
  const cfg = await api("/api/config");
  MASKED_KEYS = cfg.masked_keys || [];
  const form = $("config-form");
  form.innerHTML = "";
  for (const [key, spec] of Object.entries(cfg.fields || {})) {
    const isSecret = MASKED_KEYS.includes(key);
    const isBool = key === "dns_query_logging";
    const value = cfg.values[key] ?? spec.default;
    const input = isBool
      ? `<select name="${key}">
           <option value="false" ${value === "false" ? "selected" : ""}>false</option>
           <option value="true" ${value === "true" ? "selected" : ""}>true</option>
         </select>`
      : `<input name="${key}" type="${isSecret ? "password" : "text"}"
           value="${esc(value)}" ${
           isSecret ? `autocomplete="off" data-orig="${esc(value)}"` : ""}>`;
    const targets = spec.targets ? `<span class="hint">${esc(spec.targets)}</span>` : "";
    form.insertAdjacentHTML("beforeend",
      `<label>${fieldLabel(key, spec)}${input}${targets}</label>`);
  }
  const warns = (cfg.warnings || []).map(w =>
    `<div class="muted warning">⚠ ${esc(w.message)}</div>`).join("");
  setStatus(warns || "loaded", Object.keys(cfg.values || {}).length > 0);

  const rawWrap = $("raw");
  rawWrap.innerHTML = "";
  for (const [rel, text] of Object.entries(cfg.raw || {})) {
    rawWrap.insertAdjacentHTML("beforeend",
      `<details><summary>${esc(rel)}</summary><pre>${esc(text)}</pre></details>`);
  }
}

function collectValues() {
  const values = {};
  for (const el of $("config-form").querySelectorAll("[name]")) {
    let v = el.value;
    if (el.type === "password" && (v === MASK || v === "")) {
      continue; // unchanged secret: keep current
    }
    values[el.name] = v;
  }
  return values;
}

function showErrors(errors, warnings) {
  const map = {};
  for (const e of errors || []) {
    (map[e.key] = map[e.key] || []).push({msg: e.message, cls: "field-error"});
  }
  for (const w of warnings || []) {
    (map[w.key] = map[w.key] || []).push({msg: w.message, cls: "field-warning"});
  }
  // inline per field
  document.querySelectorAll("#config-form .field-error, #config-form .field-warning")
    .forEach(n => n.remove());
  for (const [key, notes] of Object.entries(map)) {
    const input = document.querySelector(`#config-form [name="${key}"]`);
    if (input) {
      const note = document.createElement("div");
      note.className = notes[0].cls;
      note.textContent = notes.map(n => n.msg).join("; ");
      input.insertAdjacentElement("afterend", note);
    }
  }
  $("errors").textContent = (errors || []).length ?
    `${errors.length} validation error(s) — fix the highlighted fields` : "";
  return map;
}

// ---------------- preview / apply / rollback ----------------

function renderDiffs(diffs) {
  const wrap = $("diffs");
  wrap.innerHTML = "";
  for (const [rel, d] of Object.entries(diffs || {})) {
    if (!d) {
      wrap.insertAdjacentHTML("beforeend",
        `<details open><summary>${esc(rel)}</summary><pre>unchanged</pre></details>`);
    } else {
      const html = esc(d)
        .replace(/\n\+/g, '\n<span class="diff-add">+')
        .replace(/<\/span>?/g, "$&");
      // simpler: color lines starting with +
      wrap.insertAdjacentHTML("beforeend",
        `<details open><summary>${esc(rel)}</summary><pre>${esc(d)}</pre></details>`);
    }
  }
}

async function preview() {
  try {
    const res = await api("/api/preview", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({values: collectValues()}),
    });
    showErrors(res.errors || [], res.warnings || []);
    renderDiffs(res.diffs || {});
    setStatus("preview computed — nothing written", true);
  } catch (e) {
    showErrors(e.data?.errors, e.data?.warnings);
    setStatus(`preview failed: ${e.message}`);
  }
}

async function apply() {
  if (!confirm("Apply configuration? Files will be backed up, written and " +
      "changed services restarted.")) return;
  try {
    const res = await api("/api/apply", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({confirm: true, values: collectValues()}),
    });
    showErrors(res.errors || [], res.warnings || []);
    const parts = [];
    parts.push(res.backup ? `backup: ${res.backup}` : "no changes to back up");
    for (const [svc, r] of Object.entries(res.restarts || {})) {
      parts.push(`${svc}: ${r.error ? "FAILED — " + esc(r.error) :
        esc(r.state || "ok")}`);
      if (r.logs) parts.push(`<pre>${esc(r.logs)}</pre>`);
    }
    const notes = (res.notes || []).map(esc).join("<br>");
    const warnNotes = (res.warnings || []).map(w => esc(w.message)).join("<br>");
    const html = parts.join("<br>") +
      (notes ? `<br><span class="muted">${notes}</span>` : "") +
      (warnNotes ? `<br><span class="field-warning">⚠ ${warnNotes}</span>` : "");
    setStatus(html, !Object.values(res.restarts || {}).some(r => r.error));
    renderDiffs(Object.fromEntries(
      Object.entries(res.files || {}).map(([k, v]) =>
        [k, v.changed ? "(changed)" : null])));
  } catch (e) {
    showErrors(e.data?.errors, e.data?.warnings);
    if (e.data?.errors) setStatus("validation failed — nothing applied");
    else setStatus(`apply failed: ${e.message}`);
  }
}

async function rollback() {
  if (!confirm("Restore the newest backup and restart services?")) return;
  try {
    const res = await api("/api/rollback", {method: "POST"});
    setStatus(`restored: ${esc((res.restored || []).join(", "))} from ${esc(res.backup || "?")}`,
      res.ok);
    await Promise.all([loadStatus(), loadConfig()]);
  } catch (e) {
    setStatus(`rollback failed: ${e.message}`);
  }
}

async function showLogs(service) {
  try {
    const res = await api(`/api/logs?service=${service}&lines=200`);
    $("logs").textContent = res.logs ? res.logs :
      res.skipped ? "(dry run: docker logs unavailable)" : "(no logs)";
  } catch (e) {
    $("logs").textContent = `failed: ${e.message}`;
  }
}

// ---------------- firewall rules ----------------

async function rulesAction(action) {
  if (!confirm(`Run bin/pi-tor-rules.sh ${action} on the host now?`)) return;
  try {
    const res = await api(`/api/rules/${action}`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({confirm: true}),
    });
    const detail = res.skipped ? esc(res.skipped) :
      res.error ? "FAILED — " + esc(res.error) :
      action === "apply" ? "rules applied" : "rules flushed";
    setStatus(`firewall ${action}: ${detail}`, !res.error);
    await loadStatus();  // the firewall-rules card shows the resulting state
  } catch (e) {
    setStatus(`firewall ${action} failed: ${e.message}`);
  }
}

// ---------------- wire up ----------------

window.addEventListener("DOMContentLoaded", () => {
  $("refresh").onclick = loadStatus;
  $("rules-apply").onclick = () => rulesAction("apply");
  $("rules-flush").onclick = () => rulesAction("flush");
  $("preview").onclick = preview;
  $("apply").onclick = apply;
  $("rollback").onclick = rollback;
  $("logs-tor").onclick = () => showLogs("tor");
  $("logs-pihole").onclick = () => showLogs("pihole");
  $("config-form").addEventListener("submit", e => e.preventDefault());
  loadStatus();
  loadConfig();
});
