"use strict";
// All WireGuard key material is generated and handled HERE, in the browser.
// The private key is never sent to the server.

const $ = (id) => document.getElementById(id);
const CSRF = document.querySelector('meta[name="csrf"]').content;
const DEFAULT_AIPS = document.body.dataset.defaultAllowed || "0.0.0.0/0";
let PRESETS = [];
try { PRESETS = JSON.parse(document.body.dataset.presets || "[]"); } catch (e) { PRESETS = []; }

let LAST_PEERS = [];

// ---- toasts ----
function toast(msg, kind) {
  const el = document.createElement("div");
  el.className = "toast " + (kind || "");
  el.textContent = msg;
  $("toasts").appendChild(el);
  setTimeout(() => { el.classList.add("show"); }, 10);
  setTimeout(() => { el.classList.remove("show"); setTimeout(() => el.remove(), 300); }, 4200);
}

// ---- theme ----
function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  try { localStorage.setItem("wg-theme", t); } catch (e) {}
}
function toggleTheme() {
  const cur = document.documentElement.getAttribute("data-theme") || "dark";
  applyTheme(cur === "dark" ? "light" : "dark");
}

// ---- crypto ----
function bytesToB64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function generateKeypair() {
  if (!window.nacl || !nacl.scalarMult || !nacl.randomBytes) throw new Error("crypto library failed to load");
  const sk = nacl.randomBytes(32);
  sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
  const pk = nacl.scalarMult.base(sk);
  return { priv: bytesToB64(sk), pub: bytesToB64(pk) };
}

function buildConf(cfg, privateKey) {
  const lines = ["[Interface]", "PrivateKey = " + privateKey, "Address = " + cfg.address_cidr];
  if (cfg.dns) lines.push("DNS = " + cfg.dns);
  if (cfg.mtu) lines.push("MTU = " + cfg.mtu);
  lines.push("", "[Peer]");
  lines.push("PublicKey = " + cfg.server_public_key);
  lines.push("Endpoint = " + cfg.endpoint);
  lines.push("AllowedIPs = " + cfg.allowed_ips.join(", "));
  if (cfg.persistent_keepalive) lines.push("PersistentKeepalive = " + cfg.persistent_keepalive);
  return lines.join("\n") + "\n";
}
function confFilename(name) {
  return name.trim().replace(/[^A-Za-z0-9._-]+/g, "-").slice(0, 60) + ".conf";
}
function renderQR(text) {
  const el = $("qr"); el.innerHTML = "";
  try {
    const qr = qrcode(0, "M"); qr.addData(text); qr.make();
    const img = new Image(); img.src = qr.createDataURL(5, 2); img.alt = "WireGuard config QR";
    el.appendChild(img);
  } catch (e) { el.textContent = "(config too large for QR — use the download)"; }
}

let currentConf = null, currentName = null;
function showResult(cfg, privateKey, heading) {
  currentConf = buildConf(cfg, privateKey);
  currentName = cfg.name;
  $("r-name").textContent = (heading ? heading + " " : "") + cfg.name;
  $("conf-text").textContent = currentConf;
  renderQR(currentConf);
  $("result").classList.remove("hidden");
  $("result").scrollIntoView({ behavior: "smooth" });
}

async function api(path, opts) {
  opts = opts || {};
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (opts.method && opts.method !== "GET") headers["X-CSRF-Token"] = CSRF;
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  let body = null; try { body = await res.json(); } catch (e) {}
  if (!res.ok) {
    const detail = (body && (body.detail || body.message)) || ("HTTP " + res.status);
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return body;
}

// ---- extra subnet rows (shared by add + edit) ----
function addSubnetRow(containerId, cidr, descr) {
  const row = document.createElement("div");
  row.className = "subnet-row row";
  row.innerHTML =
    '<input class="s-cidr" placeholder="10.20.0.0/24" style="width:12rem">' +
    '<input class="s-desc grow" placeholder="description (e.g. site LAN)">' +
    '<button type="button" class="ghost small s-del">✕</button>';
  if (cidr) row.querySelector(".s-cidr").value = cidr;
  if (descr) row.querySelector(".s-desc").value = descr;
  row.querySelector(".s-del").addEventListener("click", () => row.remove());
  $(containerId).appendChild(row);
}
function collectSubnets(containerId) {
  const out = [];
  document.querySelectorAll("#" + containerId + " .subnet-row").forEach((r) => {
    const cidr = r.querySelector(".s-cidr").value.trim();
    const descr = r.querySelector(".s-desc").value.trim();
    if (!cidr) return;
    let address = cidr, mask = 32;
    if (cidr.includes("/")) { const p = cidr.split("/"); address = p[0].trim(); mask = parseInt(p[1], 10); }
    out.push({ address, mask, descr });
  });
  return out;
}

// ---- add ----
async function onAdd(ev) {
  ev.preventDefault();
  const name = $("dev-name").value.trim();
  const aips = $("dev-aips").value.trim();
  const expiry = parseInt($("dev-expiry").value, 10) || 0;
  const extra = collectSubnets("subnets");
  const msg = $("add-msg"), btn = $("add-btn");
  if (!name) return;
  msg.className = "msg"; msg.textContent = "Generating keypair in your browser…";
  btn.disabled = true;
  try {
    const kp = generateKeypair();
    const result = await api("/api/devices", {
      method: "POST",
      body: JSON.stringify({ name, public_key: kp.pub, client_allowed_ips: aips, expires_days: expiry, extra_allowed_ips: extra }),
    });
    msg.className = "msg ok";
    msg.textContent = "Added " + result.device.name + " → " + result.device.assigned_ip + ".";
    $("dev-name").value = ""; $("dev-expiry").value = "0"; $("subnets").innerHTML = "";
    showResult(result.config, kp.priv);
    toast("Added " + result.device.name, "ok");
    await refresh();
  } catch (e) { msg.className = "msg err"; msg.textContent = "Failed: " + e.message; toast(e.message, "err"); }
  finally { btn.disabled = false; }
}

function onDownload() {
  if (!currentConf) return;
  const blob = new Blob([currentConf], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = confFilename(currentName || "wg");
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}
async function onCopy() {
  if (!currentConf) return;
  try { await navigator.clipboard.writeText(currentConf); $("copy-btn").textContent = "Copied!"; setTimeout(() => ($("copy-btn").textContent = "Copy"), 1500); }
  catch (e) { toast("Clipboard blocked (needs HTTPS) — use Download", "err"); }
}
function onDone() {
  currentConf = null; currentName = null;
  $("conf-text").textContent = ""; $("qr").innerHTML = "";
  $("link-out").classList.add("hidden"); $("link-out").innerHTML = "";
  $("result").classList.add("hidden");
}

// ---- extra delivery methods ----
function onPrint() { if (currentConf) window.print(); }

function onQrPng() {
  const img = $("qr").querySelector("img");
  if (!img) return;
  const canvas = document.createElement("canvas");
  canvas.width = img.naturalWidth || 300; canvas.height = img.naturalHeight || 300;
  canvas.getContext("2d").drawImage(img, 0, 0);
  canvas.toBlob((blob) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = confFilename(currentName || "wg").replace(/\.conf$/, "") + "-qr.png";
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  }, "image/png");
}

async function onShare() {
  if (!currentConf) return;
  try {
    const file = new File([currentConf], confFilename(currentName || "wg"), { type: "text/plain" });
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      await navigator.share({ files: [file], title: "WireGuard config" });
    } else {
      await navigator.share({ title: "WireGuard config", text: currentConf });
    }
  } catch (e) { /* user cancelled or unsupported */ }
}

async function onEmail() {
  if (!currentConf) return;
  const to = prompt("Send this config to which email address?");
  if (!to) return;
  if (!confirm("Emailing sends the private key through the server and into an inbox. Continue?")) return;
  try {
    await api("/api/email_config", { method: "POST",
      body: JSON.stringify({ to: to.trim(), name: currentName, config: currentConf }) });
    toast("Emailed config to " + to, "ok");
  } catch (e) { toast("Email failed: " + e.message, "err"); }
}

async function onLink() {
  if (!currentConf) return;
  const out = $("link-out");
  out.classList.remove("hidden"); out.textContent = "Creating link…";
  try {
    const r = await api("/api/links", { method: "POST",
      body: JSON.stringify({ name: currentName, config: currentConf }) });
    const mins = r.ttl_minutes;
    out.innerHTML = "";
    const label = document.createElement("div");
    label.className = "muted small";
    label.textContent = "One-time link (single use, expires in " + mins + " min):";
    const field = document.createElement("input");
    field.readOnly = true; field.value = r.url; field.className = "link-field";
    const copy = mkBtn("Copy link", "ghost small", async () => {
      try { await navigator.clipboard.writeText(r.url); toast("Link copied", "ok"); }
      catch (e) { field.select(); toast("Select + copy the link", "err"); }
    });
    out.appendChild(label); out.appendChild(field); out.appendChild(copy);
  } catch (e) { out.className = "link-out msg err"; out.textContent = "Link failed: " + e.message; }
}

// ---- rendering ----
function sourceBadge(r) {
  if (!r.managed) return '<span class="badge warn">unmanaged</span>';
  return r.created_here === false ? '<span class="badge">imported</span>' : '<span class="badge ok">created here</span>';
}
function stateBadge(r) {
  if (r.present === false) return '<span class="badge err">missing on pfSense</span>';
  if (r.enabled === false) return '<span class="badge muted">disabled</span>';
  return '<span class="badge ok">active</span>';
}
function peerIpCell(r) {
  // The peer's own tunnel address = the first AllowedIP (a /32), else assigned_ip.
  const list = r.allowed_ips || [];
  if (list.length) return escapeHtml(list[0].address + "/" + list[0].mask);
  return escapeHtml(r.assigned_ip || "—");
}
function routedCell(r) {
  // Everything beyond the tunnel /32 = subnets routed to this peer.
  const extra = (r.allowed_ips || []).slice(1);
  if (!extra.length) return '<span class="muted">—</span>';
  return extra.map((a) => {
    const cidr = escapeHtml(a.address + "/" + a.mask);
    const d = a.descr ? ' <span class="muted small">' + escapeHtml(a.descr) + "</span>" : "";
    return "<div>" + cidr + d + "</div>";
  }).join("");
}
function fmtBytes(n) {
  if (!n) return "0";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(n < 10 && i > 0 ? 1 : 0) + u[i];
}
function fmtAgo(s) {
  if (s == null) return "never";
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}
function activityCell(r) {
  const l = r.live;
  if (!l) return '<span class="muted">—</span>';
  const dot = l.online ? '<span class="dot on"></span>online'
    : '<span class="dot off"></span>' + fmtAgo(l.seconds_ago);
  const xfer = (l.rx || l.tx)
    ? '<div class="muted small">↓' + fmtBytes(l.rx) + " ↑" + fmtBytes(l.tx) + "</div>"
    : "";
  return "<div>" + dot + "</div>" + xfer;
}
function expiryText(r) {
  if (!r.expires_at) return '<span class="muted">—</span>';
  const ms = new Date(r.expires_at) - new Date();
  const days = Math.floor(ms / 86400000);
  if (ms <= 0) return '<span class="badge err">expired</span>';
  if (days === 0) return '<span class="badge warn">&lt;1d</span>';
  return '<span class="' + (days <= 3 ? "badge warn" : "muted") + '">' + days + 'd</span>';
}

function renderRows() {
  const q = ($("search").value || "").toLowerCase().trim();
  const tbody = $("dev-rows"); tbody.innerHTML = "";
  const rows = LAST_PEERS.filter((r) => {
    if (!q) return true;
    if ((r.name || "").toLowerCase().includes(q)) return true;
    if ((r.assigned_ip || "").includes(q)) return true;
    return (r.allowed_ips || []).some((a) =>
      (a.address || "").includes(q) || (a.descr || "").toLowerCase().includes(q));
  });
  rows.forEach((r) => {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" + escapeHtml(r.name) + "</td>" +
      "<td>" + peerIpCell(r) + "</td>" +
      "<td>" + routedCell(r) + "</td>" +
      "<td><code>" + escapeHtml(r.public_key_short) + "</code></td>" +
      "<td>" + sourceBadge(r) + "</td>" +
      "<td>" + stateBadge(r) + "</td>" +
      "<td>" + activityCell(r) + "</td>" +
      "<td>" + expiryText(r) + "</td>" +
      "<td class='actions'></td>";
    const cell = tr.querySelector(".actions");
    if (!r.managed) cell.appendChild(mkBtn("Import", "ghost small", () => onImport(r)));
    if (r.present) {
      if (r.managed) cell.appendChild(mkBtn("Edit", "ghost small", () => { openEdit(r); }));
      cell.appendChild(mkBtn(r.enabled === false ? "Enable" : "Disable", "ghost small",
        () => onToggle(r, r.enabled === false)));
      if (r.managed) cell.appendChild(mkBtn("Re-issue", "ghost small", () => onReissue(r)));
      cell.appendChild(mkBtn("Revoke", "danger small", () => onRevoke(r)));
    }
    tbody.appendChild(tr);
  });
}
function mkBtn(label, cls, fn) {
  const b = document.createElement("button"); b.className = cls; b.textContent = label;
  b.addEventListener("click", () => { b.disabled = true; Promise.resolve(fn()).finally(() => { b.disabled = false; }); });
  return b;
}

async function refresh() {
  try {
    const s = await api("/api/state", { method: "GET" });
    if (s.tunnel) { $("t-port").textContent = s.tunnel.listenport || "—"; $("t-pubkey").textContent = s.tunnel.publickey || "—"; }
    $("t-count").textContent = s.counts.total + " (" + s.counts.managed + " tracked, " + s.counts.unmanaged + " unmanaged)";
    if (s.pool) $("t-pool").textContent = s.pool.used + "/" + s.pool.total + " used";
    $("t-online").textContent = (s.counts.online || 0) + " online";
    $("counts").textContent = s.counts.total + " peers";
    const ap = s.apply || {};
    $("apply-status").textContent = ap.last_error ? ("error: " + ap.last_error)
      : (ap.last_applied_at ? new Date(ap.last_applied_at).toLocaleTimeString() : "up to date");
    LAST_PEERS = s.peers || [];
    renderRows();
    const lm = $("list-msg");
    lm.textContent = s.pfsense_error ? "pfSense: " + s.pfsense_error : "";
    lm.className = s.pfsense_error ? "msg err" : "msg";
    await refreshAudit();
  } catch (e) { const lm = $("list-msg"); lm.className = "msg err"; lm.textContent = "Could not load state: " + e.message; }
}

// ---- inventory export (admin backup; no private keys) ----
function dateStamp() { return new Date().toISOString().slice(0, 10); }
function downloadText(text, filename, mime) {
  const blob = new Blob([text], { type: mime || "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}
function csvEsc(v) { v = String(v == null ? "" : v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
function rowSource(r) { return !r.managed ? "unmanaged" : (r.created_here === false ? "imported" : "created-here"); }
function rowState(r) { return r.present === false ? "missing" : (r.enabled === false ? "disabled" : "active"); }
function rowPeerIp(r) {
  const a = r.allowed_ips || [];
  return a.length ? a[0].address + "/" + a[0].mask : (r.assigned_ip || "");
}
function rowRouted(r) {
  return (r.allowed_ips || []).slice(1).map((a) => a.address + "/" + a.mask + (a.descr ? " (" + a.descr + ")" : "")).join("; ");
}
function exportCsv() {
  const cols = ["name", "peer_ip", "routed_subnets", "public_key", "source", "state", "created_at", "expires_at"];
  const lines = [cols.join(",")];
  LAST_PEERS.forEach((r) => {
    lines.push([r.name, rowPeerIp(r), rowRouted(r), r.public_key, rowSource(r), rowState(r),
      r.created_at || "", r.expires_at || ""].map(csvEsc).join(","));
  });
  downloadText(lines.join("\n"), "wg-peers-" + dateStamp() + ".csv", "text/csv");
  toast("Exported " + LAST_PEERS.length + " peers (CSV)", "ok");
}
function exportJson() {
  const data = LAST_PEERS.map((r) => ({
    name: r.name, peer_ip: rowPeerIp(r), allowed_ips: r.allowed_ips || [],
    public_key: r.public_key, source: rowSource(r), state: rowState(r),
    created_at: r.created_at, expires_at: r.expires_at,
  }));
  downloadText(JSON.stringify(data, null, 2), "wg-peers-" + dateStamp() + ".json", "application/json");
  toast("Exported " + LAST_PEERS.length + " peers (JSON)", "ok");
}

async function refreshAudit() {
  try {
    const a = await api("/api/audit?limit=15", { method: "GET" });
    const tb = $("audit-rows"); tb.innerHTML = "";
    a.entries.forEach((e) => {
      const tr = document.createElement("tr");
      tr.innerHTML =
        "<td class='muted'>" + new Date(e.ts).toLocaleString() + "</td>" +
        "<td>" + escapeHtml(e.action) + "</td>" +
        "<td>" + escapeHtml(e.target || "") + "</td>" +
        "<td class='muted'>" + escapeHtml(e.detail || "") + "</td>";
      tb.appendChild(tr);
    });
  } catch (e) {}
}

// ---- actions ----
async function onImport(r) {
  const name = prompt("Name for this peer:", r.name && r.name !== "(unnamed peer)" ? r.name : "");
  if (name === null) return;
  try { await api("/api/devices/import", { method: "POST", body: JSON.stringify({ public_key: r.public_key, name: name || null }) });
    toast("Imported " + (name || r.name), "ok"); await refresh(); }
  catch (e) { toast("Import failed: " + e.message, "err"); }
}
async function onImportAll() {
  try { const res = await api("/api/devices/import_all", { method: "POST", body: "{}" });
    toast(res.imported ? ("Imported " + res.imported + " peer(s)") : "Nothing to import", "ok"); await refresh(); }
  catch (e) { toast("Import-all failed: " + e.message, "err"); }
}
async function onToggle(r, enable) {
  try { await api("/api/devices/toggle", { method: "POST", body: JSON.stringify({ public_key: r.public_key, enabled: enable }) });
    toast((enable ? "Enabled " : "Disabled ") + r.name, "ok"); await refresh(); }
  catch (e) { toast("Toggle failed: " + e.message, "err"); }
}
async function onRevoke(r) {
  if (!confirm("Revoke '" + r.name + "'? Its peer will be removed from pfSense.")) return;
  try { await api("/api/devices/revoke", { method: "POST", body: JSON.stringify({ public_key: r.public_key }) });
    toast("Revoked " + r.name, "ok"); await refresh(); }
  catch (e) { toast("Revoke failed: " + e.message, "err"); }
}
async function onReissue(r) {
  if (!confirm("Re-issue keys for '" + r.name + "'? The old config stops working immediately.")) return;
  try {
    const kp = generateKeypair();
    const res = await api("/api/devices/rotate", { method: "POST",
      body: JSON.stringify({ public_key: r.public_key, new_public_key: kp.pub }) });
    showResult(res.config, kp.priv, "Re-issued");
    toast("Re-issued " + r.name + " — save the new config", "ok");
    await refresh();
  } catch (e) { toast("Re-issue failed: " + e.message, "err"); }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---- edit peer ----
let editing = null;
function openEdit(r) {
  editing = r;
  $("edit-msg").textContent = "";
  $("edit-name").value = r.name;
  $("edit-subnets").innerHTML = "";
  (r.allowed_ips || []).slice(1).forEach((a) => addSubnetRow("edit-subnets", a.address + "/" + a.mask, a.descr || ""));
  $("edit-change-expiry").checked = false;
  const exp = $("edit-expiry"); exp.disabled = true; exp.value = "0";
  $("edit-modal").classList.remove("hidden");
  $("edit-name").focus();
}
function closeEdit() { editing = null; $("edit-modal").classList.add("hidden"); }
async function onEditSubmit(ev) {
  ev.preventDefault();
  if (!editing) return;
  const body = {
    public_key: editing.public_key,
    name: $("edit-name").value.trim(),
    routed_subnets: collectSubnets("edit-subnets"),
    change_expiry: $("edit-change-expiry").checked,
    expires_days: parseInt($("edit-expiry").value, 10) || 0,
  };
  try {
    await api("/api/devices/edit", { method: "POST", body: JSON.stringify(body) });
    closeEdit(); toast("Saved changes to " + body.name, "ok");
    await refresh();
  } catch (e) { const m = $("edit-msg"); m.className = "msg err"; m.textContent = e.message; }
}

// ---- change password ----
function openPw() { $("pw-msg").textContent = ""; $("pw-form").reset(); $("pw-modal").classList.remove("hidden"); $("pw-current").focus(); }
function closePw() { $("pw-modal").classList.add("hidden"); }
async function onChangePw(ev) {
  ev.preventDefault();
  const cur = $("pw-current").value, nw = $("pw-new").value, cf = $("pw-confirm").value;
  const msg = $("pw-msg");
  if (nw !== cf) { msg.className = "msg err"; msg.textContent = "New passwords don't match."; return; }
  try {
    await api("/api/change_password", { method: "POST", body: JSON.stringify({ current_password: cur, new_password: nw }) });
    closePw(); toast("Password updated", "ok");
  } catch (e) { msg.className = "msg err"; msg.textContent = e.message; }
}

// ---- two-factor auth ----
function twofaIsOn() { return document.body.dataset.twofa === "1"; }
function renderQRInto(elId, text) {
  const el = $(elId); el.innerHTML = "";
  try {
    const qr = qrcode(0, "M"); qr.addData(text); qr.make();
    const img = new Image(); img.src = qr.createDataURL(5, 2); img.alt = "2FA QR";
    el.appendChild(img);
  } catch (e) { el.textContent = "(could not render QR — use the setup key)"; }
}
function open2fa() {
  const on = twofaIsOn();
  $("twofa-on").classList.toggle("hidden", !on);
  $("twofa-off").classList.toggle("hidden", on);
  // reset the OFF-state setup flow
  $("twofa-setup").classList.add("hidden");
  $("twofa-enable-btn").classList.add("hidden");
  $("twofa-start-btn").classList.remove("hidden");
  $("twofa-off-msg").textContent = "";
  $("twofa-on-msg").textContent = "";
  $("twofa-enable-code").value = "";
  $("twofa-disable-code").value = "";
  $("twofa-modal").classList.remove("hidden");
}
function close2fa() { $("twofa-modal").classList.add("hidden"); }
async function onStart2fa() {
  const msg = $("twofa-off-msg");
  try {
    const r = await api("/api/2fa/setup", { method: "POST", body: "{}" });
    renderQRInto("twofa-qr", r.otpauth_uri);
    $("twofa-secret").textContent = r.secret;
    $("twofa-setup").classList.remove("hidden");
    $("twofa-start-btn").classList.add("hidden");
    $("twofa-enable-btn").classList.remove("hidden");
    $("twofa-enable-code").focus();
  } catch (e) { msg.className = "msg err"; msg.textContent = e.message; }
}
async function onEnable2fa() {
  const msg = $("twofa-off-msg");
  try {
    await api("/api/2fa/enable", { method: "POST", body: JSON.stringify({ code: $("twofa-enable-code").value.trim() }) });
    document.body.dataset.twofa = "1";
    close2fa(); toast("Two-factor authentication enabled", "ok");
  } catch (e) { msg.className = "msg err"; msg.textContent = e.message; }
}
async function onDisable2fa() {
  const msg = $("twofa-on-msg");
  try {
    await api("/api/2fa/disable", { method: "POST", body: JSON.stringify({ code: $("twofa-disable-code").value.trim() }) });
    document.body.dataset.twofa = "";
    close2fa(); toast("Two-factor authentication disabled", "ok");
  } catch (e) { msg.className = "msg err"; msg.textContent = e.message; }
}

// ---- init ----
(function initTheme() { let t = "dark"; try { t = localStorage.getItem("wg-theme") || "dark"; } catch (e) {} applyTheme(t); })();
$("dev-aips").value = DEFAULT_AIPS;
PRESETS.forEach((p) => { const o = document.createElement("option"); o.value = p; $("aips-presets").appendChild(o); });
$("add-form").addEventListener("submit", onAdd);
$("download-btn").addEventListener("click", onDownload);
$("copy-btn").addEventListener("click", onCopy);
$("done-btn").addEventListener("click", onDone);
$("print-btn").addEventListener("click", onPrint);
$("qrpng-btn").addEventListener("click", onQrPng);
$("share-btn").addEventListener("click", onShare);
$("email-btn").addEventListener("click", onEmail);
$("link-btn").addEventListener("click", onLink);
// Show Share only if the browser supports it (secure context / mobile).
if (navigator.share) $("share-btn").classList.remove("hidden");
// Show Email only if SMTP is configured server-side.
if (document.body.dataset.smtp === "1") $("email-btn").classList.remove("hidden");
$("theme-btn").addEventListener("click", toggleTheme);
$("pw-btn").addEventListener("click", openPw);
$("pw-cancel").addEventListener("click", closePw);
$("pw-form").addEventListener("submit", onChangePw);
// 2FA: only offer it when the server has a writable TOTP store configured.
if (document.body.dataset.twofaAvailable === "1") $("twofa-btn").classList.remove("hidden");
$("twofa-btn").addEventListener("click", open2fa);
$("twofa-start-btn").addEventListener("click", onStart2fa);
$("twofa-enable-btn").addEventListener("click", onEnable2fa);
$("twofa-disable-btn").addEventListener("click", onDisable2fa);
$("twofa-off-cancel").addEventListener("click", close2fa);
$("twofa-on-cancel").addEventListener("click", close2fa);
$("edit-cancel").addEventListener("click", closeEdit);
$("edit-form").addEventListener("submit", onEditSubmit);
$("edit-add-subnet").addEventListener("click", () => addSubnetRow("edit-subnets"));
$("edit-change-expiry").addEventListener("change", (e) => { $("edit-expiry").disabled = !e.target.checked; });
$("import-all-btn").addEventListener("click", onImportAll);
$("export-csv-btn").addEventListener("click", exportCsv);
$("export-json-btn").addEventListener("click", exportJson);
$("add-subnet-btn").addEventListener("click", () => addSubnetRow("subnets"));
$("search").addEventListener("input", renderRows);
refresh();
