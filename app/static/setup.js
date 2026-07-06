"use strict";
// Onboarding wizard: test pfSense connection -> pick tunnel -> save -> import peers.
const $ = (id) => document.getElementById(id);
const CSRF = document.querySelector('meta[name="csrf"]').content;

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", "X-CSRF-Token": CSRF };
  const r = await fetch(path, { headers, ...opts });
  let data = null;
  try { data = await r.json(); } catch (e) { /* ignore */ }
  if (!r.ok) throw new Error((data && data.detail) || ("HTTP " + r.status));
  return data;
}
function msg(el, text, kind) { el.textContent = text || ""; el.className = "msg" + (kind ? " " + kind : ""); }

function selectedTunnel() {
  const sel = $("s-tunnel");
  const opt = sel.options[sel.selectedIndex];
  return opt ? { name: opt.value, pubkey: opt.dataset.pubkey || "", port: opt.dataset.port || "" } : null;
}

async function onTest() {
  const btn = $("s-test");
  msg($("s-msg"), "Testing…");
  btn.disabled = true;
  try {
    const r = await api("/api/setup/test", {
      method: "POST",
      body: JSON.stringify({
        url: $("s-url").value.trim(),
        api_key: $("s-key").value,
        verify_tls: $("s-verify").checked,
      }),
    });
    const sel = $("s-tunnel");
    sel.innerHTML = "";
    (r.tunnels || []).forEach((t) => {
      const o = document.createElement("option");
      o.value = t.name;
      o.textContent = t.name + (t.addresses ? "  (" + t.addresses + ")" : "");
      o.dataset.pubkey = t.publickey || "";
      o.dataset.port = t.listenport || "";
      sel.appendChild(o);
    });
    if (!sel.options.length) { msg($("s-msg"), "Connected, but no WireGuard tunnels found on this box.", "err"); return; }
    onTunnelChange();
    $("step2").classList.remove("hidden");
    msg($("s-msg"), "✔ Connected — found " + sel.options.length + " tunnel(s).", "ok");
    $("step2").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (e) {
    msg($("s-msg"), e.message, "err");
  } finally {
    btn.disabled = false;
  }
}

function onTunnelChange() {
  const t = selectedTunnel();
  if (t && t.port) $("s-port").value = t.port;  // prefill listen port from the tunnel
}

async function onSave() {
  const btn = $("s-save");
  const t = selectedTunnel();
  if (!t) { msg($("s-save-msg"), "Pick a tunnel first.", "err"); return; }
  msg($("s-save-msg"), "Saving…");
  btn.disabled = true;
  try {
    const r = await api("/api/setup/save", {
      method: "POST",
      body: JSON.stringify({
        url: $("s-url").value.trim(),
        api_key: $("s-key").value,
        verify_tls: $("s-verify").checked,
        tunnel: t.name,
        server_public_key: t.pubkey,
        endpoint_host: $("s-endpoint").value.trim(),
        endpoint_port: parseInt($("s-port").value, 10) || 51820,
        ip_pool_cidr: $("s-pool").value.trim(),
        client_allowed_ips: $("s-allowed").value.trim(),
      }),
    });
    $("s-pubkey-note").textContent = r.server_pubkey
      ? "Server public key discovered." : "Server public key not found — set it later if configs look incomplete.";
    $("step3").classList.remove("hidden");
    msg($("s-save-msg"), "✔ Saved and connected.", "ok");
    $("step3").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (e) {
    msg($("s-save-msg"), e.message, "err");
  } finally {
    btn.disabled = false;
  }
}

async function onImport() {
  const btn = $("s-import");
  msg($("s-import-msg"), "Importing…");
  btn.disabled = true;
  try {
    const r = await api("/api/devices/import_all", { method: "POST", body: "{}" });
    msg($("s-import-msg"), "✔ Imported " + (r.imported || 0) + " peer(s). Redirecting…", "ok");
    setTimeout(() => { window.location.href = "/"; }, 900);
  } catch (e) {
    msg($("s-import-msg"), e.message, "err");
    btn.disabled = false;
  }
}

$("s-test").addEventListener("click", onTest);
$("s-tunnel").addEventListener("change", onTunnelChange);
$("s-save").addEventListener("click", onSave);
$("s-import").addEventListener("click", onImport);
