"use strict";
const $ = (s, r = document) => r.querySelector(s);
let selected = null;

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
function say(text, ok) { const m = $("#msg"); m.textContent = text; m.className = ok ? "ok" : "err"; }
async function api(path, method = "GET", body) {
  const r = await fetch(path, { method, headers: body ? { "Content-Type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : "request refused (" + r.status + ")");
  return data;
}
function fmt(n) { return n > 1e15 ? n.toExponential(2) : n.toLocaleString("en"); }

async function load() {
  const rows = await api("/api/prefixes");
  const depth = {};
  const tbody = $("#tree tbody"), parent = $("#parent");
  tbody.replaceChildren(); parent.replaceChildren();
  $("#empty").hidden = rows.length > 0;
  for (const p of rows) {
    depth[p.id] = p.parent_id in depth ? depth[p.parent_id] + 1 : 0;
    const tr = el("tr");
    const net = el("td", p.cidr, "net"); net.style.paddingLeft = 8 + depth[p.id] * 18 + "px";
    tr.append(net, el("td", p.name), el("td", p.vlan || ""), el("td", p.status));
    const use = el("td"), bar = el("span", "", "bar"), fill = el("i");
    fill.style.width = Math.min(100, p.utilization.ratio * 100) + "%"; bar.append(fill);
    use.append(bar, el("span", fmt(p.utilization.used) + " / " + fmt(p.utilization.total)));
    const act = el("td");
    const addr = el("button", "addresses", "link"); addr.onclick = () => showAddresses(p);
    const del = el("button", "delete", "link"); del.onclick = () => remove(p);
    act.append(addr, del); tr.append(use, act); tbody.append(tr);
    const o = el("option", p.cidr + (p.name ? "  " + p.name : "")); o.value = p.id; parent.append(o);
  }
  if (selected) { const p = rows.find(x => x.id === selected.id); if (p) await showAddresses(p); else $("#addresses").hidden = true; }
}
async function remove(p) {
  try { await api("/api/prefixes/" + p.id, "DELETE"); say("Deleted " + p.cidr, true); await load(); }
  catch (e) {
    if (confirm(e.message + "\n\nDelete everything inside as well?")) {
      try { await api("/api/prefixes/" + p.id + "?force=true", "DELETE"); say("Deleted " + p.cidr + " and what was inside", true); await load(); } catch (e2) { say(e2.message); }
    }
  }
}
async function showAddresses(p) {
  selected = p;
  $("#addresses").hidden = false; $("#addr-title").textContent = p.cidr;
  const tbody = $("#addr-table tbody"); tbody.replaceChildren();
  for (const a of await api("/api/prefixes/" + p.id + "/addresses")) {
    const tr = el("tr");
    tr.append(el("td", a.ip, "net"), el("td", a.kind), el("td", a.hostname), el("td", a.note));
    const t = el("td"), b = el("button", "release", "link");
    b.onclick = async () => { try { await api("/api/prefixes/" + p.id + "/addresses/" + encodeURIComponent(a.ip), "DELETE"); await load(); } catch (e) { say(e.message); } };
    t.append(b); tr.append(t); tbody.append(tr);
  }
}
$("#add").onsubmit = async ev => {
  ev.preventDefault(); const f = new FormData(ev.target);
  try {
    await api("/api/prefixes", "POST", { cidr: f.get("cidr"), name: f.get("name"), status: f.get("status"), vlan: f.get("vlan") ? Number(f.get("vlan")) : null });
    ev.target.reset(); say("Added", true); await load();
  } catch (e) { say(e.message); }
};
$("#addr-form").onsubmit = async ev => {
  ev.preventDefault(); const f = new FormData(ev.target);
  try {
    const a = await api("/api/prefixes/" + selected.id + "/addresses", "POST", { hostname: f.get("hostname"), ip: f.get("ip") || null, kind: f.get("kind") });
    ev.target.reset(); say("Recorded " + a.ip, true); await load();
  } catch (e) { say(e.message); }
};
$("#plan").onsubmit = async ev => {
  ev.preventDefault(); const f = new FormData(ev.target), apply = ev.submitter && ev.submitter.value === "apply";
  const requests = [];
  for (const line of String(f.get("requests")).split("\n")) {
    if (!line.trim()) continue;
    const m = line.match(/^\s*(.+?)\s*[=,:]\s*(\d+)\s*$/);
    if (!m) { say("Cannot read: " + line.slice(0, 60)); return; }
    requests.push({ name: m[1], hosts: Number(m[2]) });
  }
  const body = { requests, growth: Number(f.get("growth") || 0) };
  const out = $("#result"); out.replaceChildren();
  try {
    let plan;
    if (apply) plan = await api("/api/prefixes/" + f.get("parent") + "/plan", "POST", body);
    else { const p = (await api("/api/prefixes")).find(x => String(x.id) === f.get("parent")); plan = await api("/api/plan", "POST", { ...body, network: p.cidr }); }
    const t = el("table"); t.append(Object.assign(el("thead"), {}));
    const hr = el("tr"); for (const h of ["Name", "Network", "Asked", "Usable"]) hr.append(el("th", h)); t.firstChild.append(hr);
    const tb = el("tbody");
    for (const a of plan.allocations) { const tr = el("tr"); tr.append(el("td", a.name), el("td", a.network, "net"), el("td", a.hosts), el("td", a.usable)); tb.append(tr); }
    t.append(tb); out.append(t);
    for (const u of plan.unplaced) out.append(el("p", "Not placed: " + u.name + " — " + u.reason, "bad"));
    out.append(el("p", (plan.utilization * 100).toFixed(1) + "% of the addresses allocated; " + (plan.efficiency * 100).toFixed(1) + "% of the handed-out usable addresses are asked for.", "muted"));
    say(apply ? "Plan applied" : "Preview only — nothing saved", true);
    if (apply) await load();
  } catch (e) { say(e.message); }
};
load().catch(e => say(e.message));
