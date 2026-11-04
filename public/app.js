"use strict";
/* BCPS Student Chat client. All user text is rendered with textContent (never innerHTML),
   and every permission shown here is ALSO enforced by the server. */

const $ = (s) => document.querySelector(s);
const state = {
  me: null, meta: null, roles: {}, servers: [], discover: [], serverId: null, channelId: null,
  members: [], messages: [], unread: new Set(), ws: null, wsOk: false, pingTimer: null, pollTimer: null,
  reconnectTimer: null,
};

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k === "css") for (const [ck, cv] of Object.entries(v)) el.style.setProperty(ck, cv);
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

async function api(method, path, body) {
  const opt = { method, credentials: "same-origin", headers: {} };
  if (method !== "GET") { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body || {}); }
  const res = await fetch(path, opt);
  if (res.status === 204) return null;
  let data = null;
  try { data = await res.json(); } catch (_) { /* no body */ }
  if (!res.ok) {
    if (res.status === 401 && state.me) { state.me = null; showLogin("Your session ended. Please sign in again."); }
    throw new Error((data && data.error) || `Request failed (${res.status})`);
  }
  return data;
}

function toast(msg, bad) {
  const t = $("#toast");
  t.textContent = msg; t.className = "toast" + (bad ? " bad" : "");
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add("hidden"), 3500);
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };

const role = (key) => state.roles[key] || state.roles.student;
const cur = () => state.servers.find((s) => s.id === state.serverId);
const curChan = () => (cur() ? cur().channels.find((c) => c.id === state.channelId) : null);
const can = (perm) => !!cur() && cur().perms.includes(perm);
const level = (key) => (state.roles[key] ? state.roles[key].level : 0);
const initial = (name) => (name || "?").trim().charAt(0).toUpperCase();
const fmtTime = (ms) => {
  const d = new Date(ms), now = new Date();
  const t = d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  return d.toDateString() === now.toDateString() ? `Today at ${t}` : `${d.toLocaleDateString()} ${t}`;
};
const roleBadge = (key) => h("span", { class: "badge", css: { "--role": role(key).color }, title: role(key).label, text: role(key).badge });
const avatar = (name, key) => h("div", { class: "avatar", css: { "--role": role(key).color }, text: initial(name) });

// ---------------------------------------------------------------- modal
const modal = $("#modal");
function openModal(title, ...content) {
  $("#modal-title").textContent = title;
  $("#modal-body").replaceChildren(...content.flat());
  if (!modal.open) modal.showModal();
}
const closeModal = () => modal.open && modal.close();
$("#modal-close").addEventListener("click", closeModal);
modal.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });
const field = (label, input) => h("div", { class: "field" }, h("label", { text: label }), input);
const roleSelect = (keys, selected) =>
  h("select", {}, keys.map((k) => h("option", { value: k, text: role(k).label, selected: k === selected })));

// ---------------------------------------------------------------- login
function showLogin(msg) {
  closeConnections();
  $("#app").classList.add("hidden"); $("#login").classList.remove("hidden");
  $("#login-error").textContent = msg || "";
}
$("#login-form").addEventListener("submit", guard(async (e) => {
  e.preventDefault();
  $("#login-error").textContent = "";
  try {
    const body = { name: $("#login-name").value };
    const code = $("#login-code").value.trim();
    if (code) body.ownerCode = code;
    const data = await api("POST", "/api/demo-session", body);
    state.me = data.student;
    $("#login-code").value = "";
    await enterApp();
  } catch (err) { $("#login-error").textContent = err.message; }
}));
$("#btn-logout").addEventListener("click", guard(async () => {
  await api("POST", "/api/logout"); state.me = null; showLogin("");
}));

// ---------------------------------------------------------------- app bootstrap
async function enterApp() {
  $("#login").classList.add("hidden"); $("#app").classList.remove("hidden");
  await loadServers(true);
  connectWS();
}

async function loadServers(selectFirst) {
  const data = await api("GET", "/api/servers");
  state.servers = data.servers; state.discover = data.discover;
  if (!cur()) { state.serverId = state.servers[0] ? state.servers[0].id : null; state.channelId = null; }
  renderRail();
  if (!cur()) { openDiscover(); return; }
  renderSidebar();
  if (!curChan()) { const first = cur().channels[0]; state.channelId = first ? first.id : null; await loadMessages(); }
  await loadMembers();
  renderTop();
}

function renderRail() {
  const rail = $("#rail");
  rail.replaceChildren(
    ...state.servers.map((s) => h("button", {
      class: "srv" + (s.id === state.serverId ? " active" : ""), title: s.name, "aria-label": s.name,
      css: { "--c": s.color }, text: initial(s.name),
      onclick: guard(() => selectServer(s.id)),
    })),
    h("div", { class: "sep" }),
    h("button", { class: "srv add", title: "Join a server", "aria-label": "Join a server", text: "+", onclick: openDiscover }),
  );
}

function renderSidebar() {
  const s = cur();
  $("#server-name").textContent = s ? s.name : "";
  const box = $("#channels");
  box.replaceChildren(
    h("div", { class: "chan-title" }, h("span", { text: "Text channels" }),
      can("manage_channels") ? h("button", { class: "icon-btn", title: "Create channel", "aria-label": "Create channel", text: "+", onclick: openCreateChannel }) : null),
    ...(s ? s.channels.map((c) => h("button", {
      class: "chan" + (c.id === state.channelId ? " active" : "") + (state.unread.has(c.id) ? " unread" : ""),
      onclick: guard(() => selectChannel(c.id)),
    }, h("span", { text: "#" }), h("span", { text: c.name }),
      state.unread.has(c.id) ? h("span", { class: "dot" }) : (!c.canPost ? h("span", { class: "lock", title: "Read only for your role", text: "🔒" }) : null))) : []),
  );
  const r = s ? s.role : "student";
  $("#me-name").textContent = state.me.name;
  $("#me-role").textContent = role(r).label + (s && s.timedOut ? " · timed out" : "");
  const av = $("#me-avatar"); av.textContent = initial(state.me.name); av.style.setProperty("--role", role(r).color);
}

function renderTop() {
  const c = curChan();
  $("#ch-name").textContent = c ? c.name : "";
  $("#ch-topic").textContent = c ? c.topic : "";
  const input = $("#msg-input");
  input.disabled = !c || !c.canPost || (cur() && cur().timedOut);
  input.placeholder = !c ? "No channel" : !c.canPost ? "You can't post in this channel" : cur().timedOut ? "You are timed out" : `Message #${c.name}`;
}

async function selectServer(id) {
  state.serverId = id; state.channelId = null; closePanels();
  await loadServers(false);
}
async function selectChannel(id) {
  state.channelId = id; state.unread.delete(id); closePanels();
  renderSidebar(); renderTop(); await loadMessages();
}

// ---------------------------------------------------------------- messages
async function loadMessages() {
  renderTop();
  if (!state.channelId) { state.messages = []; renderMessages(); return; }
  const id = state.channelId;
  const data = await api("GET", `/api/channels/${id}/messages?limit=50`);
  if (id !== state.channelId) return;
  state.messages = data.messages; renderMessages(true);
}

function renderMessages(stick) {
  const box = $("#messages");
  const nearBottom = stick || box.scrollHeight - box.scrollTop - box.clientHeight < 120;
  box.replaceChildren(...(state.messages.length
    ? state.messages.map(messageEl)
    : [h("div", { class: "empty", text: "No messages yet. Say hello!" })]));
  if (nearBottom) box.scrollTop = box.scrollHeight;
}

function messageEl(m) {
  const mine = m.user.id === state.me.id;
  const canDelete = mine || (can("delete_messages") && level(cur().role) > level(m.user.role));
  const tools = h("div", { class: "tools" },
    state.roles && state.meta.reactions.slice(0, 4).map((e) => h("button", { title: `React ${e}`, "aria-label": `React ${e}`, text: e, onclick: guard(() => react(m.id, e)) })),
    mine ? h("button", { text: "Edit", onclick: () => startEdit(m) }) : null,
    canDelete ? h("button", { text: "Delete", onclick: guard(() => deleteMessage(m)) }) : null,
    !mine ? h("button", { text: "Report", onclick: () => openReport(m) }) : null);
  const reacts = m.reactions.length ? h("div", { class: "reactions" }, m.reactions.map((r) => h("button", {
    class: "react" + (r.userIds.includes(state.me.id) ? " mine" : ""), onclick: guard(() => react(m.id, r.emoji)),
  }, h("span", { text: r.emoji }), h("span", { text: r.userIds.length })))) : null;
  return h("div", { class: "msg", "data-id": m.id },
    avatar(m.user.name, m.user.role),
    h("div", {},
      h("div", { class: "msg-head", css: { "--role": role(m.user.role).color } },
        h("button", { class: "uname", text: m.user.name, onclick: () => openProfile(m.user.id) }),
        roleBadge(m.user.role),
        h("span", { class: "time", text: fmtTime(m.createdAt) }),
        m.editedAt ? h("span", { class: "edited", text: "(edited)" }) : null),
      h("div", { class: "text", text: m.text }), reacts),
    tools);
}

function upsertMessage(m) {
  const i = state.messages.findIndex((x) => x.id === m.id);
  if (i >= 0) state.messages[i] = m; else state.messages.push(m);
  state.messages.sort((a, b) => a.seq - b.seq);
  if (state.messages.length > 200) state.messages.splice(0, state.messages.length - 200);
}

$("#composer").addEventListener("submit", guard(async (e) => {
  e.preventDefault();
  const input = $("#msg-input"), text = input.value.trim();
  if (!text || !state.channelId) return;
  const data = await api("POST", `/api/channels/${state.channelId}/messages`, { text });
  input.value = "";
  upsertMessage(data.message); renderMessages(true);
}));

async function react(id, emoji) {
  const data = await api("POST", `/api/messages/${id}/reactions`, { emoji });
  const m = state.messages.find((x) => x.id === id);
  if (m) { m.reactions = data.reactions; renderMessages(); }
}
async function deleteMessage(m) {
  if (!confirm("Delete this message?")) return;
  await api("DELETE", `/api/messages/${m.id}`);
  state.messages = state.messages.filter((x) => x.id !== m.id); renderMessages();
}
function startEdit(m) {
  const row = document.querySelector(`.msg[data-id="${m.id}"] .text`);
  if (!row) return;
  const input = h("input", { maxlength: "500", value: m.text });
  const save = guard(async () => {
    const data = await api("PATCH", `/api/messages/${m.id}`, { text: input.value });
    upsertMessage(data.message); renderMessages();
  });
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") save(); if (e.key === "Escape") renderMessages(); });
  row.replaceChildren(h("div", { class: "edit-row" }, input,
    h("button", { class: "primary", text: "Save", onclick: save }),
    h("button", { class: "ghost", text: "Cancel", onclick: () => renderMessages() })));
  input.focus();
}
function openReport(m) {
  const sel = h("select", {}, state.meta.reportReasons.map((r) => h("option", { value: r, text: r.replace("-", " ") })));
  openModal("Report message",
    h("div", { class: "card" }, h("strong", { text: m.user.name }), h("div", { class: "text", text: m.text })),
    field("Reason", sel),
    h("p", { class: "muted", text: "Reports go to this server's moderators. Don't share the message elsewhere." }),
    h("div", { class: "row" }, h("button", { class: "danger", text: "Send report", onclick: guard(async () => {
      const d = await api("POST", `/api/messages/${m.id}/report`, { reason: sel.value });
      closeModal(); toast(d.duplicate ? "You already reported this message." : "Report sent. Thank you.");
    }) })));
}

// ---------------------------------------------------------------- members & profiles
let membersTimer = null;
function refreshMembersSoon() { clearTimeout(membersTimer); membersTimer = setTimeout(guard(loadMembers), 250); }
async function loadMembers() {
  if (!state.serverId) return;
  const data = await api("GET", `/api/servers/${state.serverId}/members`);
  state.members = data.members; renderMembers();
}
function renderMembers() {
  const groups = new Map();
  for (const m of state.members) { if (!groups.has(m.role)) groups.set(m.role, []); groups.get(m.role).push(m); }
  const out = [];
  for (const key of Object.keys(state.roles).reverse()) {
    const list = groups.get(key); if (!list) continue;
    out.push(h("div", { class: "mgroup", text: `${role(key).label} — ${list.length}` }));
    for (const m of list) out.push(h("button", { class: "member" + (m.online ? "" : " off"), onclick: () => openProfile(m.id) },
      avatar(m.name, m.role), h("span", { class: "mn", css: { "--role": role(m.role).color }, text: m.name }), roleBadge(m.role)));
  }
  $("#members").replaceChildren(...out);
}

function openProfile(userId) {
  const m = state.members.find((x) => x.id === userId);
  if (!m) return toast("That member isn't in this server anymore.", true);
  const mine = cur().role, self = m.id === state.me.id;
  const body = [h("div", { class: "profile-top" }, avatar(m.name, m.role),
    h("div", {}, h("div", { class: "row" }, h("strong", { css: { color: role(m.role).color }, text: m.name }), roleBadge(m.role)),
      h("div", { class: "muted", text: (m.online ? "Online" : "Offline") + (m.timedOut ? " · timed out" : "") }))),
    h("div", { class: "card" }, h("div", { class: "muted", text: "About" }), h("div", { text: m.bio || "No bio yet." })),
    h("div", { class: "muted", text: `Joined ${new Date(m.joinedAt).toLocaleDateString()}` })];
  if (!self && can("manage_roles") && level(m.role) < level(mine)) {
    const keys = Object.keys(state.roles).filter((k) => k !== "owner" && level(k) < level(mine));
    const sel = roleSelect(keys, keys.includes(m.role) ? m.role : keys[0]);
    body.push(field("Change role", h("div", { class: "row" }, sel, h("button", { class: "primary", text: "Set role", onclick: guard(async () => {
      await api("POST", `/api/servers/${state.serverId}/members/${m.id}/role`, { role: sel.value });
      toast(`${m.name} is now ${role(sel.value).label}.`); await loadMembers(); openProfile(m.id);
    }) }))));
  }
  if (!self && can("timeout_members") && level(m.role) < level(mine)) {
    const sel = h("select", {}, [["10 minutes", 10], ["1 hour", 60], ["1 day", 1440], ["1 week", 10080], ["Remove timeout", 0]]
      .map(([t, v]) => h("option", { value: v, text: t })));
    body.push(field("Timeout", h("div", { class: "row" }, sel, h("button", { class: "danger", text: "Apply", onclick: guard(async () => {
      await api("POST", `/api/servers/${state.serverId}/members/${m.id}/timeout`, { minutes: Number(sel.value) });
      toast("Timeout updated."); await loadMembers(); openProfile(m.id);
    }) }))));
  }
  openModal("Profile", ...body);
}

$("#btn-me").addEventListener("click", () => {
  const bio = h("input", { maxlength: "160", placeholder: "Tell people about yourself (keep it school-appropriate)",
    value: (state.members.find((x) => x.id === state.me.id) || {}).bio || "" });
  openModal("Edit profile",
    h("p", { class: "muted", text: "Don't share your address, phone number, passwords or other private information." }),
    field("Bio", bio),
    h("div", { class: "row" }, h("button", { class: "primary", text: "Save", onclick: guard(async () => {
      await api("PATCH", "/api/me", { bio: bio.value }); closeModal(); toast("Profile saved."); await loadMembers();
    }) })));
});

// ---------------------------------------------------------------- server menu / moderation
$("#server-head").addEventListener("click", () => {
  const s = cur(); if (!s) return;
  const items = [];
  if (can("view_reports")) items.push(["Reports", () => openModeration("reports")]);
  if (can("view_audit")) items.push(["Audit log", () => openModeration("audit")]);
  if (can("view_diagnostics")) items.push(["Diagnostics", () => openModeration("diagnostics")]);
  if (can("manage_server")) items.push(["Server settings", openServerSettings]);
  if (can("manage_invites")) items.push(["Invite code", openInvite]);
  items.push(["Browse / join servers", openDiscover]);
  if (s.role !== "owner") items.push(["Leave server", guard(async () => {
    if (!confirm(`Leave ${s.name}?`)) return;
    await api("POST", `/api/servers/${s.id}/leave`); closeModal(); state.serverId = null; await loadServers(true);
  })]);
  openModal(s.name, h("p", { class: "muted", text: s.description }),
    ...items.map(([t, fn]) => h("button", { class: "menu-item", text: t, onclick: fn })));
});

function openModeration(tab) {
  const body = h("div", { class: "card" }, "Loading…");
  const tabs = [["reports", "view_reports"], ["audit", "view_audit"], ["diagnostics", "view_diagnostics"]].filter(([, p]) => can(p));
  const bar = h("div", { class: "tabs" }, tabs.map(([t]) => h("button", { class: t === tab ? "on" : "", text: t[0].toUpperCase() + t.slice(1), onclick: () => openModeration(t) })));
  openModal("Moderation", bar, body);
  guard(async () => {
    const sid = state.serverId;
    if (tab === "reports") {
      const d = await api("GET", `/api/servers/${sid}/reports?status=open`);
      body.replaceChildren(...(d.reports.length ? d.reports.map((r) => h("div", { class: "card" },
        h("div", { class: "row" }, h("strong", { text: r.author.name }), h("span", { class: "muted", text: `#${r.channel} · ${r.reason} · ${fmtTime(r.createdAt)}` })),
        h("div", { class: "text", text: r.text || "(message removed)" }),
        d.canResolve ? h("div", { class: "row" },
          h("button", { class: "ghost", text: "Dismiss", onclick: guard(async () => { await api("POST", `/api/reports/${r.id}/resolve`, { action: "dismissed" }); openModeration("reports"); }) }),
          h("button", { class: "danger", text: "Mark actioned", onclick: guard(async () => { await api("POST", `/api/reports/${r.id}/resolve`, { action: "actioned" }); openModeration("reports"); }) }),
          !r.deleted && can("delete_messages") ? h("button", { class: "ghost", text: "Delete message", onclick: guard(async () => { await api("DELETE", `/api/messages/${r.messageId}`); toast("Message deleted."); openModeration("reports"); }) }) : null)
          : h("div", { class: "muted", text: "Moderators resolve reports." }))) : [h("div", { class: "muted", text: "No open reports." })]));
    } else if (tab === "audit") {
      const d = await api("GET", `/api/servers/${sid}/audit`);
      body.replaceChildren(...(d.entries.length ? d.entries.map((e) => h("div", { class: "card" },
        h("strong", { text: e.action.replace(/_/g, " ") }), h("span", { class: "muted", text: ` · ${fmtTime(e.createdAt)}` }),
        h("div", { text: `${e.actor}${e.target ? " → " + e.target : ""}${e.detail ? " (" + e.detail + ")" : ""}` }))) : [h("div", { class: "muted", text: "Nothing logged yet." })]));
    } else {
      const d = await api("GET", `/api/servers/${sid}/diagnostics`);
      body.replaceChildren(...Object.entries(d).map(([k, v]) => h("div", { class: "row" }, h("strong", { text: k }), h("span", { class: "muted", text: String(v) }))));
    }
  })();
}

function openServerSettings() {
  const s = cur();
  const name = h("input", { maxlength: "32", value: s.name }), desc = h("input", { maxlength: "120", value: s.description });
  const list = s.channels.map((c) => h("div", { class: "row" }, h("span", { text: `#${c.name}  (read: ${role(c.minRead).label}, post: ${role(c.minPost).label})` }),
    h("button", { class: "danger", text: "Delete", onclick: guard(async () => {
      if (!confirm(`Delete #${c.name} and all its messages?`)) return;
      await api("DELETE", `/api/channels/${c.id}`); closeModal(); await loadServers(false);
    }) })));
  openModal("Server settings", field("Name", name), field("Description", desc),
    h("div", { class: "row" }, h("button", { class: "primary", text: "Save", onclick: guard(async () => {
      await api("PATCH", `/api/servers/${s.id}`, { name: name.value, description: desc.value }); closeModal(); await loadServers(false);
    }) })),
    can("manage_channels") ? [h("h3", { text: "Channels" }), ...list] : []);
}

function openCreateChannel() {
  const mineKeys = Object.keys(state.roles).filter((k) => level(k) <= level(cur().role));
  const name = h("input", { maxlength: "32", placeholder: "new-channel" }), topic = h("input", { maxlength: "120" });
  const rd = roleSelect(mineKeys, "student"), po = roleSelect(mineKeys, "student");
  openModal("Create text channel", field("Name", name), field("Topic", topic), field("Lowest role that can read", rd),
    field("Lowest role that can post", po),
    h("div", { class: "row" }, h("button", { class: "primary", text: "Create", onclick: guard(async () => {
      await api("POST", `/api/servers/${state.serverId}/channels`, { name: name.value, topic: topic.value, minRead: rd.value, minPost: po.value });
      closeModal(); await loadServers(false);
    }) })));
}

function openInvite() {
  const out = h("div", { class: "card muted", text: "Codes are stored hashed, so an existing code can't be shown again." });
  openModal("Invite code", out,
    h("div", { class: "row" },
      h("button", { class: "primary", text: "Generate new code", onclick: guard(async () => {
        const d = await api("POST", `/api/servers/${state.serverId}/invite`, { enabled: true });
        out.replaceChildren(h("div", { text: "New code (copy it now):" }), h("strong", { text: d.code }));
      }) }),
      h("button", { class: "ghost", text: "Make server open", onclick: guard(async () => {
        await api("POST", `/api/servers/${state.serverId}/invite`, { enabled: false }); toast("Anyone can now join this server.");
      }) })));
}

function openDiscover() {
  const items = state.discover.map((d) => {
    const code = d.requiresCode ? h("input", { placeholder: "Invite code", maxlength: "64" }) : null;
    return h("div", { class: "card" }, h("div", { class: "row" }, h("strong", { text: d.name }), d.requiresCode ? h("span", { class: "muted", text: "🔒 invite only" }) : null),
      h("div", { class: "muted", text: d.description }),
      h("div", { class: "row" }, code, h("button", { class: "primary", text: "Join", onclick: guard(async () => {
        await api("POST", "/api/servers/join", { serverId: d.id, code: code ? code.value : undefined });
        closeModal(); state.serverId = d.id; state.channelId = null; await loadServers(false);
      }) })));
  });
  openModal("Join a server", ...(items.length ? items : [h("div", { class: "muted", text: "You've joined every server available to you." })]));
}

// ---------------------------------------------------------------- real-time
function setConn(ok) {
  state.wsOk = ok; const el = $("#conn-state");
  el.className = "conn" + (ok ? " live" : ""); el.title = ok ? "Live" : "Reconnecting… (refreshing every few seconds)";
}
function closeConnections() {
  clearInterval(state.pingTimer); clearInterval(state.pollTimer); clearTimeout(state.reconnectTimer);
  const ws = state.ws; state.ws = null; if (ws) { ws.onclose = null; ws.close(); }
}
function connectWS() {
  if (state.ws || !state.me) return;
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  state.ws = ws;
  ws.onopen = () => {
    setConn(true); clearInterval(state.pollTimer);
    state.pingTimer = setInterval(() => ws.readyState === 1 && ws.send("ping"), 25000);
  };
  ws.onmessage = (e) => { try { handleEvent(JSON.parse(e.data)); } catch (_) { /* ignore malformed */ } };
  ws.onclose = () => {
    state.ws = null; setConn(false); clearInterval(state.pingTimer);
    if (!state.me) return;
    clearInterval(state.pollTimer);
    state.pollTimer = setInterval(guard(loadMessages), 4000);   // fallback while disconnected
    state.reconnectTimer = setTimeout(connectWS, 3000);
  };
}

function handleEvent(ev) {
  switch (ev.type) {
    case "message.new":
      if (ev.channelId === state.channelId) { upsertMessage(ev.message); renderMessages(); }
      else if (ev.serverId === state.serverId && ev.message.user.id !== state.me.id) { state.unread.add(ev.channelId); renderSidebar(); }
      break;
    case "message.edit":
      if (ev.channelId === state.channelId) { upsertMessage(ev.message); renderMessages(); } break;
    case "message.delete":
      if (ev.channelId === state.channelId) { state.messages = state.messages.filter((m) => m.id !== ev.messageId); renderMessages(); } break;
    case "reaction.update": {
      const m = state.messages.find((x) => x.id === ev.messageId);
      if (m) { m.reactions = ev.reactions; renderMessages(); } break;
    }
    case "presence": if (ev.serverId === state.serverId) refreshMembersSoon(); break;
    case "member.update":
      if (ev.serverId === state.serverId) refreshMembersSoon();
      if (ev.userId === state.me.id) guard(() => loadServers(false))();   // my role/timeout changed
      break;
    case "channel.update": case "server.update":
      if (ev.serverId === state.serverId) guard(() => loadServers(false))(); break;
    default: break;
  }
}

// ---------------------------------------------------------------- mobile panels
function closePanels() { $("#app").classList.remove("nav-open", "members-open"); }
$("#btn-nav").addEventListener("click", () => $("#app").classList.toggle("nav-open"));
$("#btn-members").addEventListener("click", () => {
  const app = $("#app");
  app.classList.toggle(matchMedia("(max-width:860px)").matches ? "members-open" : "no-members");
});
$("#scrim").addEventListener("click", closePanels);

// ---------------------------------------------------------------- start
(async function init() {
  try {
    state.meta = await api("GET", "/api/meta");
    for (const r of state.meta.roles) state.roles[r.key] = r;
    const s = await fetch("/api/session", { credentials: "same-origin" });
    if (s.ok) { state.me = (await s.json()).student; await enterApp(); } else showLogin("");
  } catch (e) { showLogin("Can't reach the server. Is it running?"); }
})();
