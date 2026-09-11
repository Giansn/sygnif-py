/* ============================================================
   SYGNIF Desk — SPA logic. Plain JS, no framework, no build step.
   ============================================================ */
"use strict";

/* ---------- tiny helpers ---------- */
const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const el = (tag, cls, txt) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (txt != null) n.textContent = txt;
  return n;
};
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, opts) {
  const r = await fetch(path, opts);
  const ct = r.headers.get("content-type") || "";
  let data = null;
  if (ct.includes("application/json")) { try { data = await r.json(); } catch (_) {} }
  if (!r.ok) {
    const msg = (data && (data.detail || data.error)) || `${r.status} ${r.statusText}`;
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return data;
}

let toastTimer = null;
function toast(msg, isErr) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.toggle("err", !!isErr);
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 3200);
}

/* ============================================================
   Minimal, safe Markdown renderer (self-written, offline).
   Handles: headings, fenced/inline code, bold/italic, links,
   lists, blockquotes, hr, paragraphs. Escapes all HTML first.
   ============================================================ */
const CODE_FOLD_LINES = 24;   // longer blocks arrive folded

function renderMarkdown(src) {
  // The fenced-code placeholder below is a private-use codepoint, so text the
  // user actually typed can never forge one — strip any stray copy first.
  src = String(src ?? "").replace(/\uE000/g, "");
  const codeBlocks = [];
  // 1) extract fenced code blocks so their contents are never parsed
  src = src.replace(/```([^\n`]*)\n([\s\S]*?)```/g, (_, lang, code) => {
    const i = codeBlocks.length;
    const label = lang.trim();
    const cls = label ? ` data-lang="${esc(label)}"` : "";
    const inner = esc(code.replace(/\n$/, ""));
    const n = inner ? inner.split("\n").length : 0;
    // Native <details> rather than a click handler: folding then needs no event
    // wiring and survives the innerHTML rewrite that every streaming frame does.
    // Long blocks arrive folded so a big dump cannot bury the prose around it.
    const open = n > CODE_FOLD_LINES ? "" : " open";
    codeBlocks.push(
      `<details class="codefold"${open}>` +
      `<summary>${esc(label || "code")} \u00B7 ${n} line${n === 1 ? "" : "s"}</summary>` +
      `<pre><code${cls}>${inner}</code></pre></details>`,
    );
    return `\uE000CB${i}\uE000`;
  });

  const lines = src.split("\n");
  const out = [];
  let i = 0;
  const inline = (t) => {
    // escape, then re-introduce inline markup
    t = esc(t);
    // inline code
    t = t.replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`);
    // links [txt](url)
    t = t.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g,
      (_, txt, url) => `<a href="${url}" target="_blank" rel="noopener">${txt}</a>`);
    // bold
    t = t.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    t = t.replace(/__([^_]+)__/g, "<strong>$1</strong>");
    // italic
    t = t.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
    t = t.replace(/(^|[^_])_([^_\n]+)_/g, "$1<em>$2</em>");
    return t;
  };

  while (i < lines.length) {
    let line = lines[i];

    // placeholder code block
    const cb = line.match(/^\uE000CB(\d+)\uE000$/);
    if (cb) { out.push(codeBlocks[+cb[1]]); i++; continue; }

    // blank
    if (/^\s*$/.test(line)) { i++; continue; }

    // hr
    if (/^\s*([-*_])\1{2,}\s*$/.test(line)) { out.push("<hr>"); i++; continue; }

    // heading
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) { const lv = h[1].length; out.push(`<h${lv}>${inline(h[2])}</h${lv}>`); i++; continue; }

    // blockquote
    if (/^\s*>\s?/.test(line)) {
      const buf = [];
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) { buf.push(lines[i].replace(/^\s*>\s?/, "")); i++; }
      out.push(`<blockquote>${inline(buf.join(" "))}</blockquote>`);
      continue;
    }

    // unordered list
    if (/^\s*[-*+]\s+/.test(line)) {
      const buf = [];
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
        buf.push(`<li>${inline(lines[i].replace(/^\s*[-*+]\s+/, ""))}</li>`); i++;
      }
      out.push(`<ul>${buf.join("")}</ul>`);
      continue;
    }
    // ordered list
    if (/^\s*\d+\.\s+/.test(line)) {
      const buf = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        buf.push(`<li>${inline(lines[i].replace(/^\s*\d+\.\s+/, ""))}</li>`); i++;
      }
      out.push(`<ol>${buf.join("")}</ol>`);
      continue;
    }

    // paragraph (gather consecutive non-structural lines)
    const buf = [];
    while (i < lines.length && !/^\s*$/.test(lines[i]) &&
           !/^\uE000CB\d+\uE000$/.test(lines[i]) &&
           !/^(#{1,6})\s/.test(lines[i]) &&
           !/^\s*[-*+]\s+/.test(lines[i]) &&
           !/^\s*\d+\.\s+/.test(lines[i]) &&
           !/^\s*>\s?/.test(lines[i]) &&
           !/^\s*([-*_])\1{2,}\s*$/.test(lines[i])) {
      buf.push(lines[i]); i++;
    }
    out.push(`<p>${inline(buf.join("\n")).replace(/\n/g, "<br>")}</p>`);
  }
  return out.join("\n");
}

/* ============================================================
   Global state
   ============================================================ */
const State = {
  view: "chat",
  providers: [],            // [{id,label,base_url,model,reachable,models,error}]
  activeProvider: null,     // provider id
  activeModel: "",          // model string ("" => provider default)
  conversations: [],        // [{id,title,updated}]
  conv: null,               // full active conversation {id,title,system,messages,updated}
  pendingAttachments: [],   // [{id,filename,kind,text,size}]
  pastes: {},               // paste id -> full text, collapsed to a marker in the box
  streaming: false,
  pinned: true,             // is the reader following the tail of the thread?
  lastStats: {},            // convId -> "N chars · Ns" for the newest reply
  provSig: "",              // provider-health signature, to skip no-op redraws
  convFilter: "",
  abort: null,              // AbortController for chat stream
  stream: null,             // live answer {convId, acc, asstEl, contentEl} — survives switches
  drafts: {},               // per-conversation composer text, keyed by conversation id
  workflows: [],
  wf: null,                 // editing workflow object
};

/* ============================================================
   Provider health
   ============================================================ */
async function loadProviders(opts) {
  let list;
  try { list = await api("/api/providers"); }
  catch (e) { console.warn("providers failed", e); return; }
  State.providers = Array.isArray(list) ? list : [];
  // choose default active provider: first reachable, else first
  if (!State.activeProvider) {
    const up = State.providers.find((p) => p.reachable);
    State.activeProvider = (up || State.providers[0] || {}).id || null;
  }
  // The 15s health poll used to rebuild both <select>s unconditionally, which
  // slammed the dropdown shut under the user's cursor. Redraw only on a real
  // change, and never while a picker is focused.
  const sig = State.providers
    .map((p) => `${p.id}:${p.reachable ? 1 : 0}:${(p.models || []).length}`).join("|");
  if (opts && opts.background && (sig === State.provSig || pickerBusy())) return;
  State.provSig = sig;
  renderProviderPicker();
  renderStepProviderOptions();
}

function pickerBusy() {
  const a = document.activeElement;
  return !!a && (a.id === "provider-select" || a.id === "model-select" ||
                 a.classList.contains("step-provider"));
}

function providerById(id) { return State.providers.find((p) => p.id === id) || null; }

function renderProviderPicker() {
  const sel = $("#provider-select");
  const prev = State.activeProvider;
  sel.innerHTML = "";
  State.providers.forEach((p) => {
    const o = el("option");
    o.value = p.id;
    const dot = p.reachable ? "●" : "○";
    o.textContent = `${dot} ${p.label}`;
    o.disabled = false; // still selectable; UI shows red dot + tooltip
    o.title = p.reachable
      ? `${p.base_url} — ${(p.models || []).length} model(s)`
      : `UNREACHABLE: ${p.error || "no response"} (${p.base_url})`;
    sel.appendChild(o);
  });
  if (prev && State.providers.some((p) => p.id === prev)) sel.value = prev;
  const active = providerById(sel.value);
  State.activeProvider = sel.value || null;
  sel.classList.toggle("prov-down", active && !active.reachable);
  sel.title = active
    ? (active.reachable ? `Reachable · ${active.base_url}` : `UNREACHABLE: ${active.error || "no response"}`)
    : "";
  renderModelPicker();
  updateSendEnabled();
}

function renderModelPicker() {
  const sel = $("#model-select");
  const p = providerById(State.activeProvider);
  sel.innerHTML = "";
  const def = el("option");
  def.value = "";
  def.textContent = p ? `default (${p.model})` : "default";
  sel.appendChild(def);
  if (p && Array.isArray(p.models)) {
    p.models.forEach((m) => {
      const o = el("option"); o.value = m; o.textContent = m; sel.appendChild(o);
    });
  }
  if (State.activeModel && $$("option", sel).some((o) => o.value === State.activeModel))
    sel.value = State.activeModel;
  else { sel.value = ""; State.activeModel = ""; }
}

/* ============================================================
   Conversations
   ============================================================ */
async function loadConversations() {
  try { State.conversations = await api("/api/conversations") || []; }
  catch (e) { toast("Load conversations failed: " + e.message, true); State.conversations = []; }
  renderConvList();
}

function renderConvList() {
  const ul = $("#conv-list");
  ul.innerHTML = "";
  const q = (State.convFilter || "").trim().toLowerCase();
  const list = q
    ? State.conversations.filter((c) => (c.title || "Untitled").toLowerCase().includes(q))
    : State.conversations;
  if (!list.length) {
    ul.appendChild(el("li", "empty-wf", q ? "No matches" : "No conversations yet"));
    return;
  }
  list.forEach((c) => {
    const li = el("li", "conv-item");
    li.tabIndex = 0;
    li.setAttribute("role", "button");
    if (State.conv && c.id === State.conv.id) li.classList.add("active");
    const t = el("div", "ci-title", c.title || "Untitled");
    const m = el("div", "ci-meta", c.updated ? new Date(c.updated * 1000).toLocaleString() : "");
    const del = el("button", "ci-del", "×");
    del.setAttribute("aria-label", `Delete ${c.title || "conversation"}`);
    del.title = "Delete";
    del.onclick = (e) => { e.stopPropagation(); deleteConversationById(c.id, c.title); };
    li.append(t, m, del);
    li.onclick = () => openConversation(c.id);
    li.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openConversation(c.id); } };
    ul.appendChild(li);
  });
}

async function deleteConversationById(id, title) {
  if (!confirm(`Delete "${title || "Untitled"}"?`)) return;
  try {
    await api(`/api/conversations/${id}`, { method: "DELETE" });
    delete State.drafts[id];
    if (State.conv && State.conv.id === id) { State.conv = null; renderConversation(); }
    await loadConversations();
  } catch (e) { toast("Delete failed: " + e.message, true); }
}

/* The composer is one shared textarea, so an unsent draft must be parked under
   the conversation it was typed in — otherwise it follows you into the next one
   and gets sent there. */
function saveDraft() {
  if (!State.conv) return;
  const v = $("#chat-input").value;
  if (v.trim()) State.drafts[State.conv.id] = v;
  else delete State.drafts[State.conv.id];
}

function restoreDraft() {
  const input = $("#chat-input");
  input.value = (State.conv && State.drafts[State.conv.id]) || "";
  autoGrow(input);
  updateSendEnabled();
}

async function newConversation() {
  saveDraft();
  try {
    const c = await api("/api/conversations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "New conversation" }),
    });
    State.conv = c;
    await loadConversations();
    renderConversation();
    restoreDraft();
    $("#chat-input").focus();
  } catch (e) { toast("Create failed: " + e.message, true); }
}

async function openConversation(id) {
  saveDraft();
  try {
    State.conv = await api(`/api/conversations/${id}`);
    renderConvList();
    renderConversation();
    restoreDraft();
  } catch (e) { toast("Open failed: " + e.message, true); }
}

function renderConversation(opts) {
  const c = State.conv;
  const thread = $("#thread");
  // A finished reply re-renders the thread from the server copy. If the reader
  // had scrolled up to re-read something, that rebuild must not fling them back
  // down — keepScroll restores the exact offset they were sitting at.
  const keep = !!(opts && opts.keepScroll) && State.pinned === false;
  const prevTop = thread.scrollTop;
  $("#conv-title").value = c ? (c.title || "") : "";
  $("#system-input").value = c ? (c.system || "") : "";
  thread.innerHTML = "";
  if (!c) { thread.appendChild(buildEmpty()); scrollThread(true); return; }

  // storeIdx is the index in the *stored* array (system entries included), which
  // is what the rewind actions have to slice on.
  const msgs = (c.messages || [])
    .map((m, i) => ({ role: m.role, content: m.content, storeIdx: i }))
    .filter((m) => m.role !== "system");
  const live = State.stream && State.stream.convId === c.id ? State.stream : null;
  if (!msgs.length && !live && !c.generating) {
    thread.appendChild(buildEmpty()); scrollThread(true); return;
  }
  msgs.forEach((m, i) => {
    const isLast = i === msgs.length - 1;
    thread.appendChild(buildMessage(m.role, m.content, {
      storeIdx: m.storeIdx,
      canRegen: isLast && m.role === "assistant" && !live && !c.generating,
      meta: isLast && m.role === "assistant" ? State.lastStats[c.id] : null,
    }));
  });
  if (live) attachLiveBubble(thread, live);
  else if (c.generating && !State.streaming) attachToGeneration(c.id);

  if (keep) { thread.scrollTop = prevTop; updateJumpBtn(); }
  else scrollThread(true);
}

/* Reload / tab-close no longer kills a reply: the server keeps generating. When
   we open a conversation the server still marks as generating, re-attach to the
   live buffer and stream the remaining deltas into a fresh bubble. */
async function attachToGeneration(convId) {
  const thread = $("#thread");
  const asstEl = buildMessage("assistant", "");
  asstEl.classList.add("streaming");
  thread.appendChild(asstEl);
  const live = { convId, acc: "", asstEl, contentEl: $(".content", asstEl) };
  State.stream = live;
  State.streaming = true;
  delete State.lastStats[convId];
  setStreamingUI(true);
  updateJumpBtn();
  announce("Reattached to an in-progress response…");
  State.abort = new AbortController();
  try {
    const resp = await fetch(`/api/chat/attach/${convId}`, { signal: State.abort.signal });
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = "", raf = null;
    const flush = () => { live.contentEl.innerHTML = renderMarkdown(live.acc); scrollThread(false); raf = null; };
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf("\n\n")) >= 0) {
        const chunk = buf.slice(0, idx); buf = buf.slice(idx + 2);
        for (const ln of chunk.split("\n")) {
          const m = ln.match(/^data:\s?(.*)$/);
          if (!m) continue;
          if (m[1] === "[DONE]") { buf = ""; break; }
          try { const obj = JSON.parse(m[1]);
                 if (obj.status) pushThink(live, obj.delta);
                 else if (obj.delta != null) live.acc += obj.delta; } catch (_) {}
        }
        if (!raf) raf = requestAnimationFrame(flush);
      }
    }
    live.contentEl.innerHTML = renderMarkdown(live.acc || "*(no content)*");
  } catch (_) {
    /* disconnect or abort — the server keeps the truth; re-render below */
  } finally {
    asstEl.classList.remove("streaming");
    State.streaming = false; State.abort = null; State.stream = null;
    setStreamingUI(false);
    announce("Response complete.");
    updateJumpBtn();
    try {
      if (State.conv && State.conv.id === convId) {
        State.conv = await api(`/api/conversations/${convId}`);
        renderConversation({ keepScroll: true });
      }
      loadConversations();
    } catch (_) {}
  }
}

/* Coming back to a conversation that is still generating: the user turn already
   comes from the server, only the streaming reply needs a fresh node — repoint
   the live handle at it so the remaining deltas land on screen. */
function attachLiveBubble(thread, live) {
  const asstEl = buildMessage("assistant", live.acc);
  asstEl.classList.add("streaming");
  thread.appendChild(asstEl);
  live.asstEl = asstEl;
  live.contentEl = $(".content", asstEl);
}

function buildEmpty() {
  const d = el("div", "empty-thread");
  d.innerHTML = `<div class="empty-glyph" aria-hidden="true">&Sigma;</div>
    <p>Start a conversation. Drop or paste files &mdash; text, PDF, DOCX, audio and
       images are read server-side (images via OCR) and appended to your message.</p>`;
  return d;
}

/* buildOutgoingContent appends attachment payloads to the user's own turn as
   plain text. Fold them back out into collapsed blocks, so pasting a 200KB file
   no longer turns your message into an unscrollable wall. */
const ATTACH_SPLIT = /\n\n----\nAttached ([^\n]+):\n/;

function splitAttachments(content) {
  const parts = String(content ?? "").split(ATTACH_SPLIT);
  const out = { text: parts[0], atts: [] };
  for (let i = 1; i < parts.length; i += 2)
    out.atts.push({ name: parts[i], body: parts[i + 1] || "" });
  return out;
}

function buildAttachment(a) {
  const d = el("details", "att");
  const sum = el("summary");
  sum.append(el("span", "att-name", a.name));
  const nc = a.body.length;
  sum.append(el("span", "att-size",
    nc >= 1000 ? `${(nc / 1000).toFixed(1)}k chars` : `${nc} chars`));
  d.append(sum, el("pre", null, a.body));
  return d;
}

function buildMessage(role, content, opts) {
  opts = opts || {};
  const isUser = role === "user";
  const wrap = el("div", `msg ${role}`);
  // Your own turns carry no avatar and no "You" caption — the bubble already
  // says whose it is, and the label was pure repetition on every message.
  const av = isUser ? null : el("div", "avatar", "Σ");
  const body = el("div", "body");
  const roleEl = isUser ? null : el("div", "role", "SYGNIF");
  const cont = el("div", "content" + (role === "assistant" ? " md" : ""));

  const full = String(content ?? "");
  let bare = full;
  let hadAtt = false;
  if (role === "assistant") {
    cont.innerHTML = renderMarkdown(full);
  } else {
    const split = splitAttachments(full);
    bare = split.text;
    hadAtt = split.atts.length > 0;
    cont.append(el("div", "user-text", split.text));
    split.atts.forEach((a) => cont.append(buildAttachment(a)));
  }
  if (roleEl) body.append(roleEl);
  body.append(cont);
  if (opts.meta) body.append(el("div", "msg-meta", opts.meta));
  // Live/streaming bubbles pass no storeIdx: acting on a half-written turn would
  // rewind the conversation mid-generation.
  if (opts.storeIdx != null)
    body.append(buildMsgActions(role, bare, full, opts, hadAtt));
  if (av) wrap.append(av);
  wrap.append(body);
  return wrap;
}

function buildMsgActions(role, bare, full, opts, hadAtt) {
  const box = el("div", "msg-actions");
  const copy = el("button", "msg-act", "Copy");
  copy.type = "button";
  copy.onclick = () => copyText(role === "assistant" ? full : bare, copy);
  box.append(copy);
  if (role === "user") {
    const edit = el("button", "msg-act", "Edit & resend");
    edit.type = "button";
    edit.onclick = () => editAndResend(opts.storeIdx, bare, hadAtt);
    box.append(edit);
  } else if (opts.canRegen) {
    const re = el("button", "msg-act", "Regenerate");
    re.type = "button";
    re.onclick = () => regenerate(opts.storeIdx);
    box.append(re);
  }
  return box;
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(String(text ?? ""));
    const was = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(() => (btn.textContent = was), 1200);
  } catch (_) { toast("Clipboard blocked by the browser", true); }
}

/* Both rewind actions drop every stored turn from the chosen message onward, so
   the model never sees the exchange you are replacing. */
async function truncateConv(storeIdx) {
  const kept = (State.conv.messages || []).slice(0, storeIdx);
  State.conv = await api(`/api/conversations/${State.conv.id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ messages: kept }),
  });
}

async function regenerate(storeIdx) {
  if (State.streaming) { toast("Still generating — press Stop first", true); return; }
  if (!State.conv) return;
  const convId = State.conv.id;
  const system = State.conv.system;
  try { await truncateConv(storeIdx); }
  catch (e) { toast("Regenerate failed: " + e.message, true); return; }
  const history = (State.conv.messages || []).filter((m) => m.role !== "system");
  renderConversation();
  await streamReply(convId, history, { system });
}

async function editAndResend(storeIdx, text, hadAtt) {
  if (State.streaming) { toast("Still generating — press Stop first", true); return; }
  if (!State.conv) return;
  try { await truncateConv(storeIdx); }
  catch (e) { toast("Edit failed: " + e.message, true); return; }
  renderConversation();
  const input = $("#chat-input");
  input.value = text;
  autoGrow(input); updateSendEnabled(); input.focus();
  if (hadAtt) toast("Attachments were not carried over — re-attach if needed");
  loadConversations();
}

/* Streaming must not yank the reader down. We only auto-follow when the user is
   already parked at the bottom; the moment they scroll up to read, we stop
   following and surface the "Jump to latest" button instead. */
const BOTTOM_SLOP = 90;
function threadAtBottom() {
  const t = $("#thread");
  return t.scrollHeight - t.scrollTop - t.clientHeight < BOTTOM_SLOP;
}

/* Detaching is sticky and survives the re-render at end of stream, so finishing
   a long answer never scrolls the paragraph you are reading off the screen. */
function detachThread() {
  if (State.pinned === false) return;
  State.pinned = false;
  updateJumpBtn();
}

function updateJumpBtn() {
  const btn = $("#jump-latest");
  if (!btn) return;
  const detached = State.pinned === false;
  btn.classList.toggle("hidden", !detached);
  // While detached *and* streaming, the button doubles as the "there is more
  // below" signal — that is the only cue the reader loses by not following.
  const growing = detached && State.streaming;
  btn.classList.toggle("new", growing);
  const label = $("#jump-label");
  if (label) label.textContent = growing ? "New output below" : "Jump to latest";
}

/* force=true means the user asked for it (send, jump button, opening a
   conversation). force=false is the streaming path, which may only move the
   viewport while the reader is still following the tail. */
function scrollThread(force) {
  const t = $("#thread");
  if (force) State.pinned = true;
  if (State.pinned !== false) t.scrollTop = t.scrollHeight;
  updateJumpBtn();
}
function announce(msg) {
  const r = $("#live-status");
  if (r) r.textContent = msg;
}

let titleSaveTimer = null;
function scheduleTitleSave() {
  clearTimeout(titleSaveTimer);
  titleSaveTimer = setTimeout(saveTitle, 600);
}
async function saveTitle() {
  if (!State.conv) return;
  const title = $("#conv-title").value.trim() || "Untitled";
  if (title === State.conv.title) return;
  try {
    State.conv = await api(`/api/conversations/${State.conv.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title }),
    });
    loadConversations();
  } catch (e) { toast("Rename failed: " + e.message, true); }
}

async function saveSystem() {
  if (!State.conv) return;
  const system = $("#system-input").value;
  if (system === (State.conv.system || "")) return;
  try {
    State.conv = await api(`/api/conversations/${State.conv.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ system }),
    });
    toast("System prompt saved");
  } catch (e) { toast("Save system failed: " + e.message, true); }
}

async function deleteConversation() {
  if (!State.conv) return;
  if (!confirm(`Delete "${State.conv.title || "Untitled"}"?`)) return;
  try {
    await api(`/api/conversations/${State.conv.id}`, { method: "DELETE" });
    delete State.drafts[State.conv.id];
    State.conv = null;
    await loadConversations();
    renderConversation();
  } catch (e) { toast("Delete failed: " + e.message, true); }
}

/* ============================================================
   Attachments
   ============================================================ */
function renderChips() {
  const box = $("#attach-chips");
  box.innerHTML = "";
  State.pendingAttachments.forEach((a) => {
    const chip = el("div", "chip" + (a.pending ? " pending" : "") + (a.error ? " error" : ""));
    chip.append(el("span", "chip-kind", a.kind || "file"));
    chip.append(el("span", "chip-name", a.filename + (a.pending ? " …" : "")));
    const x = el("button", "chip-x", "×");
    x.setAttribute("aria-label", `Remove ${a.filename}`);
    x.title = "Remove";
    x.onclick = () => { State.pendingAttachments = State.pendingAttachments.filter((p) => p !== a); renderChips(); };
    chip.append(x);
    box.appendChild(chip);
  });
}

async function uploadFile(file) {
  // A pasted screenshot occasionally arrives as a zero-byte blob (the clipboard
  // image isn't ready at paste time). Catch it here with a clear ask to re-paste,
  // instead of uploading nothing and letting OCR fail with "cannot identify image".
  if (!file.size) {
    toast(`"${file.name || "clipboard image"}" arrived empty — re-copy and paste again`, true);
    return;
  }
  if (file.size > 25 * 1024 * 1024) { toast(`"${file.name}" exceeds 25MB`, true); return; }
  const placeholder = { filename: file.name, kind: "file", text: "", pending: true, size: file.size };
  State.pendingAttachments.push(placeholder);
  renderChips();
  try {
    const fd = new FormData();
    fd.append("file", file);
    const res = await api("/api/upload", { method: "POST", body: fd });
    Object.assign(placeholder, {
      id: res.id, filename: res.filename || file.name, kind: res.kind || "file",
      text: res.text || "", size: res.size, pending: false,
    });
    if (res.note) toast(res.note);
  } catch (e) {
    placeholder.pending = false; placeholder.error = true;
    toast(`Upload "${file.name}" failed: ${e.message}`, true);
  }
  renderChips();
}

function handleFiles(files) {
  Array.from(files).forEach((f) => uploadFile(f));
}

/* ============================================================
   Chat send + streaming
   ============================================================ */
/* ---------- pasted-blob compaction (Claude-CLI style) ----------
   A big paste would otherwise blow the composer up to full height and bury the
   line you are actually typing. Collapse it to a one-line marker, keep the real
   text aside, and splice it back in at send time. */
const PASTE_MAX_CHARS = 800;
const PASTE_MAX_LINES = 12;
let pasteSeq = 0;

function pasteMarker(id, lines) { return `[Pasted text #${id} +${lines} lines]`; }

/* Only markers still present in the box are expanded — deleting the marker is
   how you discard the paste, so a removed one must not come back on send. */
function expandPastes(text) {
  return String(text).replace(/\[Pasted text #(\d+) \+\d+ lines\]/g,
    (full, id) => (State.pastes[id] !== undefined ? State.pastes[id] : full));
}

function insertAtCursor(el, str) {
  const s = el.selectionStart ?? el.value.length;
  const e = el.selectionEnd ?? el.value.length;
  el.value = el.value.slice(0, s) + str + el.value.slice(e);
  const pos = s + str.length;
  el.setSelectionRange(pos, pos);
}

function buildOutgoingContent(text) {
  let content = expandPastes(text);
  const ready = State.pendingAttachments.filter((a) => !a.pending && !a.error && a.text);
  ready.forEach((a) => {
    content += `\n\n----\nAttached ${a.filename}:\n${a.text}`;
  });
  return content;
}

function updateSendEnabled() {
  const hasText = $("#chat-input").value.trim().length > 0;
  const hasAttach = State.pendingAttachments.some((a) => !a.pending && !a.error);
  $("#send-btn").disabled = State.streaming || (!hasText && !hasAttach);
}

async function sendMessage() {
  if (State.streaming) {
    toast("Still generating — press Stop first (your text is kept)", true);
    return;
  }
  const inputEl = $("#chat-input");
  const raw = inputEl.value.trim();
  const readyAttach = State.pendingAttachments.filter((a) => !a.pending && !a.error && a.text);
  if (!raw && !readyAttach.length) return;
  if (State.pendingAttachments.some((a) => a.pending)) { toast("Wait for uploads to finish"); return; }

  if (!State.conv) await newConversation();
  if (!State.conv) return;

  const provider = State.activeProvider;
  if (!provider) { toast("No provider selected", true); return; }

  // Pin the target conversation: everything below belongs to THIS id, even if
  // the user switches away while the answer is still streaming.
  const convId = State.conv.id;
  const content = buildOutgoingContent(raw);
  // clear composer
  inputEl.value = ""; autoGrow(inputEl);
  delete State.drafts[convId];
  State.pendingAttachments = []; renderChips();
  State.pastes = {};   // markers were expanded into `content` above

  // local message list (exclude system entries)
  const history = (State.conv.messages || []).filter((m) => m.role !== "system");
  history.push({ role: "user", content });

  // remove empty-thread placeholder
  const emptyEl = $("#empty-thread") || $(".empty-thread", $("#thread"));
  if (emptyEl) emptyEl.remove();

  const thread = $("#thread");
  thread.appendChild(buildMessage("user", content));
  scrollThread(true);
  autoTitle(convId, raw);
  await streamReply(convId, history, { system: State.conv.system, restoreText: raw });
}

/* A sidebar full of "New conversation" is unusable, and nothing else in the app
   ever names a thread. Derive one from the opening line — never overwriting a
   title the user typed. */
function deriveTitle(text) {
  const first = String(text || "").split("\n").find((l) => l.trim()) || "";
  const t = first.trim().replace(/\s+/g, " ");
  if (t.length <= 52) return t;
  return t.slice(0, 52).replace(/\s\S*$/, "") + "…";
}

async function autoTitle(convId, userText) {
  const c = State.conv;
  const cur = ((c && c.id === convId ? c.title : "") || "").trim();
  if (cur && !/^(new conversation|untitled)$/i.test(cur)) return;
  const title = deriveTitle(userText);
  if (!title) return;
  try {
    const updated = await api(`/api/conversations/${convId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title }),
    });
    if (State.conv && State.conv.id === convId) {
      State.conv.title = updated.title;
      if (document.activeElement !== $("#conv-title")) $("#conv-title").value = updated.title;
    }
    loadConversations();
  } catch (_) { /* a title is not worth an error toast */ }
}

function statsLine(chars, ms) {
  const secs = ms / 1000;
  const rate = secs > 0.2 ? ` · ${Math.round(chars / secs)} char/s` : "";
  return `${chars.toLocaleString()} chars · ${secs < 10 ? secs.toFixed(1) : Math.round(secs)}s${rate}`;
}

/* The streaming half of a turn, shared by a fresh send and by Regenerate. */
async function streamReply(convId, history, opts) {
  opts = opts || {};
  const provider = State.activeProvider;
  if (!provider) { toast("No provider selected", true); return; }
  const inputEl = $("#chat-input");
  const raw = opts.restoreText || "";
  const thread = $("#thread");
  const asstEl = buildMessage("assistant", "");
  asstEl.classList.add("streaming");
  thread.appendChild(asstEl);
  scrollThread(false);

  State.streaming = true;
  announce("SYGNIF is responding…");
  setStreamingUI(true);
  updateJumpBtn();
  State.abort = new AbortController();
  const live = { convId, acc: "", asstEl, contentEl: $(".content", asstEl) };
  State.stream = live;
  const t0 = performance.now();

  const payload = {
    provider,
    messages: history,
    stream: true,
    conversation_id: convId,
  };
  if (State.activeModel) payload.model = State.activeModel;
  if (opts.system) payload.system = opts.system;

  let aborted = false;
  try {
    const resp = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: State.abort.signal,
    });
    if (!resp.ok) {
      let detail = `${resp.status}`;
      try { const j = await resp.json(); detail = j.detail || j.content || detail; } catch (_) {}
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    const ctype = resp.headers.get("content-type") || "";
    if (ctype.includes("application/json")) {
      // non-stream fallback
      const j = await resp.json();
      live.acc = j.content || "";
      live.contentEl.innerHTML = renderMarkdown(live.acc);
    } else {
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      let raf = null;
      const flush = () => { live.contentEl.innerHTML = renderMarkdown(live.acc); scrollThread(false); raf = null; };
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf("\n\n")) >= 0) {
          const chunk = buf.slice(0, idx); buf = buf.slice(idx + 2);
          const lines = chunk.split("\n");
          for (const ln of lines) {
            const m = ln.match(/^data:\s?(.*)$/);
            if (!m) continue;
            const data = m[1];
            if (data === "[DONE]") { buf = ""; break; }
            try {
              const obj = JSON.parse(data);
              if (obj.status) pushThink(live, obj.delta);
              else if (obj.delta != null) live.acc += obj.delta;
              else if (obj.error) live.acc += `\n\n[error] ${obj.content || obj.error}`;
            } catch (_) { /* ignore partial/non-json */ }
          }
          if (!raf) raf = requestAnimationFrame(flush);
        }
      }
      live.contentEl.innerHTML = renderMarkdown(live.acc || "*(no content)*");
    }
  } catch (e) {
    if (e.name === "AbortError") {
      aborted = true;
      live.acc += "\n\n_[stopped]_";
      live.contentEl.innerHTML = renderMarkdown(live.acc);
    } else {
      live.contentEl.innerHTML = renderMarkdown(live.acc + `\n\n[error] ${e.message}`);
      toast("Chat error: " + e.message, true);
      // The request never reached the server (400/500/offline): hand the typed
      // text back to the composer instead of eating it.
      if (!live.acc && !inputEl.value.trim()) { inputEl.value = raw; autoGrow(inputEl); updateSendEnabled(); }
    }
  } finally {
    live.asstEl.classList.remove("streaming");
    State.streaming = false;
    State.abort = null;
    State.stream = null;
    setStreamingUI(false);
    announce(aborted ? "Generation stopped." : "Response complete.");
    State.lastStats[convId] = statsLine(live.acc.length, Math.round(performance.now() - t0));
    updateJumpBtn();
    // On abort the server writes its partial a moment after the socket closes.
    if (aborted) await new Promise((r) => setTimeout(r, 350));
    // The server holds the truth now (user turn written up front, answer at the
    // end). Re-render whatever is on screen so the exchange shows immediately —
    // no switch-away-and-back needed.
    try {
      if (State.conv && State.conv.id === convId) {
        State.conv = await api(`/api/conversations/${convId}`);
        renderConversation({ keepScroll: true });
      }
      loadConversations();
    } catch (_) {
      if (State.conv && State.conv.id === convId)
        State.conv.messages = history.concat([{ role: "assistant", content: live.acc }]);
    }
  }
}

/* Liveness ticker.
   Measured gaps between visible frames run 10-20s, and the server's keepalive is
   an SSE *comment* — it keeps the socket open but paints nothing, so the UI sat
   on "thinking (round 1)" looking dead for ~35s before an answer. This ticks
   client-side, so it keeps moving during any upstream pause without needing a
   single extra byte from the server. */
let streamTimer = null;


/* ---------- foldable thinking trace ----------
   Status frames (round/tool/retry notices) used to be appended straight into the
   answer text, so the reasoning noise and the actual reply were one blob. They
   now collect into a <details> above the content: folded by default, expand to
   see every step. Native <details> again, so it survives the innerHTML rewrite
   that each streaming frame performs. Live-only — status is never persisted
   server-side, so it is gone after a reload, by design. */
function ensureThinkEl(live) {
  if (live.thinkEl && live.thinkEl.isConnected) return live.thinkEl;
  const d = el("details", "thinking");
  d.innerHTML = '<summary><span class="think-label"></span></summary><div class="think-body"></div>';
  if (live.contentEl && live.contentEl.parentNode)
    live.contentEl.parentNode.insertBefore(d, live.contentEl);
  live.thinkEl = d;
  return d;
}

function pushThink(live, line) {
  const t = String(line || "").replace(/\s+$/, "").replace(/^[·\s]+/, "").trim();
  if (!t) return;
  live.think = live.think || [];
  live.think.push(t);
  const d = ensureThinkEl(live);
  const n = live.think.length;
  const lbl = d.querySelector(".think-label");
  if (lbl) lbl.textContent = `thinking · ${n} step${n === 1 ? "" : "s"}`;
  const body = d.querySelector(".think-body");
  if (body) body.textContent = live.think.join("\n");
}

function setStreamingUI(on) {
  $("#send-btn").classList.toggle("hidden", on);
  $("#stop-btn").classList.toggle("hidden", !on);
  const el = $("#stream-timer");
  if (streamTimer) { clearInterval(streamTimer); streamTimer = null; }
  if (el) {
    el.classList.toggle("hidden", !on);
    if (on) {
      const t0 = Date.now();
      const tick = () => {
        const s = Math.round((Date.now() - t0) / 1000);
        el.textContent = s < 60 ? `working ${s}s` : `working ${Math.floor(s / 60)}m ${s % 60}s`;
      };
      tick();
      streamTimer = setInterval(tick, 1000);
    } else {
      el.textContent = "";
    }
  }
  updateSendEnabled();
}

/* Generation is detached on the server, so aborting the local fetch alone would
   leave it running (and billing). Tell the server to cancel first, then drop
   our reader. */
function stopStreaming() {
  const convId = (State.stream && State.stream.convId) || (State.conv && State.conv.id);
  if (convId) {
    fetch(`/api/chat/stop/${convId}`, { method: "POST" }).catch(() => {});
  }
  if (State.abort) State.abort.abort();
}

/* ============================================================
   Composer autosize + keyboard
   ============================================================ */
function autoGrow(t) {
  t.style.height = "auto";
  t.style.height = Math.min(t.scrollHeight, 220) + "px";
}

/* ============================================================
   Workflows
   ============================================================ */
async function loadWorkflows() {
  try { State.workflows = await api("/api/workflows") || []; }
  catch (e) { toast("Load workflows failed: " + e.message, true); State.workflows = []; }
  renderWfList();
}

function renderWfList() {
  const ul = $("#wf-list");
  ul.innerHTML = "";
  if (!State.workflows.length) ul.appendChild(el("li", "empty-wf", "No workflows"));
  // Prefer a server-supplied flag; the id list is only a fallback for older
  // payloads, and would silently go stale as seeds are added.
  const BUILTIN_IDS = new Set(["wf-summarize-actions", "wf-translate-polish", "wf-meeting-summary"]);
  const isBuiltin = (w) => (w.builtin != null ? !!w.builtin : BUILTIN_IDS.has(w.id));
  State.workflows.forEach((w) => {
    const li = el("li", "conv-item" + (isBuiltin(w) ? " builtin" : ""));
    if (State.wf && w.id === State.wf.id) li.classList.add("active");
    li.append(el("div", "ci-title", w.name || "Untitled"));
    li.append(el("div", "ci-meta", `${(w.steps || []).length} step(s)`));
    li.onclick = () => editWorkflow(w.id);
    ul.appendChild(li);
  });
}

function newWorkflow() {
  State.wf = {
    id: null,
    name: "New workflow",
    steps: [{ name: "Step 1", provider: defaultWfProvider(), model: "", system: "", prompt: "{{input}}" }],
  };
  renderWfList();
  renderWfEditor();
}

function defaultWfProvider() {
  if (providerById("claude")) return "claude";
  return State.activeProvider || (State.providers[0] || {}).id || "";
}

async function editWorkflow(id) {
  try {
    const w = await api(`/api/workflows/${id}`);
    // deep-ish clone for editing
    State.wf = { id: w.id, name: w.name, steps: (w.steps || []).map((s) => ({ ...s })) };
    renderWfList();
    renderWfEditor();
  } catch (e) { toast("Open workflow failed: " + e.message, true); }
}

function providerOptionsHtml(selected) {
  return State.providers.map((p) => {
    const dot = p.reachable ? "●" : "○";
    return `<option value="${esc(p.id)}"${p.id === selected ? " selected" : ""}>${dot} ${esc(p.label)}</option>`;
  }).join("");
}

function renderStepProviderOptions() {
  // refresh provider dropdowns already in DOM (health changed)
  $$(".step-provider").forEach((sel) => {
    const cur = sel.value;
    sel.innerHTML = providerOptionsHtml(cur);
  });
}

function renderWfEditor() {
  const w = State.wf;
  const editor = $("#wf-editor");
  if (!w) { editor.style.display = "none"; return; }
  editor.style.display = "flex";
  $("#wf-name").value = w.name || "";
  $("#wf-delete").style.display = w.id ? "" : "none";
  const stepsBox = $("#wf-steps");
  stepsBox.innerHTML = "";
  w.steps.forEach((s, idx) => stepsBox.appendChild(buildStepEditor(s, idx)));
}

function buildStepEditor(step, idx) {
  const box = el("div", "wf-step");
  box.dataset.idx = idx;

  const head = el("div", "wf-step-head");
  head.append(el("span", "wf-step-num", `#${idx + 1}`));
  const nameIn = el("input", "step-name"); nameIn.value = step.name || "";
  nameIn.placeholder = "Step name";
  nameIn.oninput = () => (State.wf.steps[idx].name = nameIn.value);
  head.append(nameIn);

  const up = el("button", "wf-step-move", "↑"); up.title = "Move up"; up.setAttribute("aria-label", `Move step ${idx + 1} up`);
  up.onclick = () => moveStep(idx, -1);
  const down = el("button", "wf-step-move", "↓"); down.title = "Move down"; down.setAttribute("aria-label", `Move step ${idx + 1} down`);
  down.onclick = () => moveStep(idx, 1);
  const del = el("button", "wf-step-del", "×"); del.title = "Delete step"; del.setAttribute("aria-label", `Delete step ${idx + 1}`);
  del.onclick = () => { State.wf.steps.splice(idx, 1); if (!State.wf.steps.length) addStep(); else renderWfEditor(); };
  head.append(up, down, del);
  box.append(head);

  const grid = el("div", "wf-step-grid");
  // provider
  const pf = el("div", "wf-field");
  pf.append(el("label", null, "Provider"));
  const psel = el("select", "step-provider");
  psel.innerHTML = providerOptionsHtml(step.provider || defaultWfProvider());
  psel.value = step.provider || defaultWfProvider();
  State.wf.steps[idx].provider = psel.value;
  psel.onchange = () => (State.wf.steps[idx].provider = psel.value);
  pf.append(psel);
  // model
  const mf = el("div", "wf-field");
  mf.append(el("label", null, "Model (optional)"));
  const min = el("input"); min.value = step.model || ""; min.placeholder = "provider default";
  min.oninput = () => (State.wf.steps[idx].model = min.value);
  mf.append(min);
  grid.append(pf, mf);
  box.append(grid);

  // system
  const sf = el("div", "wf-field");
  sf.append(el("label", null, "System (optional)"));
  const sin = el("input"); sin.value = step.system || ""; sin.placeholder = "system prompt for this step";
  sin.oninput = () => (State.wf.steps[idx].system = sin.value);
  sf.append(sin);
  box.append(sf);

  // prompt
  const pl = el("label", null, "Prompt template");
  pl.style.cssText = "font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--text-faint);display:block;margin:8px 0 3px";
  box.append(pl);
  const pta = el("textarea", "step-prompt"); pta.value = step.prompt || "";
  pta.oninput = () => (State.wf.steps[idx].prompt = pta.value);
  box.append(pta);
  const hint = el("div", "tmpl-hint");
  hint.innerHTML = `Use <code>{{input}}</code> (original) and <code>{{prev}}</code> (previous step output).`;
  box.append(hint);

  return box;
}

function moveStep(idx, dir) {
  const to = idx + dir;
  if (to < 0 || to >= State.wf.steps.length) return;
  const s = State.wf.steps.splice(idx, 1)[0];
  State.wf.steps.splice(to, 0, s);
  renderWfEditor();
}

function addStep() {
  State.wf.steps.push({
    name: `Step ${State.wf.steps.length + 1}`,
    provider: defaultWfProvider(), model: "", system: "",
    prompt: State.wf.steps.length ? "{{prev}}" : "{{input}}",
  });
  renderWfEditor();
}

async function saveWorkflow() {
  const w = State.wf;
  if (!w) return;
  w.name = $("#wf-name").value.trim() || "Untitled workflow";
  if (!w.steps.length) { toast("Add at least one step", true); return; }
  const body = {
    name: w.name,
    steps: w.steps.map((s) => ({
      name: s.name || "Step", provider: s.provider || defaultWfProvider(),
      model: s.model || undefined, system: s.system || undefined, prompt: s.prompt || "{{input}}",
    })),
  };
  if (w.id) body.id = w.id;
  try {
    const saved = await api("/api/workflows", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    State.wf = { id: saved.id, name: saved.name, steps: (saved.steps || []).map((s) => ({ ...s })) };
    await loadWorkflows();
    renderWfEditor();
    toast("Workflow saved");
  } catch (e) { toast("Save failed: " + e.message, true); }
}

async function deleteWorkflow() {
  const w = State.wf;
  if (!w || !w.id) return;
  if (!confirm(`Delete workflow "${w.name}"?`)) return;
  try {
    await api(`/api/workflows/${w.id}`, { method: "DELETE" });
    State.wf = null;
    await loadWorkflows();
    $("#wf-editor").style.display = "none";
  } catch (e) { toast("Delete failed: " + e.message, true); }
}

async function runWorkflow() {
  const w = State.wf;
  if (!w) { toast("Select or create a workflow first", true); return; }
  if (!w.id) { toast("Save the workflow before running", true); return; }
  const input = $("#wf-input").value;
  if (!input.trim()) { toast("Provide input to run", true); return; }

  const log = $("#wf-log");
  log.innerHTML = "";
  const btn = $("#wf-run-btn");
  btn.disabled = true; btn.textContent = "Running…";
  State.wfAbort = new AbortController();
  const wfStop = $("#wf-stop-btn");
  if (wfStop) wfStop.classList.remove("hidden");

  // Same rule as the chat thread: only follow the tail if the reader is on it.
  const wfAtBottom = () => log.scrollHeight - log.scrollTop - log.clientHeight < 60;
  const stepEls = {}; // index -> {body, head, spin}
  const ensureStep = (i, name) => {
    if (stepEls[i]) return stepEls[i];
    const stick = wfAtBottom();
    const box = el("div", "wf-log-step");
    const head = el("div", "wf-log-step-head");
    head.append(el("span", "st-num", `#${i + 1}`));
    head.append(el("span", null, name || (w.steps[i] ? w.steps[i].name : "Step")));
    const spin = el("span", "st-spin", "running…");
    head.append(spin);
    const body = el("div", "wf-log-step-body md");
    box.append(head, body);
    log.appendChild(box);
    stepEls[i] = { body, head, spin, acc: "" };
    if (stick) log.scrollTop = log.scrollHeight;
    return stepEls[i];
  };

  try {
    const resp = await fetch(`/api/workflows/${w.id}/run`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input, stream: true }),
      signal: State.wfAbort.signal,
    });
    if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`);
    const ctype = resp.headers.get("content-type") || "";
    if (ctype.includes("application/json")) {
      const j = await resp.json();
      (j.steps || []).forEach((s, i) => {
        const st = ensureStep(i, s.name); st.acc = s.output || "";
        st.body.innerHTML = renderMarkdown(st.acc);
        st.spin.className = "st-done"; st.spin.textContent = "done";
      });
    } else {
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf("\n\n")) >= 0) {
          const chunk = buf.slice(0, idx); buf = buf.slice(idx + 2);
          for (const ln of chunk.split("\n")) {
            const m = ln.match(/^data:\s?(.*)$/);
            if (!m) continue;
            if (m[1] === "[DONE]") { buf = ""; break; }
            try {
              const obj = JSON.parse(m[1]);
              const i = obj.step ?? 0;
              const stick = wfAtBottom();
              const st = ensureStep(i, obj.name);
              if (obj.delta != null) { st.acc += obj.delta; st.body.innerHTML = renderMarkdown(st.acc); }
              if (obj.done) { st.spin.className = "st-done"; st.spin.textContent = "done"; }
              if (stick) log.scrollTop = log.scrollHeight;
            } catch (_) {}
          }
        }
      }
    }
  } catch (e) {
    if (e.name === "AbortError") { log.appendChild(el("div", "empty-wf", "Run stopped.")); }
    else { log.appendChild(el("div", "empty-wf", "Run error: " + e.message)); toast("Run failed: " + e.message, true); }
  } finally {
    btn.disabled = false; btn.textContent = "Run workflow";
    State.wfAbort = null;
    const wfStop = $("#wf-stop-btn");
    if (wfStop) wfStop.classList.add("hidden");
  }
}

/* ============================================================
   View switching
   ============================================================ */
function switchView(v) {
  State.view = v;
  $$(".navbtn").forEach((b) => {
    const on = b.dataset.view === v;
    b.classList.toggle("active", on);
    b.setAttribute("aria-selected", on ? "true" : "false");
    b.tabIndex = on ? 0 : -1;
  });
  $("#view-chat").classList.toggle("active", v === "chat");
  $("#view-workflows").classList.toggle("active", v === "workflows");
  if (v === "workflows") {
    loadWorkflows();
    if (!State.wf) $("#wf-editor").style.display = "none";
  }
}

/* ============================================================
   Wiring
   ============================================================ */
function wire() {
  // nav
  $$(".navbtn").forEach((b) => (b.onclick = () => switchView(b.dataset.view)));

  // provider/model
  $("#provider-select").onchange = (e) => {
    State.activeProvider = e.target.value; State.activeModel = "";
    renderProviderPicker();
  };
  $("#model-select").onchange = (e) => { State.activeModel = e.target.value; };
  $("#health-refresh").onclick = () => { loadProviders(); toast("Refreshing provider health…"); };

  // conversations
  $("#new-conv").onclick = newConversation;
  $("#conv-title").oninput = scheduleTitleSave;
  $("#conv-title").onblur = saveTitle;
  $("#toggle-system").onclick = () => $("#system-row").classList.toggle("hidden");
  $("#system-input").onblur = saveSystem;
  $("#del-conv").onclick = deleteConversation;

  // composer
  const input = $("#chat-input");
  input.addEventListener("input", () => { autoGrow(input); updateSendEnabled(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); sendMessage(); }
  });
  $("#send-btn").onclick = sendMessage;
  $("#stop-btn").onclick = stopStreaming;
  $("#attach-btn").onclick = () => $("#file-input").click();
  $("#file-input").onchange = (e) => { handleFiles(e.target.files); e.target.value = ""; };

  // paste: files go to upload, oversized text collapses to a marker
  input.addEventListener("paste", (e) => {
    if (!e.clipboardData) return;
    const items = e.clipboardData.items || [];
    const files = [];
    for (const it of items) if (it.kind === "file") { const f = it.getAsFile(); if (f) files.push(f); }
    if (files.length) { e.preventDefault(); handleFiles(files); return; }

    const txt = e.clipboardData.getData("text");
    if (!txt) return;
    const lines = txt.split("\n").length;
    if (txt.length <= PASTE_MAX_CHARS && lines <= PASTE_MAX_LINES) return;  // small paste: normal
    e.preventDefault();
    const id = ++pasteSeq;
    State.pastes[id] = txt;
    insertAtCursor(input, pasteMarker(id, lines));
    autoGrow(input);
    updateSendEnabled();
    toast(`Collapsed ${lines} pasted lines — sent in full`);
    announce(`Pasted text ${id} collapsed, ${lines} lines`);
  });

  // drag & drop onto thread/chat-main
  const dz = $("#chat-main");
  const overlay = $("#dropzone-overlay");
  let dragDepth = 0;
  const showOverlay = (on) => overlay.classList.toggle("hidden", !on);
  ["dragenter"].forEach((ev) => dz.addEventListener(ev, (e) => {
    if (!e.dataTransfer || Array.from(e.dataTransfer.types || []).indexOf("Files") < 0) return;
    e.preventDefault(); dragDepth++; showOverlay(true);
  }));
  dz.addEventListener("dragover", (e) => {
    if (e.dataTransfer && Array.from(e.dataTransfer.types || []).indexOf("Files") >= 0) e.preventDefault();
  });
  dz.addEventListener("dragleave", () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) showOverlay(false); });
  dz.addEventListener("drop", (e) => {
    if (!e.dataTransfer) return;
    e.preventDefault(); dragDepth = 0; showOverlay(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
  });

  // workflows
  $("#new-wf").onclick = newWorkflow;
  $("#wf-add-step").onclick = () => State.wf && addStep();
  $("#wf-save").onclick = saveWorkflow;
  $("#wf-delete").onclick = deleteWorkflow;
  $("#wf-name").oninput = () => State.wf && (State.wf.name = $("#wf-name").value);
  $("#wf-run-btn").onclick = runWorkflow;

  // follow-on-stream: track whether the reader is parked at the bottom
  const thread = $("#thread");
  thread.addEventListener("scroll", () => {
    State.pinned = threadAtBottom();
    updateJumpBtn();
  }, { passive: true });
  // Detach on the gesture, not on the resulting scroll event: during a fast
  // stream a rAF flush can land in the same frame and re-pin to the bottom,
  // undoing the scroll before the user sees it. Returning to the bottom re-pins
  // via the scroll handler above.
  thread.addEventListener("wheel", (e) => { if (e.deltaY < 0) detachThread(); }, { passive: true });
  thread.addEventListener("touchmove", detachThread, { passive: true });
  thread.addEventListener("keydown", (e) => {
    if (e.key === "PageUp" || e.key === "ArrowUp" || e.key === "Home") detachThread();
  });
  const jump = $("#jump-latest");
  if (jump) jump.onclick = () => { State.pinned = true; scrollThread(true); };

  // mobile sidebar drawer
  const drawer = $("#drawer-toggle");
  if (drawer) drawer.onclick = () => toggleDrawer();
  const scrim = $("#scrim");
  if (scrim) scrim.onclick = () => toggleDrawer(false);

  // conversation filter
  const search = $("#conv-search");
  if (search) search.oninput = (e) => { State.convFilter = e.target.value; renderConvList(); };

  // workflow stop
  const wfStop = $("#wf-stop-btn");
  if (wfStop) wfStop.onclick = () => { if (State.wfAbort) State.wfAbort.abort(); };

  // global keys
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      if (State.view !== "chat") switchView("chat");
      newConversation();
    }
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && State.view === "workflows") {
      e.preventDefault(); runWorkflow();
    }
    if (e.key === "Escape") {
      if (State.streaming) { stopStreaming(); }
      else if (State.wfAbort) { State.wfAbort.abort(); }
      else if (document.body.classList.contains("drawer-open")) { toggleDrawer(false); }
    }
  });
}

function toggleDrawer(force) {
  const open = force === undefined ? !document.body.classList.contains("drawer-open") : force;
  document.body.classList.toggle("drawer-open", open);
  const scrim = $("#scrim");
  if (scrim) scrim.classList.toggle("hidden", !open);
  const btn = $("#drawer-toggle");
  if (btn) btn.setAttribute("aria-expanded", open ? "true" : "false");
}

/* ============================================================
   Boot
   ============================================================ */
/* Closing the tab no longer ends a reply — generation is detached server-side.
   On reopen, say so plainly and offer the way back, instead of leaving the user
   to guess whether the work survived. */
function showResumeBar() {
  const bar = $("#resume-bar");
  if (!bar) return;
  const live = State.conversations.find((c) => c.generating);
  const cut = State.conversations.find((c) => c.interrupted);
  const target = live || cut;
  if (!target) { bar.classList.add("hidden"); return; }
  const name = target.title || "Untitled";
  $("#resume-text").textContent = live
    ? `“${name}” is still generating on the server.`
    : `“${name}” was cut short.`;
  $("#resume-btn").textContent = live ? "Reattach" : "Open";
  $("#resume-btn").onclick = () => {
    bar.classList.add("hidden");
    if (State.view !== "chat") switchView("chat");
    openConversation(target.id);
  };
  $("#resume-dismiss").onclick = () => bar.classList.add("hidden");
  bar.classList.remove("hidden");
  announce($("#resume-text").textContent);
}

async function boot() {
  State.pinned = true;
  State.convFilter = "";
  wire();
  $("#wf-editor").style.display = "none";
  await loadProviders();
  await loadConversations();
  // open most recent conversation if any
  if (State.conversations.length) openConversation(State.conversations[0].id);
  else renderConversation();
  showResumeBar();
  updateSendEnabled();
  // poll provider health every 15s
  setInterval(() => loadProviders({ background: true }), 15000);
}

document.addEventListener("DOMContentLoaded", boot);
