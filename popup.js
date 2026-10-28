import { totp, normalizeSite, parseOtpauth, base32Decode, cleanSecret, hostMatches, normalizeAlgorithm } from "./lib.js";

const $ = (sel) => document.querySelector(sel);

let accounts = [];
let currentHost = "";
let currentTabId = null;
let editingId = null;
let tickTimer = null;

async function call(type, data = {}) {
  const res = await chrome.runtime.sendMessage({ type, ...data });
  if (!res) throw new Error("The extension did not respond. Try reopening the popup.");
  if (!res.ok) throw new Error(res.error);
  return res.result;
}

function show(view) {
  document.querySelectorAll(".view").forEach((v) => (v.hidden = v.id !== "view-" + view));
  if (view !== "list") clearInterval(tickTimer);
  const focus = { setup: "#setup-pw", unlock: "#unlock-pw", list: "#search" }[view];
  if (focus) setTimeout(() => $(focus)?.focus(), 0);
}

let toastTimer;
function toast(text) {
  const t = $("#toast");
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 1600);
}

async function busy(button, fn) {
  if (button) button.disabled = true;
  try { return await fn(); } finally { if (button) button.disabled = false; }
}

// ---------- start ----------

async function init() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTabId = tab?.id ?? null;
    if (tab?.url && /^https?:/.test(tab.url)) currentHost = new URL(tab.url).hostname;
  } catch { /* no tab access */ }

  const { initialized, unlocked } = await call("status");
  if (!initialized) return show("setup");
  if (!unlocked) return showUnlock({ auto: true });
  await openList();
}

// ---------- setup / unlock ----------

$("#setup-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pw = $("#setup-pw").value;
  const err = $("#setup-error");
  err.textContent = "";
  if (pw !== $("#setup-pw2").value) return (err.textContent = "Passwords don't match.");
  await busy(e.submitter, async () => {
    try {
      await call("setup", { password: pw });
      await openList();
    } catch (ex) { err.textContent = ex.message; }
  });
});

async function showUnlock({ auto = false } = {}) {
  const { enabled } = await call("bioStatus");
  // Opening the popup while locked goes straight to the fingerprint prompt (can be turned off in Settings).
  if (enabled && auto && (await call("getSettings")).autoBio && !(await call("consumeBioSkip"))) {
    await call("openBioWindow", { mode: "unlock" });
    return window.close();
  }
  $("#bio-unlock").hidden = !enabled;
  show("unlock");
  if (enabled) setTimeout(() => $("#bio-unlock-btn").focus(), 0);
}

// The fingerprint prompt runs in its own small window; the popup would close when Windows Hello takes focus.
$("#bio-unlock-btn").addEventListener("click", async () => {
  await call("openBioWindow", { mode: "unlock" });
  window.close();
});

$("#unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#unlock-error");
  err.textContent = "";
  const btn = $("#unlock-btn");
  btn.textContent = "Unlocking…";
  await busy(btn, async () => {
    try {
      await call("unlock", { password: $("#unlock-pw").value });
      $("#unlock-pw").value = "";
      await openList();
    } catch (ex) {
      err.textContent = ex.message;
      $("#unlock-pw").select();
    }
  });
  btn.textContent = "Unlock";
});

$("#reset-btn").addEventListener("click", async () => {
  const ok = confirm("Erase the vault?\n\nThis permanently deletes every saved 2FA secret in this browser. " +
    "Make sure you can still get codes some other way (another authenticator app or backup codes) before doing this.");
  if (!ok) return;
  await call("resetVault");
  show("setup");
});

$("#lock-btn").addEventListener("click", async () => {
  await call("lock");
  accounts = [];
  await showUnlock();
});

// ---------- list ----------

async function openList() {
  accounts = await call("getAccounts");
  show("list");
  render();
}

function sortForDisplay(list) {
  const here = (a) => currentHost && (a.sites || []).some((s) => hostMatches(currentHost, s));
  const byName = (a, b) => (a.name || "").localeCompare(b.name || "");
  return {
    here: list.filter(here).sort(byName),
    rest: list.filter((a) => !here(a)).sort(byName),
  };
}

function render() {
  const q = $("#search").value.trim().toLowerCase();
  const filtered = accounts.filter((a) =>
    !q || [a.name, a.username, a.email, ...(a.sites || [])].some((v) => (v || "").toLowerCase().includes(q))
  );
  const list = $("#list");
  list.textContent = "";
  $("#empty").hidden = accounts.length > 0;
  $("#search").hidden = accounts.length === 0;

  const { here, rest } = sortForDisplay(filtered);
  if (here.length) {
    list.append(label("This site"));
    here.forEach((a) => list.append(card(a, true)));
    if (rest.length) list.append(label("Other accounts"));
  }
  rest.forEach((a) => list.append(card(a, false)));
  if (accounts.length && !filtered.length) list.append(label("No matches"));

  clearInterval(tickTimer);
  tick();
  tickTimer = setInterval(tick, 1000);
}

function label(text) {
  const d = document.createElement("div");
  d.className = "section-label";
  d.textContent = text;
  return d;
}

const formatCode = (c) => (c.length === 6 ? c.slice(0, 3) + " " + c.slice(3) : c.length === 8 ? c.slice(0, 4) + " " + c.slice(4) : c);

function card(a, isHere) {
  const el = $("#card-tpl").content.firstElementChild.cloneNode(true);
  el.dataset.id = a.id;
  el.classList.toggle("here", isHere);
  el.querySelector(".name").textContent = a.name || "Untitled";
  el.querySelector(".sub").textContent = [a.username, a.email].filter(Boolean).join(" · ");
  const sites = el.querySelector(".sites");
  for (const s of a.sites || []) {
    const chip = document.createElement("span");
    chip.textContent = s;
    sites.append(chip);
  }
  const copy = async () => {
    const { code } = await totp(a);
    await navigator.clipboard.writeText(code);
    toast("Code copied");
  };
  el.querySelector(".code").addEventListener("click", copy);
  el.querySelector(".copy").addEventListener("click", copy);
  el.querySelector(".edit").addEventListener("click", () => openEdit(a));
  el.querySelector(".fill").addEventListener("click", () => fillInPage(a));
  return el;
}

async function tick() {
  for (const el of document.querySelectorAll("#list .card")) {
    const a = accounts.find((x) => x.id === el.dataset.id);
    const codeEl = el.querySelector(".code");
    try {
      const { code, remaining, period } = await totp(a);
      codeEl.textContent = formatCode(code);
      codeEl.classList.remove("error-code");
      el.querySelector(".timer-fill").style.width = (remaining / period) * 100 + "%";
      el.querySelector(".timer").classList.toggle("low", remaining <= 5);
    } catch {
      codeEl.textContent = "Invalid secret";
      codeEl.classList.add("error-code");
    }
  }
}

$("#search").addEventListener("input", render);

async function fillInPage(a) {
  const { code } = await totp(a);
  let filled = false;
  if (currentTabId != null) {
    try { filled = await chrome.tabs.sendMessage(currentTabId, { type: "fillCode", code }); } catch { /* no field */ }
  }
  if (filled) {
    window.close();
  } else {
    await navigator.clipboard.writeText(code);
    toast("No code field found — copied instead");
  }
}

// ---------- add / edit ----------

function openEdit(a) {
  editingId = a?.id ?? null;
  $("#edit-title").textContent = a ? "Edit account" : "Add account";
  $("#delete-btn").hidden = !a;
  $("#edit-error").textContent = "";
  $("#f-uri").value = "";
  $("#f-name").value = a?.name ?? "";
  $("#f-sites").value = a ? (a.sites || []).join(", ") : currentHost.replace(/^www\./, "");
  $("#f-username").value = a?.username ?? "";
  $("#f-email").value = a?.email ?? "";
  $("#f-secret").value = a?.secret ?? "";
  $("#f-digits").value = String(a?.digits ?? 6);
  $("#f-period").value = String(a?.period ?? 30);
  $("#f-alg").value = normalizeAlgorithm(a?.algorithm);
  show("edit");
  updatePreview();
  $(a ? "#f-name" : "#f-uri").focus();
}

$("#add-btn").addEventListener("click", () => openEdit(null));
$("#empty-add").addEventListener("click", () => openEdit(null));
$("#edit-back").addEventListener("click", openList);
$("#cancel-btn").addEventListener("click", openList);

$("#f-uri").addEventListener("input", () => {
  const v = $("#f-uri").value.trim();
  if (!v) return ($("#edit-error").textContent = "");
  try {
    const p = parseOtpauth(v);
    if (p.name) $("#f-name").value = p.name;
    if (p.username) $("#f-username").value = p.username;
    if (p.email) $("#f-email").value = p.email;
    $("#f-secret").value = p.secret;
    $("#f-digits").value = String(p.digits);
    $("#f-period").value = String(p.period);
    $("#f-alg").value = p.algorithm;
    $("#edit-error").textContent = "";
    updatePreview();
  } catch (ex) {
    $("#edit-error").textContent = ex.message;
  }
});

function formAccount() {
  return {
    secret: cleanSecret($("#f-secret").value),
    digits: Number($("#f-digits").value),
    period: Number($("#f-period").value) || 30,
    algorithm: $("#f-alg").value,
  };
}

let previewTimer;
async function updatePreview() {
  clearTimeout(previewTimer);
  const out = $("#f-preview");
  const acc = formAccount();
  if (!acc.secret) return (out.textContent = "");
  try {
    const { code, remaining } = await totp(acc);
    out.innerHTML = "";
    out.append("Current code: ");
    const b = document.createElement("b");
    b.textContent = formatCode(code);
    out.append(b, ` (${remaining}s) — check it matches your authenticator app or the site's setup page.`);
    previewTimer = setTimeout(updatePreview, 1000);
  } catch (ex) {
    out.textContent = ex.message;
  }
}
["#f-secret", "#f-digits", "#f-period", "#f-alg"].forEach((s) => $(s).addEventListener("input", updatePreview));

$("#edit-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#edit-error");
  err.textContent = "";
  const base = formAccount();
  try {
    if (base32Decode(base.secret).length < 5) throw new Error("That secret key looks too short.");
  } catch (ex) { return (err.textContent = ex.message); }

  const rawSites = $("#f-sites").value.split(/[,\s]+/).filter(Boolean);
  const sites = [];
  for (const s of rawSites) {
    const n = normalizeSite(s);
    if (!n) return (err.textContent = `"${s}" isn't a valid website.`);
    if (!sites.includes(n)) sites.push(n);
  }

  const account = {
    id: editingId || crypto.randomUUID(),
    name: $("#f-name").value.trim(),
    sites,
    username: $("#f-username").value.trim(),
    email: $("#f-email").value.trim(),
    ...base,
  };
  const next = editingId ? accounts.map((a) => (a.id === editingId ? { ...a, ...account } : a)) : [...accounts, account];
  await busy(e.submitter, async () => {
    try {
      await call("saveAccounts", { accounts: next });
      clearTimeout(previewTimer);
      await openList();
      toast(editingId ? "Saved" : "Account added");
    } catch (ex) { err.textContent = ex.message; }
  });
});

$("#delete-btn").addEventListener("click", async () => {
  const a = accounts.find((x) => x.id === editingId);
  if (!a) return;
  const ok = confirm(`Delete "${a.name}"?\n\nMake sure 2FA is turned off on that site or you have another way to get codes, or you could be locked out.`);
  if (!ok) return;
  await call("saveAccounts", { accounts: accounts.filter((x) => x.id !== editingId) });
  clearTimeout(previewTimer);
  await openList();
  toast("Deleted");
});

// ---------- settings ----------

$("#settings-btn").addEventListener("click", async () => {
  const s = await call("getSettings");
  $("#s-autofill").checked = s.autoFill;
  $("#s-badge").checked = s.showBadge;
  $("#s-autolock").value = String(s.autoLockMinutes);
  $("#s-autobio").checked = s.autoBio;
  $("#pw-error").textContent = "";
  $("#backup-error").textContent = "";
  await renderBio();
  show("settings");
});
$("#settings-back").addEventListener("click", openList);

for (const id of ["#s-autofill", "#s-badge", "#s-autolock", "#s-autobio"]) {
  $(id).addEventListener("change", async () => {
    await call("saveSettings", {
      settings: {
        autoFill: $("#s-autofill").checked,
        showBadge: $("#s-badge").checked,
        autoLockMinutes: Number($("#s-autolock").value),
        autoBio: $("#s-autobio").checked,
      },
    });
    toast("Settings saved");
  });
}

async function renderBio() {
  const { enabled, mode } = await call("bioStatus");
  $("#bio-toggle").textContent = enabled ? "Turn off fingerprint unlock" : "Turn on fingerprint unlock";
  $("#bio-toggle").dataset.enabled = enabled ? "1" : "";
  $("#s-autobio-row").hidden = !enabled;
  $("#bio-status").textContent = !enabled
    ? "Unlock with your fingerprint, face or Windows Hello PIN instead of typing your master password."
    : mode === "prf"
      ? "On. Your vault key is protected by your fingerprint / Windows Hello."
      : "On (limited mode). This device can't encrypt the vault with your fingerprint, so it only guards the unlock button.";
}

$("#bio-toggle").addEventListener("click", async () => {
  if ($("#bio-toggle").dataset.enabled) {
    await call("clearBio");
    await renderBio();
    toast("Fingerprint unlock turned off");
  } else {
    await call("openBioWindow", { mode: "enroll" });
    window.close();
  }
});

$("#pw-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#pw-error");
  err.textContent = "";
  await busy(e.submitter, async () => {
    try {
      await call("changePassword", { current: $("#pw-current").value, next: $("#pw-next").value });
      e.target.reset();
      const hadBio = !!$("#bio-toggle").dataset.enabled;
      await renderBio();
      toast(hadBio ? "Password changed. Turn fingerprint unlock on again." : "Password changed");
    } catch (ex) { err.textContent = ex.message; }
  });
});

$("#export-btn").addEventListener("click", async () => {
  const vault = await call("exportVault");
  const blob = new Blob([JSON.stringify(vault, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `2fa-autofill-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
});

$("#import-btn").addEventListener("click", () => $("#import-file").click());
$("#import-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  const err = $("#backup-error");
  err.textContent = "";
  try {
    const vault = JSON.parse(await file.text());
    const ok = confirm("Replace your current vault with this backup?\n\nYour current accounts will be overwritten. " +
      "You'll unlock it with the password the backup was made with.");
    if (!ok) return;
    await call("importVault", { vault });
    accounts = [];
    await showUnlock();
  } catch (ex) {
    err.textContent = ex instanceof SyntaxError ? "That file isn't valid JSON." : ex.message;
  }
});

document.querySelectorAll(".open-import").forEach((b) =>
  b.addEventListener("click", () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("import.html") });
    window.close();
  })
);

init().catch((ex) => {
  document.body.textContent = "Error: " + ex.message;
});
