import { deriveKey, encryptJSON, decryptJSON, totp, randomBytes, toB64, fromB64, hostMatches } from "./lib.js";

const ITERATIONS = 600000;
const DEFAULT_SETTINGS = { autoLockMinutes: 15, autoFill: true, showBadge: true };

// The vault (encrypted accounts) lives in chrome.storage.local.
// While unlocked, the derived AES key is kept in chrome.storage.session, which is
// memory-only, cleared when the browser closes, and not readable by content scripts.

async function getSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...settings };
}

async function getVault() {
  const { vault } = await chrome.storage.local.get("vault");
  return vault || null;
}

async function loadKey() {
  const { key } = await chrome.storage.session.get("key");
  return key ? crypto.subtle.importKey("jwk", key, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]) : null;
}

async function requireKey() {
  const key = await loadKey();
  if (!key) throw new Error("Vault is locked.");
  return key;
}

async function readAccounts(key) {
  return (await decryptJSON(key, await getVault())).accounts;
}

// Domains are stored unencrypted so the page helper can show "locked" only on sites you configured.
function buildSiteIndex(accounts) {
  return [...new Set(accounts.flatMap((a) => a.sites || []))];
}

async function writeAccounts(key, accounts, vaultBase) {
  const base = vaultBase || (await getVault());
  const sealed = await encryptJSON(key, { accounts });
  await chrome.storage.local.set({ vault: { ...base, ...sealed }, siteIndex: buildSiteIndex(accounts) });
}

async function scheduleAutoLock() {
  const { autoLockMinutes } = await getSettings();
  await chrome.alarms.clear("autolock");
  if (autoLockMinutes > 0) await chrome.alarms.create("autolock", { delayInMinutes: autoLockMinutes });
}

async function unlockWith(key) {
  await chrome.storage.session.set({ key: await crypto.subtle.exportKey("jwk", key) });
  await scheduleAutoLock();
}

async function lock() {
  await chrome.storage.session.remove("key");
  await chrome.alarms.clear("autolock");
}

async function keyFromPassword(password, vault) {
  const key = await deriveKey(password, fromB64(vault.salt), vault.iterations);
  try {
    return { key, accounts: (await decryptJSON(key, vault)).accounts };
  } catch {
    throw new Error("Wrong password.");
  }
}

function checkPassword(password) {
  if (typeof password !== "string" || password.length < 8) throw new Error("Use a password of at least 8 characters.");
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "autolock") lock();
});

// Messages from the popup / settings (trusted extension pages).
const popupHandlers = {
  async status() {
    return { initialized: !!(await getVault()), unlocked: !!(await loadKey()) };
  },

  async setup({ password }) {
    if (await getVault()) throw new Error("A vault already exists.");
    checkPassword(password);
    const salt = randomBytes(16);
    const key = await deriveKey(password, salt, ITERATIONS);
    await writeAccounts(key, [], { v: 1, salt: toB64(salt), iterations: ITERATIONS });
    await unlockWith(key);
  },

  async unlock({ password }) {
    const vault = await getVault();
    if (!vault) throw new Error("No vault yet.");
    const { key, accounts } = await keyFromPassword(password, vault);
    await chrome.storage.local.set({ siteIndex: buildSiteIndex(accounts) });
    await unlockWith(key);
  },

  lock,

  async getAccounts() {
    const key = await requireKey();
    await scheduleAutoLock();
    return readAccounts(key);
  },

  async saveAccounts({ accounts }) {
    if (!Array.isArray(accounts)) throw new Error("Invalid accounts.");
    const key = await requireKey();
    await writeAccounts(key, accounts);
    await scheduleAutoLock();
  },

  getSettings,

  async saveSettings({ settings }) {
    await chrome.storage.local.set({ settings: { ...(await getSettings()), ...settings } });
    if (await loadKey()) await scheduleAutoLock();
  },

  async changePassword({ current, next }) {
    checkPassword(next);
    const { accounts } = await keyFromPassword(current, await getVault());
    const salt = randomBytes(16);
    const key = await deriveKey(next, salt, ITERATIONS);
    await writeAccounts(key, accounts, { v: 1, salt: toB64(salt), iterations: ITERATIONS });
    await unlockWith(key);
  },

  async exportVault() {
    return getVault();
  },

  async importVault({ vault }) {
    const ok = vault && vault.v === 1 && ["salt", "iv", "data"].every((k) => typeof vault[k] === "string") &&
      Number.isInteger(vault.iterations);
    if (!ok) throw new Error("That file is not a 2FA Autofill backup.");
    await lock();
    await chrome.storage.local.set({ vault, siteIndex: [] });
  },

  async resetVault() {
    await lock();
    await chrome.storage.local.remove(["vault", "siteIndex"]);
  },
};

// Messages from content scripts on web pages. They only ever receive codes for the
// page's own domain (taken from the sender, not from the message) — never secrets.
const contentHandlers = {
  async codesForPage(_msg, sender) {
    let host = "";
    try { host = new URL(sender.url).hostname; } catch { /* ignore */ }
    const { siteIndex = [] } = await chrome.storage.local.get("siteIndex");
    if (!host || !siteIndex.some((s) => hostMatches(host, s))) return { relevant: false };
    const settings = await getSettings();
    const key = await loadKey();
    if (!key) return { relevant: true, locked: true, settings };
    const now = Date.now();
    const accounts = (await readAccounts(key)).filter((a) => (a.sites || []).some((s) => hostMatches(host, s)));
    const matches = await Promise.all(accounts.map(async (a) => {
      const { code, remaining } = await totp(a, now);
      return { id: a.id, name: a.name, username: a.username, email: a.email, code, remaining };
    }));
    return { relevant: true, locked: false, matches, settings };
  },

  async openPopup() {
    try {
      await chrome.action.openPopup();
      return true;
    } catch {
      return false;
    }
  },
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;
  // Extension pages opened in a tab (the import page) count as trusted, like the popup.
  const fromWebPage = !!sender.tab && !String(sender.url || "").startsWith(chrome.runtime.getURL(""));
  const handlers = fromWebPage ? contentHandlers : popupHandlers;
  const fn = msg && Object.hasOwn(handlers, msg.type) ? handlers[msg.type] : null;
  if (!fn) return;
  Promise.resolve()
    .then(() => fn(msg, sender))
    .then(
      (result) => sendResponse({ ok: true, result }),
      (err) => sendResponse({ ok: false, error: err?.message || String(err) })
    );
  return true;
});

chrome.commands.onCommand.addListener((command, tab) => {
  if (command === "fill-code" && tab?.id) {
    chrome.tabs.sendMessage(tab.id, { type: "fillBest" }).catch(() => {});
  }
});
