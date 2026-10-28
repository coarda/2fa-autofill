import { deriveKey, encryptJSON, decryptJSON, totp, randomBytes, toB64, fromB64, hostMatches, keyFromPrf } from "./lib.js";

const ITERATIONS = 600000;
const DEFAULT_SETTINGS = { autoLockMinutes: 15, autoFill: true, showBadge: true, autoBio: true };

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

// ---- fingerprint / Windows Hello unlock ----
// "prf" mode: the vault key is encrypted with a secret that only the passkey can produce after a
// fingerprint/face/PIN check, so the stored copy is useless without it.
// "device" mode (for devices without PRF support): the wrapping key is stored next to it and the
// fingerprint check only gates the unlock in the UI. Weaker, and the user is told so before enabling.

async function getBio() {
  const { bio } = await chrome.storage.local.get("bio");
  return bio || null;
}

async function clearBio() {
  await chrome.storage.local.remove("bio");
}

async function openBioWindow(mode) {
  await chrome.windows.create({
    url: chrome.runtime.getURL(`biometric.html?mode=${mode}`),
    type: "popup",
    width: 420,
    height: 440,
    focused: true,
  });
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
    await clearBio(); // it wrapped the old key
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
    await clearBio();
    await chrome.storage.local.set({ vault, siteIndex: [] });
  },

  async resetVault() {
    await lock();
    await chrome.storage.local.remove(["vault", "siteIndex", "bio"]);
  },

  async bioStatus() {
    const bio = await getBio();
    return { enabled: !!bio, mode: bio?.mode ?? null };
  },

  // What the fingerprint page needs to ask for the passkey (no secrets).
  async bioParams() {
    const bio = await getBio();
    if (!bio) throw new Error("Fingerprint unlock is not turned on.");
    return { mode: bio.mode, credentialId: bio.credentialId, prfSalt: bio.prfSalt };
  },

  async bioEnroll({ credentialId, prfSalt, prfOutput }) {
    const key = await requireKey();
    const jwk = await crypto.subtle.exportKey("jwk", key);
    let wrapKey;
    let deviceKey = null;
    if (prfOutput) {
      wrapKey = await keyFromPrf(fromB64(prfOutput));
    } else {
      wrapKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
      deviceKey = await crypto.subtle.exportKey("jwk", wrapKey);
    }
    const sealed = await encryptJSON(wrapKey, jwk);
    await chrome.storage.local.set({
      bio: { mode: prfOutput ? "prf" : "device", credentialId, prfSalt, deviceKey, ...sealed },
    });
  },

  async bioUnlock({ prfOutput }) {
    const bio = await getBio();
    if (!bio) throw new Error("Fingerprint unlock is not turned on.");
    const wrapKey = bio.mode === "prf"
      ? await keyFromPrf(prfOutput ? fromB64(prfOutput) : null)
      : await crypto.subtle.importKey("jwk", bio.deviceKey, { name: "AES-GCM" }, false, ["decrypt"]);
    let key;
    try {
      const jwk = await decryptJSON(wrapKey, bio);
      key = await crypto.subtle.importKey("jwk", jwk, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
    } catch {
      throw new Error("Fingerprint unlock failed. Unlock with your master password instead.");
    }
    let accounts;
    try {
      accounts = await readAccounts(key);
    } catch {
      await clearBio();
      throw new Error("Fingerprint unlock is out of date. Unlock with your master password, then turn it on again in Settings.");
    }
    await chrome.storage.local.set({ siteIndex: buildSiteIndex(accounts) });
    await unlockWith(key);
  },

  clearBio,

  // "Use master password instead": the next popup opening shows the password form, not the fingerprint prompt.
  async bioSkipOnce() {
    await chrome.storage.session.set({ bioSkip: true });
  },

  async consumeBioSkip() {
    const { bioSkip } = await chrome.storage.session.get("bioSkip");
    if (bioSkip) await chrome.storage.session.remove("bioSkip");
    return !!bioSkip;
  },

  async openBioWindow({ mode }) {
    await openBioWindow(mode === "enroll" ? "enroll" : "unlock");
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
    // With fingerprint unlock on, go straight to the fingerprint prompt.
    if (await getBio()) {
      await openBioWindow("unlock");
      return true;
    }
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
