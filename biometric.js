// Runs the Windows Hello / fingerprint prompt (WebAuthn) in its own small window.
// The browser-action popup can't do this: it closes as soon as the system prompt takes focus.
import { randomBytes, toB64, fromB64 } from "./lib.js";

const $ = (s) => document.querySelector(s);
const mode = new URLSearchParams(location.search).get("mode") === "enroll" ? "enroll" : "unlock";

async function call(type, data = {}) {
  const res = await chrome.runtime.sendMessage({ type, ...data });
  if (!res) throw new Error("The extension did not respond.");
  if (!res.ok) throw new Error(res.error);
  return res.result;
}

function say(title, message, { ok = false, retry = false } = {}) {
  $("#title").textContent = title;
  $("#message").textContent = message;
  $("#box").classList.toggle("ok", ok);
  $("#retry").hidden = !retry;
}

function prfOf(credential) {
  const out = credential.getClientExtensionResults?.().prf?.results?.first;
  return out ? new Uint8Array(out) : null;
}

function friendly(ex) {
  if (ex?.name === "NotAllowedError") return "The fingerprint check was cancelled or timed out.";
  if (ex?.name === "InvalidStateError") return "This device already has a passkey for 2FA Autofill. Try again.";
  if (ex?.name === "SecurityError") return "Chrome blocked the fingerprint prompt for this extension.";
  return ex?.message || String(ex);
}

async function assertion(credentialId, prfSalt) {
  return navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials: [{ type: "public-key", id: fromB64(credentialId) }],
      userVerification: "required",
      timeout: 60000,
      extensions: { prf: { eval: { first: fromB64(prfSalt) } } },
    },
  });
}

// ---------- turning it on ----------

let pendingWeak = null;

async function enroll() {
  say("Turn on fingerprint unlock", "Confirm with your fingerprint, face or Windows Hello PIN…");
  if (!window.PublicKeyCredential || !(await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())) {
    return say("Not available", "This computer has no fingerprint reader or Windows Hello set up. Set up Windows Hello in Windows Settings → Accounts → Sign-in options, then try again.", { retry: true });
  }
  const prfSalt = randomBytes(32);
  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { name: "2FA Autofill" },
      user: { id: randomBytes(16), name: "2FA Autofill vault", displayName: "2FA Autofill vault" },
      challenge: randomBytes(32),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "discouraged" },
      timeout: 60000,
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
  const credentialId = toB64(new Uint8Array(credential.rawId));
  const ext = credential.getClientExtensionResults?.().prf;
  let prf = prfOf(credential);
  if (!prf && ext?.enabled) {
    // Some authenticators only return the secret on sign-in, not on creation.
    say("One more time", "Confirm once more to finish setting up…");
    prf = prfOf(await assertion(credentialId, toB64(prfSalt)));
  }
  if (prf) {
    await call("bioEnroll", { credentialId, prfSalt: toB64(prfSalt), prfOutput: toB64(prf) });
    return done("Fingerprint unlock is on", "Next time the vault is locked, click “Unlock with fingerprint”.");
  }
  // No PRF support: offer the weaker mode and explain the trade-off.
  pendingWeak = { credentialId, prfSalt: toB64(prfSalt) };
  say("Limited support on this device", "Your fingerprint/Windows Hello works, but it can't encrypt the vault on this device.");
  $("#warn").hidden = false;
  $("#warn").textContent =
    "If you turn it on anyway, the key that opens your vault is saved on this computer and the fingerprint " +
    "only guards the unlock button. Someone with access to your Windows account files could open the vault " +
    "without your fingerprint or master password. Your master password keeps working either way.";
  $("#weak-yes").hidden = false;
}

$("#weak-yes").addEventListener("click", async () => {
  try {
    await call("bioEnroll", { ...pendingWeak, prfOutput: null });
    $("#warn").hidden = true;
    $("#weak-yes").hidden = true;
    done("Fingerprint unlock is on", "Next time the vault is locked, click “Unlock with fingerprint”.");
  } catch (ex) {
    say("Couldn't turn it on", friendly(ex), { retry: true });
  }
});

// ---------- unlocking ----------

async function unlock() {
  say("Unlock with fingerprint", "Confirm with your fingerprint, face or Windows Hello PIN…");
  const { initialized, unlocked } = await call("status");
  if (!initialized) return say("No vault", "Create your vault from the extension icon first.");
  if (unlocked) return done("Already unlocked", "");
  const { mode: bioMode, credentialId, prfSalt } = await call("bioParams");
  const a = await assertion(credentialId, prfSalt);
  const prf = prfOf(a);
  if (bioMode === "prf" && !prf) throw new Error("Your device didn't return the unlock key. Use your master password.");
  await call("bioUnlock", { prfOutput: prf ? toB64(prf) : null });
  done("Unlocked", "You can close this window.");
}

function done(title, message) {
  say(title, message, { ok: true });
  setTimeout(() => window.close(), 900);
}

async function run() {
  $("#retry").hidden = true;
  try {
    await (mode === "enroll" ? enroll() : unlock());
  } catch (ex) {
    say(mode === "enroll" ? "Couldn't turn it on" : "Couldn't unlock", friendly(ex), { retry: true });
  }
}

// Opens the regular popup showing the password form (skipping the automatic fingerprint prompt once).
$("#use-password").hidden = mode !== "unlock";
$("#use-password").addEventListener("click", async () => {
  await call("bioSkipOnce");
  try {
    const win = await chrome.windows.getLastFocused({ windowTypes: ["normal"] });
    await chrome.action.openPopup({ windowId: win.id });
  } catch {
    say("Use your master password", "Click the 2FA Autofill icon in the toolbar and enter your master password.");
    return;
  }
  window.close();
});

$("#retry").addEventListener("click", run);
$("#close").addEventListener("click", () => window.close());
run();
