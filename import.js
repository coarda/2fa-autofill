import { parseMigration, parseOtpauth, guessSites, normalizeSite, totp, cleanSecret } from "./lib.js";

const $ = (s) => document.querySelector(s);

let existing = [];          // accounts already in the vault
const pending = [];         // accounts read from QR codes, waiting for review
const seenCodes = new Set(); // raw QR texts already processed
const batches = new Map();  // batch id -> { size, got: Set(index) }
let codeTimer = null;

async function call(type, data = {}) {
  const res = await chrome.runtime.sendMessage({ type, ...data });
  if (!res) throw new Error("The extension did not respond. Reload this page.");
  if (!res.ok) throw new Error(res.error);
  return res.result;
}

// ---------- start / unlock ----------

async function init() {
  const { initialized, unlocked } = await call("status");
  $("#no-vault").hidden = initialized;
  $("#locked").hidden = !initialized || unlocked;
  if (initialized && unlocked) await start();
  else if (initialized) $("#unlock-pw").focus();
}

async function start() {
  existing = await call("getAccounts");
  $("#locked").hidden = true;
  $("#main").hidden = false;
}

$("#unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#unlock-error").textContent = "";
  try {
    await call("unlock", { password: $("#unlock-pw").value });
    $("#unlock-pw").value = "";
    await start();
  } catch (ex) {
    $("#unlock-error").textContent = ex.message;
  }
});

// ---------- turning QR text into accounts ----------

const secretKey = (a) => cleanSecret(a.secret);

function addText(text) {
  text = String(text || "").trim();
  if (!text || seenCodes.has(text)) return false;
  let accounts;
  let skipped = 0;
  if (/^otpauth-migration:/i.test(text)) {
    const r = parseMigration(text);
    accounts = r.accounts;
    skipped = r.skipped;
    const b = batches.get(r.batch.id) || { size: r.batch.size, got: new Set() };
    b.got.add(r.batch.index);
    batches.set(r.batch.id, b);
  } else if (/^otpauth:/i.test(text)) {
    accounts = [parseOtpauth(text)];
  } else {
    throw new Error("That QR code isn't a Google Authenticator export.");
  }
  seenCodes.add(text);
  for (const a of accounts) {
    if (pending.some((p) => secretKey(p) === secretKey(a))) continue;
    pending.push({
      ...a,
      sites: guessSites(a.name),
      include: !existing.some((x) => secretKey(x) === secretKey(a)),
      duplicate: existing.some((x) => secretKey(x) === secretKey(a)),
    });
  }
  if (skipped) {
    $("#read-error").textContent =
      `${skipped} counter-based (HOTP) account${skipped > 1 ? "s were" : " was"} skipped. Only time-based codes are supported.`;
  }
  renderBatches();
  renderRows();
  return true;
}

function renderBatches() {
  const el = $("#batches");
  el.textContent = "";
  for (const b of batches.values()) {
    for (let i = 0; i < b.size; i++) {
      const chip = document.createElement("span");
      const got = b.got.has(i);
      chip.className = "chip " + (got ? "ok" : "missing");
      chip.textContent = `QR code ${i + 1} of ${b.size}: ${got ? "read ✓" : "not read yet"}`;
      el.append(chip);
    }
  }
}

function renderRows() {
  const body = $("#rows");
  body.textContent = "";
  $("#review").hidden = pending.length === 0;
  for (const a of pending) {
    const tr = document.createElement("tr");
    tr.classList.toggle("dup", a.duplicate);

    const check = document.createElement("input");
    check.type = "checkbox";
    check.checked = a.include;
    check.onchange = () => { a.include = check.checked; updateSummary(); };

    const name = document.createElement("input");
    name.value = a.name;
    name.oninput = () => (a.name = name.value);

    const who = document.createElement("input");
    who.value = a.email || a.username;
    who.placeholder = "username or email";
    who.oninput = () => {
      const v = who.value.trim();
      a.email = v.includes("@") ? v : "";
      a.username = v.includes("@") ? "" : v;
    };

    const sites = document.createElement("input");
    sites.value = a.sites.join(", ");
    sites.placeholder = "e.g. example.com";
    sites.oninput = () => (a.sitesText = sites.value);
    a.sitesText = sites.value;

    const code = document.createElement("td");
    code.className = "code";
    code.dataset.secret = a.secret;

    const cells = [check, name, who, sites].map((el) => {
      const td = document.createElement("td");
      td.append(el);
      return td;
    });
    if (a.duplicate) {
      const tag = document.createElement("span");
      tag.className = "tag";
      tag.textContent = "Already in your vault";
      cells[1].append(tag);
    }
    tr.append(...cells, code);
    tr._account = a;
    body.append(tr);
  }
  updateSummary();
  updateCodes();
  clearInterval(codeTimer);
  codeTimer = setInterval(updateCodes, 1000);
}

async function updateCodes() {
  for (const tr of $("#rows").children) {
    try {
      const { code, remaining } = await totp(tr._account);
      tr.lastChild.textContent = `${code} (${remaining}s)`;
    } catch {
      tr.lastChild.textContent = "invalid";
    }
  }
}

function updateSummary() {
  const n = pending.filter((a) => a.include).length;
  $("#summary").textContent = `${n} of ${pending.length} selected`;
  $("#import-btn").textContent = `Import ${n} account${n === 1 ? "" : "s"}`;
  $("#import-btn").disabled = n === 0;
}

function report(ex) {
  $("#read-error").textContent = ex?.message || String(ex);
}

// ---------- QR decoding ----------

let detector = null;
async function getDetector() {
  if (detector !== null) return detector;
  detector = false;
  try {
    if ("BarcodeDetector" in window && (await BarcodeDetector.getSupportedFormats()).includes("qr_code")) {
      detector = new BarcodeDetector({ formats: ["qr_code"] });
    }
  } catch { /* not available */ }
  return detector;
}

const canvas = document.createElement("canvas");
const ctx = canvas.getContext("2d", { willReadFrequently: true });

// Returns the text of every QR code found in the image/video frame.
async function decode(source, width, height) {
  const det = await getDetector();
  if (det) {
    const found = await det.detect(source);
    if (found.length) return found.map((f) => f.rawValue);
  }
  if (typeof window.jsQR !== "function") {
    throw new Error("The QR reader is missing (vendor/jsQR.js). Use the Paste link option instead.");
  }
  const scale = Math.min(1, 1400 / Math.max(width, height));
  canvas.width = Math.round(width * scale);
  canvas.height = Math.round(height * scale);
  ctx.drawImage(source, 0, 0, canvas.width, canvas.height);
  const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const hit = window.jsQR(img.data, img.width, img.height, { inversionAttempts: "attemptBoth" });
  return hit ? [hit.data] : [];
}

// ---------- webcam ----------

let stream = null;
let scanning = false;

$("#cam-btn").addEventListener("click", async () => {
  if (stream) return stopCamera();
  $("#read-error").textContent = "";
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 1280 }, height: { ideal: 720 } } });
  } catch (ex) {
    stream = null;
    report(ex.name === "NotAllowedError"
      ? "Camera access was blocked. Allow the camera for this page (icon in the address bar), then try again."
      : ex.name === "NotFoundError" ? "No webcam was found. Use a photo or paste a link instead." : ex);
    return;
  }
  const video = $("#video");
  video.srcObject = stream;
  await video.play();
  $("#video-wrap").hidden = false;
  $("#cam-btn").textContent = "Stop webcam";
  $("#cam-status").textContent = "Hold the phone's QR code inside the frame, about 20–30 cm from the camera.";
  scanning = true;
  scanLoop();
});

function stopCamera() {
  scanning = false;
  stream?.getTracks().forEach((t) => t.stop());
  stream = null;
  $("#video-wrap").hidden = true;
  $("#cam-btn").textContent = "Start webcam";
}

async function scanLoop() {
  const video = $("#video");
  while (scanning) {
    if (video.readyState >= 2) {
      try {
        const texts = await decode(video, video.videoWidth, video.videoHeight);
        for (const t of texts) {
          if (addText(t)) {
            $("#video-wrap").classList.add("hit");
            setTimeout(() => $("#video-wrap").classList.remove("hit"), 700);
            const missing = [...batches.values()].some((b) => b.got.size < b.size);
            $("#cam-status").textContent = missing
              ? "Got it! Now show the next QR code (tap Next on the phone)."
              : `Got it! ${pending.length} account(s) read. Check them below.`;
            if (!missing) {
              stopCamera();
              $("#review").scrollIntoView({ behavior: "smooth" });
            }
          }
        }
      } catch (ex) {
        report(ex);
        if (/QR reader is missing/.test(ex.message)) stopCamera();
      }
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

// ---------- images ----------

async function readFiles(files) {
  $("#read-error").textContent = "";
  let found = 0;
  for (const file of files) {
    if (!file.type.startsWith("image/")) continue;
    try {
      const bmp = await createImageBitmap(file);
      const texts = await decode(bmp, bmp.width, bmp.height);
      bmp.close?.();
      if (!texts.length) {
        report(`No QR code found in ${file.name}. Make sure the whole code is sharp and fills a good part of the picture.`);
      }
      for (const t of texts) if (addText(t)) found++;
    } catch (ex) {
      report(ex);
    }
  }
  $("#file-status").textContent = found ? `Read ${found} QR code(s).` : "";
}

$("#file").addEventListener("change", (e) => readFiles([...e.target.files]).then(() => (e.target.value = "")));
const drop = $("#drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  readFiles([...e.dataTransfer.files]);
});
document.addEventListener("paste", (e) => {
  const imgs = [...(e.clipboardData?.files || [])].filter((f) => f.type.startsWith("image/"));
  if (imgs.length) readFiles(imgs);
});

// ---------- pasted links ----------

$("#paste-btn").addEventListener("click", () => {
  $("#read-error").textContent = "";
  const lines = $("#paste").value.split(/\s+/).filter(Boolean);
  let ok = 0;
  for (const line of lines) {
    try { if (addText(line)) ok++; } catch (ex) { report(ex); }
  }
  if (ok) $("#paste").value = "";
});

// ---------- import ----------

$("#import-btn").addEventListener("click", async () => {
  const err = $("#import-error");
  err.textContent = "";
  const chosen = pending.filter((a) => a.include);
  const toAdd = [];
  for (const a of chosen) {
    const sites = [];
    for (const s of (a.sitesText || "").split(/[,\s]+/).filter(Boolean)) {
      const n = normalizeSite(s);
      if (!n) return (err.textContent = `"${s}" (for ${a.name}) isn't a valid website.`);
      if (!sites.includes(n)) sites.push(n);
    }
    toAdd.push({
      id: crypto.randomUUID(),
      name: a.name.trim() || "Account",
      sites,
      username: a.username || "",
      email: a.email || "",
      secret: a.secret,
      digits: a.digits,
      period: a.period,
      algorithm: a.algorithm,
    });
  }
  const btn = $("#import-btn");
  btn.disabled = true;
  try {
    existing = await call("getAccounts"); // re-read in case the popup changed something
    const fresh = toAdd.filter((a) => !existing.some((x) => secretKey(x) === secretKey(a)));
    await call("saveAccounts", { accounts: [...existing, ...fresh] });
    clearInterval(codeTimer);
    stopCamera();
    $("#review").hidden = true;
    $("#done").hidden = false;
    $("#done-text").textContent = `${fresh.length} account${fresh.length === 1 ? " was" : "s were"} added to your vault.`;
    $("#done").scrollIntoView({ behavior: "smooth" });
  } catch (ex) {
    err.textContent = ex.message;
    btn.disabled = false;
  }
});

init().catch((ex) => {
  document.body.textContent = "Error: " + ex.message;
});
