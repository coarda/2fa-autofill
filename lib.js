// Shared helpers: Base32, TOTP (RFC 6238), vault encryption, site matching.

const encoder = new TextEncoder();
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function cleanSecret(input) {
  return String(input || "").toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
}

export function base32Decode(input) {
  const clean = cleanSecret(input);
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = BASE32.indexOf(ch);
    if (idx === -1) throw new Error("Secret key must be Base32 (letters A–Z and digits 2–7).");
    value = ((value << 5) | idx) & 0xfff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function normalizeAlgorithm(alg) {
  const a = String(alg || "SHA1").toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (a === "SHA256") return "SHA-256";
  if (a === "SHA512") return "SHA-512";
  return "SHA-1";
}

export async function totp(account, now = Date.now()) {
  const digits = Number(account.digits) || 6;
  const period = Number(account.period) || 30;
  const keyBytes = base32Decode(account.secret);
  if (!keyBytes.length) throw new Error("Secret key is empty.");
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: normalizeAlgorithm(account.algorithm) }, false, ["sign"]
  );
  const seconds = Math.floor(now / 1000);
  const counter = Math.floor(seconds / period);
  const msg = new DataView(new ArrayBuffer(8));
  msg.setUint32(0, Math.floor(counter / 2 ** 32));
  msg.setUint32(4, counter >>> 0);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg.buffer));
  const off = sig[sig.length - 1] & 0x0f;
  const bin = ((sig[off] & 0x7f) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3];
  const code = String(bin % 10 ** digits).padStart(digits, "0");
  return { code, remaining: period - (seconds % period), period };
}

// ---- encryption (PBKDF2-SHA256 -> AES-256-GCM) ----

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function toB64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromB64(str) {
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}

export async function deriveKey(password, salt, iterations) {
  const base = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function encryptJSON(key, obj) {
  const iv = randomBytes(12);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(obj)));
  return { iv: toB64(iv), data: toB64(new Uint8Array(data)) };
}

export async function decryptJSON(key, { iv, data }) {
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, key, fromB64(data));
  return JSON.parse(new TextDecoder().decode(plain));
}

// ---- sites ----

export function normalizeSite(input) {
  let s = String(input || "").trim().toLowerCase();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//.test(s)) s = "https://" + s;
  try {
    const host = new URL(s).hostname.replace(/^www\./, "");
    return host || null;
  } catch {
    return null;
  }
}

export function hostMatches(host, site) {
  host = String(host || "").toLowerCase();
  return !!site && (host === site || host.endsWith("." + site));
}

// ---- otpauth:// URIs (what QR codes contain) ----

export function parseOtpauth(uri) {
  const url = new URL(String(uri).trim());
  if (url.protocol !== "otpauth:") throw new Error("Not an otpauth:// link.");
  if (url.host.toLowerCase() !== "totp") throw new Error("Only time-based (TOTP) codes are supported.");
  const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
  const [labelIssuer, labelAccount] = label.includes(":") ? label.split(/:(.*)/s) : ["", label];
  const p = url.searchParams;
  const secret = cleanSecret(p.get("secret"));
  if (!secret) throw new Error("The link has no secret.");
  const issuer = p.get("issuer") || labelIssuer.trim();
  const account = (labelAccount || "").trim();
  return {
    name: issuer || account,
    username: account.includes("@") ? "" : account,
    email: account.includes("@") ? account : "",
    secret,
    digits: Number(p.get("digits")) || 6,
    period: Number(p.get("period")) || 30,
    algorithm: normalizeAlgorithm(p.get("algorithm")),
  };
}

// ---- Google Authenticator export (otpauth-migration://offline?data=...) ----

export function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = ((value << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

function readVarint(buf, pos) {
  let result = 0;
  let mul = 1;
  let b;
  do {
    if (pos >= buf.length) throw new Error("The export data is incomplete.");
    b = buf[pos++];
    result += (b & 0x7f) * mul;
    mul *= 128;
  } while (b & 0x80);
  return [result, pos];
}

// Minimal protobuf reader: yields { field, value } for varints and { field, bytes } for length-delimited.
function* protoFields(buf) {
  let pos = 0;
  while (pos < buf.length) {
    const [tag, p1] = readVarint(buf, pos);
    const field = Math.floor(tag / 8);
    const wire = tag % 8;
    pos = p1;
    if (wire === 0) {
      const [value, p2] = readVarint(buf, pos);
      pos = p2;
      yield { field, value };
    } else if (wire === 2) {
      const [len, p2] = readVarint(buf, pos);
      pos = p2 + len;
      if (pos > buf.length) throw new Error("The export data is incomplete.");
      yield { field, bytes: buf.subarray(p2, pos) };
    } else if (wire === 1) {
      pos += 8;
    } else if (wire === 5) {
      pos += 4;
    } else {
      throw new Error("The export data is not in a format this extension understands.");
    }
  }
}

function splitAccount(name) {
  return name.includes("@") ? { username: "", email: name } : { username: name, email: "" };
}

function parseOtpParameters(bytes) {
  const dec = new TextDecoder();
  const p = { secret: null, name: "", issuer: "", algorithm: 1, digits: 1, type: 2 };
  for (const f of protoFields(bytes)) {
    if (f.field === 1) p.secret = f.bytes;
    else if (f.field === 2) p.name = dec.decode(f.bytes);
    else if (f.field === 3) p.issuer = dec.decode(f.bytes);
    else if (f.field === 4) p.algorithm = f.value;
    else if (f.field === 5) p.digits = f.value;
    else if (f.field === 6) p.type = f.value;
  }
  // type 1 = HOTP (counter-based) and algorithm 4 = MD5 aren't supported.
  if (!p.secret?.length || p.type === 1 || p.algorithm === 4) return null;
  let issuer = p.issuer.trim();
  let account = p.name.trim();
  const colon = account.indexOf(":");
  if (colon > -1) {
    if (!issuer) issuer = account.slice(0, colon).trim();
    account = account.slice(colon + 1).trim();
  }
  return {
    name: issuer || account || "Account",
    ...splitAccount(account),
    secret: base32Encode(p.secret),
    digits: p.digits === 2 ? 8 : 6,
    period: 30,
    algorithm: { 2: "SHA-256", 3: "SHA-512" }[p.algorithm] || "SHA-1",
  };
}

export function parseMigration(uri) {
  const m = String(uri).trim().match(/^otpauth-migration:\/\/offline\?(?:.*&)?data=([^&]+)/i);
  if (!m) throw new Error("Not a Google Authenticator export code.");
  // URLSearchParams would turn '+' into spaces, so decode the raw value ourselves.
  let b64 = decodeURIComponent(m[1]).replace(/ /g, "+").replace(/-/g, "+").replace(/_/g, "/");
  b64 += "=".repeat((4 - (b64.length % 4)) % 4);
  let buf;
  try { buf = fromB64(b64); } catch { throw new Error("The export code is damaged. Try scanning it again."); }
  const accounts = [];
  let skipped = 0;
  const batch = { size: 1, index: 0, id: 0 };
  for (const f of protoFields(buf)) {
    if (f.field === 1 && f.bytes) {
      const acc = parseOtpParameters(f.bytes);
      acc ? accounts.push(acc) : skipped++;
    } else if (f.field === 3) batch.size = f.value || 1;
    else if (f.field === 4) batch.index = f.value;
    else if (f.field === 5) batch.id = f.value;
  }
  return { accounts, skipped, batch };
}

// Well-known issuers -> login domains. Unknown issuers are left blank on purpose: guessing a
// domain could send codes to a site you don't use.
const KNOWN_SITES = {
  google: ["google.com"], gmail: ["google.com"], github: ["github.com"], gitlab: ["gitlab.com"],
  microsoft: ["microsoft.com", "live.com", "microsoftonline.com"], outlook: ["live.com"],
  amazon: ["amazon.com"], aws: ["aws.amazon.com", "signin.aws.amazon.com"], amazonwebservices: ["aws.amazon.com"],
  facebook: ["facebook.com"], meta: ["facebook.com"], instagram: ["instagram.com"],
  twitter: ["x.com", "twitter.com"], x: ["x.com", "twitter.com"], discord: ["discord.com"],
  dropbox: ["dropbox.com"], reddit: ["reddit.com"], epicgames: ["epicgames.com"], binance: ["binance.com"],
  coinbase: ["coinbase.com"], paypal: ["paypal.com"], apple: ["apple.com"], bitbucket: ["bitbucket.org"],
  atlassian: ["atlassian.com"], slack: ["slack.com"], linkedin: ["linkedin.com"], twitch: ["twitch.tv"],
  cloudflare: ["cloudflare.com"], digitalocean: ["digitalocean.com"], heroku: ["heroku.com"], npm: ["npmjs.com"],
  nvidia: ["nvidia.com"], ubisoft: ["ubisoft.com"], ea: ["ea.com"], proton: ["proton.me"], protonmail: ["proton.me"],
  tiktok: ["tiktok.com"], snapchat: ["snapchat.com"], yahoo: ["yahoo.com"], zoom: ["zoom.us"], adobe: ["adobe.com"],
  openai: ["openai.com", "chatgpt.com"], anthropic: ["anthropic.com", "claude.ai"], kraken: ["kraken.com"],
  steam: ["steampowered.com", "steamcommunity.com"], riotgames: ["riotgames.com"], roblox: ["roblox.com"],
  battlenet: ["battle.net"], blizzard: ["battle.net"], namecheap: ["namecheap.com"], godaddy: ["godaddy.com"],
  shopify: ["shopify.com"], stripe: ["stripe.com"], vercel: ["vercel.com"], netlify: ["netlify.com"],
  bitwarden: ["bitwarden.com"], "1password": ["1password.com"], lastpass: ["lastpass.com"], nintendo: ["nintendo.com"],
  playstation: ["playstation.com", "sony.com"], sony: ["sony.com"], wordpress: ["wordpress.com"], ovh: ["ovh.com"],
};

export function guessSites(issuer) {
  const key = String(issuer || "").toLowerCase().replace(/\.(com|net|org|io)$/, "").replace(/[^a-z0-9]/g, "");
  return KNOWN_SITES[key] ? [...KNOWN_SITES[key]] : [];
}
