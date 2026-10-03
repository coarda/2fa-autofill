// Detects verification-code fields and fills TOTP codes supplied by the background worker.
(() => {
  if (window.__twofaAutofill) return;
  window.__twofaAutofill = true;

  const STRONG = /one[\s_-]?time|\botp\b|otp[\s_-]?code|2fa|two[\s_-]?factor|two[\s_-]?step|2[\s_-]?step|\bmfa\b|totp|authenticator|verification[\s_-]?code|verify[\s_-]?code|security[\s_-]?code|auth(entication)?[\s_-]?code|passcode|login[\s_-]?code|6[\s_-]?digit/i;
  const WEAK = /code|verif|token|\bpin\b|otp/i;
  const NEGATIVE = /zip|postal|post[\s_-]?code|promo|coupon|discount|voucher|gift|referr|country|captcha|search|invite|area[\s_-]?code|cvc|cvv|card/i;
  const TEXTY = new Set(["text", "tel", "number", "password", ""]);

  const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  const seen = new WeakSet();
  const badges = new Map(); // first input element -> badge
  let autoFilled = false;

  // ---------- messaging ----------

  async function ask(type) {
    try {
      const res = await chrome.runtime.sendMessage({ type });
      return res && res.ok ? res.result : null;
    } catch {
      return null; // extension reloaded / context gone
    }
  }

  // ---------- detection ----------

  function isVisible(el) {
    const r = el.getBoundingClientRect();
    if (r.width < 4 || r.height < 4) return false;
    const cs = getComputedStyle(el);
    return cs.visibility !== "hidden" && cs.display !== "none" && Number(cs.opacity) > 0.05;
  }

  function usable(el) {
    return el instanceof HTMLInputElement && TEXTY.has(el.type) && !el.disabled && !el.readOnly && isVisible(el);
  }

  function describe(el) {
    const parts = [el.name, el.id, el.placeholder, el.title, el.getAttribute("aria-label"), el.getAttribute("data-testid")];
    if (el.labels) for (const l of el.labels) parts.push(l.textContent);
    const by = el.getAttribute("aria-labelledby");
    if (by) for (const id of by.split(/\s+/)) parts.push(document.getElementById(id)?.textContent);
    return parts.filter(Boolean).join(" ").slice(0, 500);
  }

  function isOtpInput(el) {
    if (!usable(el)) return false;
    if ((el.autocomplete || "").includes("one-time-code")) return true;
    const d = describe(el);
    if (NEGATIVE.test(d)) return false;
    if (STRONG.test(d)) return true;
    const ml = el.maxLength;
    const numeric = el.inputMode === "numeric" || el.type === "tel" || el.type === "number" || /\\d|0-9/.test(el.pattern);
    return WEAK.test(d) && ((ml >= 4 && ml <= 10) || numeric);
  }

  // Codes split over 4–8 single-character boxes.
  function findSplitGroups() {
    const singles = [...document.querySelectorAll("input")].filter((el) => el.maxLength === 1 && usable(el));
    const groups = [];
    const used = new Set();
    for (const el of singles) {
      if (used.has(el)) continue;
      let node = el.parentElement;
      for (let depth = 0; node && depth < 4; depth++, node = node.parentElement) {
        const members = singles.filter((s) => node.contains(s));
        if (members.length >= 4) {
          if (members.length <= 8) {
            members.forEach((m) => used.add(m));
            groups.push({ kind: "split", els: members });
          }
          break;
        }
      }
    }
    return groups;
  }

  function findTargets() {
    const split = findSplitGroups();
    const inSplit = new Set(split.flatMap((g) => g.els));
    const singles = [...document.querySelectorAll("input")]
      .filter((el) => !inSplit.has(el) && isOtpInput(el))
      .map((el) => ({ kind: "single", els: [el] }));
    return [...singles, ...split];
  }

  function targetFromFocus() {
    const el = document.activeElement;
    if (!usable(el)) return null;
    const group = findSplitGroups().find((g) => g.els.includes(el));
    return group || { kind: "single", els: [el] };
  }

  function bestTarget() {
    const focused = targetFromFocus();
    const targets = findTargets();
    if (focused && targets.some((t) => t.els[0] === focused.els[0])) return focused;
    return targets[0] || focused;
  }

  // ---------- filling ----------

  function setValue(el, value) {
    el.focus();
    valueSetter.call(el, value);
    el.dispatchEvent(new InputEvent("input", { bubbles: true, data: value, inputType: "insertText" }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function fill(target, code) {
    if (target.kind === "single") {
      setValue(target.els[0], code);
    } else {
      target.els.forEach((el, i) => {
        const ch = code[i] ?? "";
        el.dispatchEvent(new KeyboardEvent("keydown", { key: ch, bubbles: true }));
        setValue(el, ch);
        el.dispatchEvent(new KeyboardEvent("keyup", { key: ch, bubbles: true }));
      });
      target.els[Math.min(code.length, target.els.length) - 1]?.focus();
    }
    toast("2FA code filled");
  }

  const isEmpty = (target) => target.els.every((el) => !el.value);

  // ---------- UI (shadow DOM so page styles can't interfere) ----------

  const STYLE = `
    :host { all: initial; }
    * { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
    .btn { width: 22px; height: 22px; border-radius: 6px; border: none; cursor: pointer; padding: 0;
      background: #2f6fec; color: #fff; display: grid; place-items: center; box-shadow: 0 1px 3px rgba(0,0,0,.3); }
    .btn:hover { background: #1f58c8; }
    .btn svg { width: 14px; height: 14px; }
    .menu { position: absolute; top: 28px; right: 0; min-width: 240px; max-width: 320px; background: #fff; color: #1b1f24;
      border: 1px solid #d5d9e0; border-radius: 10px; box-shadow: 0 8px 24px rgba(0,0,0,.18); padding: 6px; font-size: 13px; }
    .row { display: flex; align-items: center; gap: 10px; padding: 8px; border-radius: 7px; cursor: pointer; }
    .row:hover { background: #eef3fd; }
    .who { flex: 1; min-width: 0; }
    .name { font-weight: 600; }
    .sub { color: #5d6673; font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .code { font-family: ui-monospace, Consolas, monospace; font-size: 15px; font-weight: 600; letter-spacing: 1px; }
    .msg { padding: 8px; color: #3b4350; line-height: 1.4; }
    .link { margin: 2px 8px 8px; background: #2f6fec; color: #fff; border: none; border-radius: 6px; padding: 6px 10px; cursor: pointer; font-size: 13px; }
    .toast { background: #1b1f24; color: #fff; padding: 8px 12px; border-radius: 8px; font-size: 13px; box-shadow: 0 4px 14px rgba(0,0,0,.25); }
  `;
  const KEY_ICON = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3M16 7l3 3M14 9l2 2"/></svg>`;

  function makeHost() {
    const host = document.createElement("div");
    host.style.cssText = "position:fixed;z-index:2147483647;top:0;left:0;";
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    root.append(style);
    document.documentElement.append(host);
    return { host, root };
  }

  function addBadge(target) {
    const anchor = target.kind === "single" ? target.els[0] : target.els[target.els.length - 1];
    const { host, root } = makeHost();
    const wrap = document.createElement("div");
    wrap.style.position = "relative";
    const btn = document.createElement("button");
    btn.className = "btn";
    btn.type = "button";
    btn.title = "Fill 2FA code";
    btn.innerHTML = KEY_ICON;
    wrap.append(btn);
    root.append(wrap);

    let menu = null;
    const closeMenu = () => { menu?.remove(); menu = null; };
    const badge = { host, anchor, target, closeMenu, open: () => openMenu() };

    async function openMenu() {
      closeMenu();
      menu = document.createElement("div");
      menu.className = "menu";
      menu.innerHTML = `<div class="msg">Loading…</div>`;
      wrap.append(menu);
      const info = await ask("codesForPage");
      if (!menu) return;
      menu.textContent = "";
      if (!info || !info.relevant) {
        menu.append(msgEl("No 2FA accounts are saved for this site."));
      } else if (info.locked) {
        menu.append(msgEl("Your 2FA vault is locked."));
        const b = document.createElement("button");
        b.className = "link";
        b.textContent = "Unlock";
        b.onclick = async () => {
          const opened = await ask("openPopup");
          if (!opened) { b.remove(); menu?.append(msgEl("Click the 2FA Autofill icon in the toolbar to unlock, then try again.")); }
        };
        menu.append(b);
      } else {
        for (const m of info.matches) {
          const row = document.createElement("div");
          row.className = "row";
          const who = document.createElement("div");
          who.className = "who";
          const name = document.createElement("div");
          name.className = "name";
          name.textContent = m.name || "Account";
          const sub = document.createElement("div");
          sub.className = "sub";
          sub.textContent = [m.username, m.email].filter(Boolean).join(" · ");
          who.append(name, sub);
          const code = document.createElement("div");
          code.className = "code";
          code.textContent = m.code;
          row.append(who, code);
          row.onclick = async () => {
            closeMenu();
            const fresh = await ask("codesForPage"); // codes may have rolled over while the menu was open
            const pick = fresh?.matches?.find((x) => x.id === m.id) || m;
            fill(target, pick.code);
          };
          menu.append(row);
        }
      }
    }

    btn.addEventListener("mousedown", (e) => e.preventDefault()); // keep focus in the field
    btn.addEventListener("click", (e) => { e.stopPropagation(); menu ? closeMenu() : openMenu(); });
    document.addEventListener("click", (e) => { if (!host.contains(e.target)) closeMenu(); }, true);

    badges.set(target.els[0], badge);
    positionBadge(badge);
    return badge;
  }

  function msgEl(text) {
    const d = document.createElement("div");
    d.className = "msg";
    d.textContent = text;
    return d;
  }

  function positionBadge(badge) {
    const { anchor, host } = badge;
    if (!anchor.isConnected || !isVisible(anchor)) {
      host.style.display = "none";
      return;
    }
    const r = anchor.getBoundingClientRect();
    host.style.display = "";
    const inside = badge.target.kind === "single" && r.width > 120;
    const x = inside ? r.right - 28 : r.right + 6;
    host.style.transform = `translate(${Math.round(x)}px, ${Math.round(r.top + r.height / 2 - 11)}px)`;
  }

  function repositionAll() {
    for (const [first, badge] of badges) {
      if (!first.isConnected) {
        badge.host.remove();
        badges.delete(first);
      } else {
        positionBadge(badge);
      }
    }
  }

  let toastTimer;
  function toast(text) {
    if (window !== window.top && !document.hasFocus()) return;
    const { host, root } = makeHost();
    host.style.cssText += "top:auto;left:auto;bottom:20px;right:20px;";
    const t = document.createElement("div");
    t.className = "toast";
    t.textContent = text;
    root.append(t);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => host.remove(), 1800);
  }

  // ---------- main loop ----------

  async function scan() {
    const fresh = findTargets().filter((t) => !seen.has(t.els[0]));
    if (!fresh.length) return;
    fresh.forEach((t) => seen.add(t.els[0]));
    const info = await ask("codesForPage");
    if (!info || !info.relevant) return; // nothing saved for this site: stay invisible
    if (info.settings.showBadge) fresh.forEach(addBadge);
    if (!info.locked && info.settings.autoFill && !autoFilled && info.matches.length === 1) {
      const target = fresh.find(isEmpty);
      if (target) {
        autoFilled = true;
        fill(target, info.matches[0].code);
      }
    }
  }

  let scanTimer;
  const scheduleScan = () => {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(scan, 250);
  };

  new MutationObserver(scheduleScan).observe(document.documentElement, {
    childList: true, subtree: true, attributes: true, attributeFilter: ["style", "class", "hidden", "type"],
  });
  addEventListener("scroll", () => requestAnimationFrame(repositionAll), true);
  addEventListener("resize", () => requestAnimationFrame(repositionAll));
  addEventListener("focusin", scheduleScan, true);
  setInterval(repositionAll, 1000);
  scan();

  // ---------- commands from popup / keyboard shortcut ----------

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.type === "fillCode") {
      // Only the frame that has a code field answers, so the popup hears from the right one.
      const target = bestTarget();
      if (!target) return;
      fill(target, String(msg.code));
      sendResponse(true);
    } else if (msg?.type === "fillBest") {
      (async () => {
        const target = bestTarget();
        if (!target) return;
        const info = await ask("codesForPage");
        if (!info || !info.relevant) return toast("No 2FA accounts saved for this site");
        if (info.locked) {
          if (!(await ask("openPopup"))) toast("2FA vault is locked — click the extension icon");
          return;
        }
        if (info.matches.length === 1) return fill(target, info.matches[0].code);
        const badge = badges.get(target.els[0]) || addBadge(target);
        badge.open();
      })();
    }
  });
})();
