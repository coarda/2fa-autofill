# 2FA Autofill (Chrome extension)

Generates your two-factor (TOTP) codes — the same 6-digit codes Google Authenticator / Authy show — and fills them in when a site asks for a verification code.

## Install

1. Open `chrome://extensions` in Chrome.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and choose this `2fa-autofill` folder.
4. Pin the extension (puzzle-piece icon → pin) and click it to create your master password.

## Adding an account

When you enable 2FA on a website it shows a QR code and usually a "can't scan? enter this key" link. In the extension click **+** and either:

- paste the **setup key** (e.g. `JBSW Y3DP EHPK 3PXP`) into *Secret key*, or
- paste the **otpauth://** link if the site gives you one (it fills everything in).

Then fill in the **websites** (e.g. `github.com` — subdomains like `login.github.com` match automatically), your **username** and **email**. The form shows the current code so you can confirm it against the site before saving.

## Importing from Google Authenticator

1. Click the extension icon → ⚙ Settings → **Import from Google Authenticator** (a new tab opens).
2. On your phone, open Google Authenticator → ☰ menu → **Transfer accounts** → **Export accounts**, pick accounts, tap **Next**.
3. Hold the phone's QR code up to your **webcam**, or upload a **photo** of it. If the export shows several QR codes, read each one (the page tracks "QR 1 of 3" etc.).
4. Check each account, add its website(s) (common services like Google and GitHub are filled in for you), and click **Import**.

Only time-based (TOTP) accounts are imported. Old counter-based (HOTP) entries are skipped. QR reading uses the bundled open-source [jsQR](https://github.com/cozmo/jsQR) library (`vendor/jsQR.js`, Apache-2.0) and runs entirely on your computer.

## Filling codes

- **Automatic:** if a site has exactly one saved account and the vault is unlocked, the code field is filled as soon as it appears.
- **Button:** a small blue key button appears next to code fields on your saved sites — click it to pick an account.
- **Popup:** click the extension icon → **Fill** (or **Copy**).
- **Shortcut:** `Alt+Shift+O` (change at `chrome://extensions/shortcuts`).

Both single code boxes and "one box per digit" layouts are supported.

## Security notes

- Secrets are encrypted with AES-256-GCM using a key derived from your master password (PBKDF2-SHA256, 600,000 rounds) and stored only in this Chrome profile.
- The unlocked key is held in memory-only session storage; the vault re-locks after the auto-lock time and whenever Chrome closes.
- Web pages never see your secrets — only the current code, and only for the domains you listed for that account.
- The list of site domains is stored unencrypted so the extension knows where to show the fill button while locked.
- Keeping your password and 2FA codes in the same browser reduces the protection 2FA gives you. Keep your site's **backup/recovery codes** somewhere safe, and use **Settings → Export backup** regularly. If you forget the master password, the vault cannot be recovered.
