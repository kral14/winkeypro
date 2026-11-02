# Account registration and multiple computers

## Requested behavior

On first desktop use, the user creates an account with email and password or signs in to an existing account. The same account can own multiple computers. On the first QR pairing, the user supplies a name such as PC 1 or Ofis 2. Mobile shows the account's computer list. Its last selected computer survives closing and reopening the page; lock and unlock commands always target that selected computer.

## Proposed implementation

- Keep the current Python gateway, SQLite/PostgreSQL storage, Tauri desktop, and mobile page.
- Add account records, hashed passwords, expiring account sessions, and account-to-computer ownership records. Never store plaintext passwords or log them. Keep existing device authentication separate from account authentication.
- Desktop signs in through the configured gateway and stores the account session protected by Windows DPAPI. It binds the local authenticated device to that account before showing its pairing QR.
- Registration and account sign-in occur on PC only. Mobile consumes each one-use QR, requires a computer name, and keeps the resulting device-scoped session in its local portfolio. There is no mobile account login.
- The mobile Add device action scans another QR inside the existing page without navigation. It appends a named device to the selector, preserving other pairings. Existing command and WebSocket authorization remain scoped to a single device.
- Persist the selected device in the phone's portfolio storage. Revalidate device sessions when restoring it. Close the previous device's connection and clear pending actions before switching; ignore late responses from the previous device. Do not allow a switch while a command is still in progress.
- Show an unknown/checking state until real Windows state arrives. Query the interactive console session from the Windows service rather than the service's Session 0 desktop.
- Provide a PWA manifest, reconnection on resume, and a short-lived one-use install handoff. This lets an iOS standalone launch restore its paired devices even when Safari and the installed web app do not share local storage. Do not put persistent remote tokens in launch URLs.

## Validation

Test registration/login, password verification, session expiry, account isolation, QR ownership and replay rejection, per-device naming, multiple-device selection, restored selection, and commands after switching. Run mobile and desktop regressions, native session state tests, and the local release build. Server code must be deployed before account-enabled clients can use the new flow; deployment is separate from the local build.

## Compatibility

Keep unowned legacy device pairings working during migration. Since the user explicitly requires no mobile account login, possession of the first one-use QR intentionally authorizes a new phone. When a phone supplies its existing remote token to add a device, both devices must have the same account owner. Apply that check in shared pairing logic across both APIs. The QR is a credential and must not be shared. Public release-key rotation previously approved by the user is independent of account passwords and device credentials.

## Deployment prerequisite

The current default cloud endpoint is HTTP. New account onboarding requires a trusted HTTPS endpoint; sending passwords over the existing public HTTP endpoint is deliberately blocked. The desktop provides a server-settings action so a trusted HTTPS IP or domain can be configured. No server credentials or deployment authorization were supplied in this chat. A local build alone does not activate the new mobile page on the running server.
