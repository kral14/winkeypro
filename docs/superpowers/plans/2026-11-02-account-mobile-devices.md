# Desktop accounts and mobile device portfolio implementation plan

> Implement inline using executing-plans, with tests per task.

**Goal:** PC account registration, named mobile QR pairings, persistent device selection, and iOS standalone restoration.
**Architecture:** Existing Tauri client and Python gateway; keep device-scoped command authorization. Add account auth behind native DPAPI storage, a browser portfolio, and one-use PWA installation handoffs.
**Spec:** docs/account-multi-pc-design.md (updated by the user's PC-only registration clarification).

## Tasks

- [x] Add gateway account registration/login with hashed passwords, throttling and expiring hashed sessions. Test invalid credentials, duplicate emails and session expiry.
- [x] Add native desktop account commands and registration/sign-in overlay before cloud QR generation; protect stored session with DPAPI. Verify UI bootstrap and Rust compilation.
- [x] Add a mobile portfolio module: migrate existing pairing, name each device, select/persist, append QR without navigation, reconnect safely and discard late device responses. Test storage reload, two devices and switch isolation.
- [x] Add iOS manifest, one-use install handoff endpoint and explicit recovery UI. Test expired/replayed handoffs, token isolation and mobile resume behavior.
- [x] Run focused native/mobile/backend regressions and local release build. Record any hardware-only checks and server deployment requirements.

## Constraints and review

No private keys in artifacts or Git; passwords are never stored or logged in plaintext. No automatic server publish or Windows lock/unlock tests. Scanner must work without BarcodeDetector on iOS. QR codes are one-use; only selected-device credentials authorize commands. Do not replay unfinished commands after switching devices.


## Verification and handoff

- Account/install API suite: 8 tests, including real local ASGI HTTP requests, session expiry, QR replay, account/device proof and ownership isolation, revoked/expired/one-use install handoffs.
- Mobile portfolio browser harness: two named PCs, storage reload, in-page pair, token selection, busy switch/race handling, and independent iOS app storage bootstrap.
- Existing mobile transport and desktop bootstrap regressions passed. Native WTS session flag unit test passed. The earlier broad native run under sandbox had filesystem access failures; this is not claimed as a passing full suite.
- Release pipeline's two local-Git tests passed (no real remote push).
- Local build 0.1.7 succeeded. Setup SHA-256 matches dist/SHA256SUMS.txt; Ed25519 package signature and every manifest file hash verified. Desktop embedded XML manifests parse and request asInvoker.
- Prepared deploy/windows_release/WinKeyUpdate.zip from the verified new signed archive because dist is ignored by Git. No Git push, VM deploy, installation or lock/unlock action performed.
- Independent review's credential persistence, camera handling and asynchronous selection findings were corrected and regression-tested. Reviewer reported no definite remaining P1/P2 issues.
- Ruling: first-phone QR possession authorizes that phone without mobile account login, as explicitly requested. Existing phone portfolios send their current token and shared pairing logic checks account membership for added PCs.
- Ruling: do not send account passwords to the public HTTP default. Keep an actionable HTTPS prerequisite and settings path; user will push/deploy from VM themselves. IP-certificate instructions are in docs/IP_HTTPS_SETUP.md.
- Physical iOS camera, Add to Home Screen, and actual Windows locked/unlocked behavior still require live-device verification after server deployment and trusted HTTPS setup.
