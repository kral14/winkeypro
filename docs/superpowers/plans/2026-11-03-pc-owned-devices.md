# PC-owned device management and mandatory account lifecycle

**Goal:** Require PC sign-in; manage named devices on PC; mobile only selects and controls paired PCs.
**Architecture:** Preserve agent connections and pairing tokens across sign-out and pause. Persist account device control state on the gateway and enforce it before command enqueue/claim. Online/offline is independent of workstation lock state. Device addition names the real PC before generating its QR; the user confirmed adding the currently running physical PC.

## Tasks

- [x] Fix account device listing (`last_seen_at`, not nonexistent `last_seen`); expose online and paused flags.
- [x] Add ownership-checked pause/resume/delete and local signed-out state, retaining agent authentication/connection and pairings for pause/logout. Reject commands while disabled; notify mobile sessions of availability changes.
- [x] Remove account skip and unauthenticated close; retain success message until Continue; add account logout and safe PC device controls.
- [x] Name the current PC before QR generation, then consume that QR on mobile without a mobile Add device flow. Keep last selection and refresh names/availability.
- [x] Update regression tests to the current UI and verify account lifecycle, cross-account isolation, device selection, command suppression, installer and release build.

## Deployment

No server push or deployment: the user does those from the VM. IP HTTPS is supported by Let's Encrypt; document a trusted IP-certificate setup without changing server configuration or falsely claiming HTTPS is already active. Existing locally modified signed manifests belong to the user/build and must not be discarded.


## Verification and handoff

- User confirmed that Add device enrolls the real PC currently running the app.
- 13 account/install/API/WebSocket tests passed, including ownership isolation, command suppression, logout preserving agent and phone sockets, heartbeats not undoing logout, and same-phone group synchronization.
- Desktop account, desktop bootstrap, mobile portfolio and mobile transport JS tests passed. Installer privilege/shortcut tests passed (3 tests). Cargo check passed.
- Independent code review reported no definite new P1/P2 in the reviewed lifecycle, ownership checks or phone-group synchronization. Real iOS installation remains a hardware check.
- 3 Docker allowlist/import/runtime tests passed with the updated backend.
- Local 0.2.0 build completed. Setup SHA-256, signed manifest, all payload hashes and source public-key pin consistency verified. Updated deploy/windows_release/WinKeyUpdate.zip for the user's manual Git/VM deployment.
- No Git push, VM deployment, Windows installation, or physical lock/unlock action performed.
- Existing user-added public-IP HTTP exemption remains unchanged pending VM trusted HTTPS setup. Confirmed from official Let's Encrypt documentation that IP certificates need no domain; they require automated renewal. No TLS provisioning was claimed.
