# PC-owned devices and mobile control (2026-11-03)

The user clarified that adding/managing devices belongs on PC, not mobile. New device means the physical PC currently running WinKey. On another PC, install WinKey and sign in to the same account.

## PC flow

- Sign-in/registration is mandatory. There is no Skip, unauthenticated drawer close, or fake browser registration success.
- A valid stored account session can resume. Successful new registration/login stays visible until Continue.
- The owner sees all owned PCs with online/offline and locked/unlocked as separate states, and can pause/resume/delete each owned PC.
- Add device opens the current PC naming field. Explicitly confirm its name before creating QR. The signed device proof binds the PC to its account and stores its canonical name on the server.
- Sign out marks only this PC signed out on the server and removes its local account session. It preserves agent transport, device ownership, PIN storage and phone pairings. Existing phone commands are rejected while signed out.
- Sign back in reactivates an already enrolled PC using its device proof. Pause persists until explicit Resume. A deleted PC must be added again and paired with a fresh QR.

## Mobile flow

- No mobile Add device/name/scanner form. Scan the QR produced on the PC using the phone camera.
- QR pairing consumes the one-use code and appends the server-provided PC name to the phone portfolio. A second QR adds another choice, such as Ev next to Ofis.
- Keep the last selection on reload. Online/offline and lock state update independently; offline controls are disabled. Never switch a target while a physical command is pending.
- Session groups synchronize only PCs explicitly paired to the same phone group. This also lets an installed iOS PWA learn about a second PC paired in Safari. It does not grant every phone access to every device in the owner's account.
- iOS install handoff remains one-use and expiring. Physical iPhone/PWA testing still follows trusted HTTPS deployment.

## Server behavior

Account owner checks protect PC management. Account-device control state is separate from agent credentials and device ACTIVE status. Command enqueue, WS claim and HTTP poll all enforce signed-in/not-paused/not-removed state. Agent heartbeats cannot turn a signed-out PC back online. Logout/pause pushes offline presence without closing agent/phone sockets; delete revokes that PC's phone sessions.

The account device query uses last_seen_at. Missing schema columns are not silently converted into an empty device list.

## HTTPS and deployment

Let's Encrypt supports trusted certificates for a public IP without buying a domain. Short-lived IP certificates require automatic renewal; see docs/IP_HTTPS_SETUP.md. No VM access was provided and the user handles Git push/deployment. The existing user-added HTTP exemption for the public IP remains unchanged in this task; it does not encrypt passwords. HTTPS provisioning is still required on the VM to secure that traffic and enable iOS secure-context features.
