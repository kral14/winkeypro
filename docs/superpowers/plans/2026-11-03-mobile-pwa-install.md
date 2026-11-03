# Mobile PWA installation and connection restoration

**Goal:** Preserve paired devices when opening iOS Home Screen apps and provide Android installation from the website (user confirmed PWA, not APK).

## Evidence

The live HTTP health endpoint responds, while HTTPS on the IP is unavailable. Current code creates the iOS storage handoff only when a manual preparation button is pressed, leaves the browser's launch URL unchanged, has only a 128px manifest icon, and has no Android install prompt or service worker. Apple documents separate Home Screen storage; secure PWA installation requires HTTPS.

## Implementation

- [x] Add 192px/512px and Apple icons; serve an offline shell worker from the origin root. Cache only static shell GETs, never credentials, API responses, QR URLs or manifests with install tickets.
- [x] Add a shared install controller that automatically prepares a one-use handoff for a paired HTTPS browser, updates both manifest and browser launch fragment, and handles beforeinstallprompt/appinstalled on Android.
- [x] Keep installed-app restoration before connection startup. Offer recovery of an existing pairing via an expiring copied handoff code when an old installed icon has no browser storage. This is not mobile device enrollment.
- [x] Test installability metadata, secure/insecure origins, deferred install prompt, separate storage restoration, static worker routing/cache exclusions, Docker packaging and existing pairing regressions.

## Operational boundary

The user handles VM deployment. No server credentials are available; HTTPS cannot be enabled by editing frontend files. Provide precise live diagnosis and deployment guidance, without weakening trust validation or calling HTTP a supported installation origin. Physical iOS/Android installation still requires device verification after trusted HTTPS is configured.


## Verification

15 account/install/API/WebSocket tests passed, including Android icon dimensions, root worker route and install handoff retry bound to a random persisted client nonce. New install-controller and service-worker VM tests passed, as did existing mobile portfolio/transport regressions. Three Docker allowlist/import/runtime tests passed with the new assets included. Independent review found an Android transient-user-activation race; fixed by using a ready handoff before calling prompt synchronously in the click and requiring a second click after asynchronous preparation. Gesture and no-network-at-ready-click regressions passed.

No native Windows source was changed for this PWA task; existing native/layout release modifications in the workspace were preserved. No Git push, VM deployment, APK build, TLS provisioning, or actual phone installation occurred. The live IP HTTPS endpoint remains unavailable, so physical iOS/Android validation is pending deployment with trusted HTTPS. Instructions were updated in docs/IP_HTTPS_SETUP.md.
