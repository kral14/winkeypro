# WinKey: HTTPS without purchasing a domain

The current configured gateway is `http://158.101.172.228:8080`. Account passwords must not be sent over this public HTTP connection. iPhone camera access also requires a secure context. A locally generated self-signed certificate is not a substitute for a certificate trusted by iOS.

Let's Encrypt supports publicly trusted IP-address certificates. See the [official Certbot instructions](https://letsencrypt.org/2026/03/11/shorter-certs-certbot/). IP certificates use the shortlived profile (about six days), so automatic renewal and a web-server reload hook are required.

On the server, an administrator must:

1. Confirm that `158.101.172.228` is its public IP and that inbound TCP ports 80 and 443 are reachable. Preserve the existing database and gateway secrets.
2. Install a current Certbot release (5.4 or newer for IP webroot support). Configure HTTP challenge serving or use standalone validation while port 80 is free.
3. Request a production certificate with `--preferred-profile shortlived --ip-address 158.101.172.228`. The official guide includes a staging test; staging certificates are not trusted by phones.
4. Configure the TLS reverse proxy to use the issued fullchain and private-key files, proxy both HTTP API and WebSocket traffic to the existing gateway, and set up automatic renewal plus proxy reload. Avoid logging QR queries or installation tickets.
5. Deploy the updated Python gateway **including** `account_service.py`, `mobile_install.py`, and `deploy/static/`. The Dockerfile includes these files. Retain the current database volume and admin secret.
6. Verify `https://158.101.172.228/healthz` and WebSocket reconnection from an iPhone. Then configure this HTTPS origin in the desktop's server settings. The new account endpoints must be running before installing account-enabled clients.

The repository's existing domain-based Caddyfile does not automatically configure an IP certificate. Do not run the domain configure command with an invented domain. No remote server was modified as part of the local Windows build.

## iPhone and Android PWA installation

PC registration and device naming happen on PC. Scan its QR with the phone camera and open the mobile page in Safari (iPhone) or Chrome (Android). The paired device list and selection remain on the phone.

On HTTPS, a browser with paired PCs automatically prepares an expiring handoff and updates both the web manifest and current launch fragment. This handles iOS opening an installed web app with storage separate from Safari. Persistent device tokens are never placed in the launch URL. First open the new icon within 24 hours.

- iPhone: press **Ana ekrana əlavə et**, then Safari Share → Add to Home Screen. Depending on the iOS version, enable opening as a web app.
- Android: press **Android-də quraşdır** when Chrome offers installation. If preparation is still running, the first click prepares it and the next click opens Chrome's native install prompt. If no prompt is available, use Chrome's menu → Install app / Add to Home Screen.
- Old installed icon opens empty: in the paired Safari/Chrome page press **Qoşulma kodunu kopyala**. In the empty installed app, paste it into **Birdəfəlik qoşulma kodu** and press **Qoşulmanı bərpa et**. Prepare a fresh code if expired/already claimed elsewhere. This restores an existing phone pairing, rather than enrolling a PC on mobile.
- If a restore response is lost, the same installed app can retry using its persisted random installation nonce. A different installation cannot reuse a claimed handoff. Expiry and live session revocation are still enforced.
- The service worker caches only the public static shell and icons. API calls, commands, account/session data, QR query URLs, and install-ticket manifests are never cached. Offline controls do not execute commands.

## Deployment files

The Docker allowlist includes `deploy/static/install.js`, `mobile-sw.js`, 192px/512px icons and the 180px Apple touch icon. Both the ASGI and compatibility HTTP servers serve the worker at **/mobile-sw.js** with root scope. Deploy the new Python modules together with all static files; keep the existing database volume so phone sessions survive.

This is a server/mobile update, not an APK and not a Windows setup change. Native mobile store distribution is outside this workflow. Physical iPhone and Android installation remains a device check after VM deployment.

## Current operational blocker

The last live check showed HTTP health 200 at `http://158.101.172.228:8080`, while `https://158.101.172.228` was unavailable. A shortcut can still be created on some browsers, but this is not a reliable secure PWA installation. Frontend changes cannot provision a trusted certificate on the VM. Configure IP HTTPS as described above before testing installation. After HTTPS is ready, the desktop must produce QR links using that HTTPS origin; do not keep pairing over the old HTTP origin and expect its storage to migrate automatically to HTTPS.
