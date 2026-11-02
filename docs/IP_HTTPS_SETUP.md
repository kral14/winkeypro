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

## iPhone installation

In Safari, scan the PC QR and name that PC. Use **Yeni cihaz əlavə et** for more PCs. Select the required PC. Before adding to the home screen, press **iPhone üçün tətbiqi hazırla**, then use Safari's Share → Add to Home Screen. Open the new icon within 24 hours. A one-use handoff restores the paired devices into the installed app's own storage; persistent remote-control tokens are not placed in its launch URL.

If an old home-screen icon opens with no pairing, use its **Yeni cihaz əlavə et** action to scan a fresh PC QR, or prepare a new installation from Safari. Clearing browser/app storage requires pairing again. The installed app reconnects when brought back to the foreground. Physical iOS installation and camera permission still require device testing.
