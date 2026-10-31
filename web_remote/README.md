# WinKey Remote Web

Private web control panel for Windows unlock, lock and wake. The browser never sends or stores the Windows PIN. A Windows companion polls this Site over HTTPS and executes a single-use command locally.

## Development

- `npm run dev -- --host 127.0.0.1 --port 5173`
- `node node_modules/typescript/bin/tsc --noEmit`
- `python tests/integration.py` against the running local preview (simulated actions; never controls Windows).

D1 schema is in `db/schema.ts`. Generated immutable migrations are in `drizzle/`.
Hosted browser access uses Sites-owned ChatGPT sign-in. The Windows companion needs the separately authorized Sites service-access bearer plus its own device key. These secrets are never included in this repository.

Pairing codes expire after ten minutes. Commands expire after twenty seconds before claim and are atomically claimed once. The companion persists consumed command IDs before execution. A missing result is reported as unknown, never assumed successful.

The companion's source, build output and encrypted local configuration are outside this Site checkout. Website publication does not upload Windows PINs, agent credentials or the previous PC-agent configuration.

## Simple mobile remote

`/mobile` is a separate phone surface with only Lock and Unlock. The original `/` dashboard is unchanged. Windows companion QR links select the device and can include its short-lived, one-time pairing code. Windows PIN, service access token and device secret never appear in QR links. Pairing still requires an authorized signed-in visitor. The code is removed from the mobile address after pairing.
