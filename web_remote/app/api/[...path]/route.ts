import { env } from "cloudflare:workers";

export const dynamic = "force-dynamic";

const json = (data: unknown, status = 200) =>
  Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, oai-authenticated-user-id"
    }
  });

const hash = async (text: string) => {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf))
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
};

const id = () => crypto.randomUUID();

function error(message: string, status = 400): never {
  throw { message, status };
}

/**
 * Cloudflare D1 cədvəllərinin möhkəm və xətasız inisializasiyası
 */
let tablesInitialized = false;
async function ensureTables(db: any) {
  if (tablesInitialized) return;

  const criticalTables = [
    "CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, owner TEXT, name TEXT NOT NULL, public_key_hex TEXT NOT NULL, secret_hash TEXT NOT NULL, pair_hash TEXT, pair_expires INTEGER, last_seen INTEGER NOT NULL, locked INTEGER, pin_ready INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'ACTIVE', created INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS challenges (nonce TEXT PRIMARY KEY, device_id TEXT NOT NULL, purpose TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS mobile_sessions (token TEXT PRIMARY KEY, device_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, scope TEXT NOT NULL DEFAULT 'mobile_remote')",
    "CREATE TABLE IF NOT EXISTS commands (id TEXT PRIMARY KEY, device_id TEXT NOT NULL, owner TEXT, action TEXT NOT NULL, state TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL, finished INTEGER, result TEXT)",
    "CREATE TABLE IF NOT EXISTS audit_logs (id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, target_device_id TEXT, details TEXT, timestamp INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS telemetry_events (id TEXT PRIMARY KEY, device_id TEXT NOT NULL, level TEXT NOT NULL, event TEXT NOT NULL, details TEXT, timestamp INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS pair_attempts (client_ip TEXT PRIMARY KEY, attempts INTEGER NOT NULL, last_attempt INTEGER NOT NULL, blocked_until INTEGER NOT NULL DEFAULT 0)",
    "CREATE INDEX IF NOT EXISTS idx_devices_owner ON devices(owner)",
    "CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status)",
    "CREATE INDEX IF NOT EXISTS idx_challenges_device_purpose ON challenges(device_id, purpose)",
    "CREATE INDEX IF NOT EXISTS idx_mobile_sessions_device ON mobile_sessions(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_command_queue ON commands(device_id, state, created)",
    "CREATE INDEX IF NOT EXISTS idx_telemetry_device ON telemetry_events(device_id, timestamp)"
  ];

  for (const sql of criticalTables) {
    try {
      await db.prepare(sql).run();
    } catch (err: any) {
      console.error("[CRITICAL_DB_INIT_ERROR]", err);
      throw new Error(`D1 cədvəl inisializasiyası uğursuz oldu: ${err.message}`);
    }
  }

  // Gözlənilən kolon miqrasiyaları (köhnə bazalarda idempotent)
  const optionalMigrations = [
    "ALTER TABLE devices ADD COLUMN public_key_hex TEXT",
    "ALTER TABLE devices ADD COLUMN status TEXT DEFAULT 'ACTIVE'"
  ];
  for (const sql of optionalMigrations) {
    try {
      await db.prepare(sql).run();
    } catch (err: any) {
      const msg = String(err?.message || "");
      if (!msg.toLowerCase().includes("duplicate column") && !msg.toLowerCase().includes("already exists")) {
        console.warn("[MIGRATION_NOTICE]", msg);
      }
    }
  }

  tablesInitialized = true;
}

async function handle(request: Request) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, oai-authenticated-user-id"
      }
    });
  }

  try {
    const pathname = new URL(request.url).pathname;
    const path = pathname.startsWith("/api/") ? pathname.slice(5) : pathname.replace(/^\//, "");
    const now = Date.now();
    const post = request.method === "POST";
    const body = post ? ((await request.json().catch(() => ({}))) as Record<string, any>) : {};

    // 1. D1 Database Əldə Edilməsi
    const db = (env as any)?.DB || (globalThis as any).__TEST_D1_DB__;
    if (!db) {
      if (path === "status" || path === "health") {
        return json({ status: "ONLINE", db: "UNAVAILABLE", now });
      }
      return json({ error: "Verilənlər bazası (D1) hazır deyil" }, 503);
    }
    await ensureTables(db);

    const one = async (sql: string, ...args: any[]) => {
      const stmt = db.prepare(sql);
      return (await stmt.bind(...args).first()) as Record<string, any> | null;
    };

    const all = async (sql: string, ...args: any[]) => {
      const stmt = db.prepare(sql);
      const res = await stmt.bind(...args).all();
      return res.results || [];
    };

    // Audit Logging Köməkçisi
    const logAudit = async (actor: string, action: string, targetDeviceId: string | null, details: string) => {
      try {
        await db
          .prepare("INSERT INTO audit_logs (id, actor, action, target_device_id, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)")
          .bind(id(), actor, action, targetDeviceId, details, now)
          .run();
      } catch (_) {}
    };

    // 2. Autentifikasiya Köməkçiləri
    const authHeader = request.headers.get("authorization") || "";
    const bearerToken = authHeader.replace(/^Bearer /i, "").trim();

    // OpenAI Sites / ChatGPT tərəfindən inyeksiya edilən istifadəçi
    const oaiUserId = (request.headers.get("oai-authenticated-user-id") || "").trim();
    const oaiEmail = (request.headers.get("oai-authenticated-user-email") || "").trim().toLowerCase();
    const adminSecret = ((env as any)?.WINKEY_ADMIN_SECRET || process.env.WINKEY_ADMIN_SECRET || "").trim();
    const isAdminToken = Boolean(adminSecret && bearerToken === adminSecret && adminSecret.length >= 16);

    // Sabit Platforma Site ID və Layihə Sahibi Allowlist
    const DEFAULT_OWNER_SITE_ID = "usr_owner_nesib20";
    const ownerSiteId = ((env as any)?.WINKEY_OWNER_SITE_ID || process.env.WINKEY_OWNER_SITE_ID || DEFAULT_OWNER_SITE_ID).trim();
    const ownerEmail = ((env as any)?.WINKEY_OWNER_EMAIL || process.env.WINKEY_OWNER_EMAIL || "nesib20@gmail.com").trim().toLowerCase();

    // Layihə Sahibi İcazəsi (Yalnız təsdiqlənmiş platforma ID-si, email allowlist və ya sistem admin açarı)
    const isProjectOwner = Boolean(
      isAdminToken ||
      (oaiUserId && oaiUserId === ownerSiteId) ||
      (oaiEmail && oaiEmail === ownerEmail)
    );

    // Caller-controlled x-user-id rədd edilir
    if (request.headers.get("x-user-id")) {
      error("Caller-controlled x-user-id başlığı qadağandır (E_SPOOFED_HEADER)", 401);
    }

    // Mobil Sessiya Doğrulaması (Device-Scoped Bearer Token)
    async function getMobileSession(reqDeviceId?: string) {
      if (!bearerToken || !bearerToken.startsWith("sess_")) return null;
      const sess = await one(
        `SELECT s.token, s.device_id, s.expires_at, d.status as device_status 
         FROM mobile_sessions s 
         JOIN devices d ON s.device_id = d.id 
         WHERE s.token=? AND s.expires_at>? AND d.status='ACTIVE'`,
        bearerToken,
        now
      );
      if (!sess) return null;
      if (reqDeviceId && sess.device_id !== reqDeviceId) return null;
      return sess;
    }

    // Agent Autentifikasiyası (Desktop Native PC)
    async function agent() {
      const deviceId = String(body.device_id || "").trim();
      if (!deviceId) error("Cihaz ID tələb olunur", 400);
      if (bearerToken.length < 16) error("Cihaz açarı (secret) tələb olunur", 401);

      const secretH = await hash(bearerToken);
      const row = await one(
        "SELECT * FROM devices WHERE id=? AND secret_hash=? AND status='ACTIVE'",
        deviceId,
        secretH
      );
      if (!row) {
        const anyDev = await one("SELECT id, status FROM devices WHERE id=?", deviceId);
        if (!anyDev) error("Cihaz qeydiyyatdan keçməyib (E_DEVICE_NOT_FOUND)", 404);
        if (anyDev.status === "REVOKED") error("Cihaz ləğv edilib (E_DEVICE_REVOKED)", 403);
        error("Cihaz açarı yanlışdır (E_UNAUTHORIZED_AGENT)", 401);
      }
      return row!;
    }

    // Client IP müəyyən edilməsi
    const clientIp =
      request.headers.get("cf-connecting-ip") ||
      request.headers.get("x-real-ip") ||
      request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      "127.0.0.1";

    // 0. Status / Health Check
    if (path === "status" || path === "health") {
      return json({ status: "ONLINE", now });
    }

    // =========================================================================
    // 1. AGENT: Registration Challenge (/api/agent/challenge) -- Durable in D1
    // =========================================================================
    if (path === "agent/challenge" && post) {
      const deviceId = String(body.device_id || "").trim();
      if (!deviceId) error("device_id sahəsi məcburidir", 400);

      const purpose = String(body.purpose || "register").trim();
      const nonce = Array.from(crypto.getRandomValues(new Uint8Array(24)))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
      const expiresAt = now + 120000; // 120 saniyə etibarlılıq

      await db
        .prepare(
          "INSERT OR REPLACE INTO challenges (nonce, device_id, purpose, expires_at, consumed, created_at) VALUES (?, ?, ?, ?, 0, ?)"
        )
        .bind(nonce, deviceId, purpose, expiresAt, now)
        .run();

      return json({
        nonce,
        expires_at: Math.floor(expiresAt / 1000),
        status: "CHALLENGE"
      });
    }

    // =========================================================================
    // 2. AGENT: Device Registration (/api/agent/register) -- P0 Identity Guard
    // =========================================================================
    if (path === "agent/register" && post) {
      const deviceId = String(body.device_id || "").trim();
      const devName = String(body.computer_name || body.name || "Windows PC").slice(0, 80);
      const publicKeyHex = String(body.public_key_hex || "").trim().toLowerCase();
      const nonce = String(body.nonce || "").trim();
      const proofSignatureHex = String(body.proof_signature_hex || "").trim().toLowerCase();

      // 1. Məcburi sahələrin tam yoxlanışı
      if (!deviceId || !publicKeyHex || !nonce || !proofSignatureHex) {
        error("Bütün təhlükəsizlik sahələri məcburidir (device_id, public_key_hex, nonce, proof_signature_hex)", 400);
      }
      if (!/^[0-9a-f]{64}$/.test(publicKeyHex)) {
        error("public_key_hex formatı yanlışdır (32 bayt / 64 hex simvol tələb olunur)", 400);
      }
      if (!/^[0-9a-f]{128}$/.test(proofSignatureHex)) {
        error("proof_signature_hex formatı yanlışdır (64 bayt / 128 hex simvol tələb olunur)", 400);
      }

      // 2. D1-də Nonce doğrulaması (QƏTİYYƏN İMZADAN ƏVVƏL CONSUME EDİLMİR!)
      const chRow = await one("SELECT nonce, device_id, purpose, expires_at, consumed FROM challenges WHERE nonce=?", nonce);
      if (!chRow) {
        error("Göstərilən nonce tapılmadı və ya qeydiyyatdan keçməyib (E_INVALID_NONCE)", 400);
      }
      if (chRow.device_id !== deviceId) {
        error("Nonce göstərilən cihaz üçün yaradılmayıb (E_NONCE_DEVICE_MISMATCH)", 400);
      }
      if (chRow.purpose !== "register") {
        error("Nonce təyinatı qeydiyyat üçün deyil (E_NONCE_PURPOSE_MISMATCH)", 400);
      }
      if (chRow.expires_at < now) {
        error("Nonce müddəti bitib (E_EXPIRED_NONCE)", 400);
      }
      if (chRow.consumed !== 0) {
        error("Nonce artıq istifadə edilib, təkrar hücum cəhdi bloklandı (E_NONCE_ALREADY_USED)", 400);
      }

      // 3. Mövcud cihazın sahiblik və status yoxlanışı
      const existing = await one("SELECT id, public_key_hex, status FROM devices WHERE id=?", deviceId);
      if (existing) {
        if (existing.status === "REVOKED") {
          error("Bu cihaz ləğv edilib və təkrar aktivləşdirilə bilməz (E_DEVICE_REVOKED)", 403);
        }
        if (!existing.public_key_hex) {
          error("Köhnə qeydiyyat növü olan cihaz üçün təhlükəsiz təkrar qeydiyyat tələb olunur (E_LEGACY_DEVICE_REENROLLMENT_REQUIRED)", 403);
        }
        if (existing.public_key_hex.toLowerCase() !== publicKeyHex) {
          error(
            "Bu cihaz ID başqa bir Ed25519 açarına bağlıdır. Cihaz identity takeover qadağandır (E_DEVICE_TAKEOVER_FORBIDDEN)",
            409
          );
        }
      }

      // 4. Web Crypto Ed25519 İmza Təsdiqi
      try {
        const pubBytes = new Uint8Array(publicKeyHex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
        const sigBytes = new Uint8Array(proofSignatureHex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
        const msgBytes = new TextEncoder().encode(`WINKEY_REGISTER:${nonce}:${deviceId}`);

        const key = await crypto.subtle.importKey("raw", pubBytes, { name: "Ed25519" }, false, ["verify"]);
        const isValid = await crypto.subtle.verify("Ed25519", key, sigBytes, msgBytes);
        if (!isValid) {
          error("Kriptoqrafik Ed25519 imza təsdiqlənmədi (E_INVALID_PROOF)", 400);
        }
      } catch (e: any) {
        error(`Ed25519 yoxlanış xətası: ${e.message || e}`, 400);
      }

      // 5. Yalnız etibarlı imzadan SONRA Nonce atomik istehlak edilir (anti-replay və anti-DOS)
      const consumeRes = await db
        .prepare("UPDATE challenges SET consumed=1 WHERE nonce=? AND consumed=0 AND expires_at>=? AND device_id=?")
        .bind(nonce, now, deviceId)
        .run();
      if (!consumeRes.meta || consumeRes.meta.changes === 0) {
        error("Nonce artıq başqa sorğu tərəfindən istifadə edilib (E_CONCURRENT_NONCE_REPLAY)", 409);
      }

      // 6. Təhlükəsiz yeni 24-bayt cihaz secret generasiyası və şərtli verilənlər bazası yazılışı
      const rawSecret = Array.from(crypto.getRandomValues(new Uint8Array(24)))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
      const secretH = await hash(rawSecret);

      if (existing) {
        const updRes = await db
          .prepare(
            "UPDATE devices SET name=?, secret_hash=?, last_seen=?, status='ACTIVE', owner=COALESCE(owner, ?) WHERE id=? AND public_key_hex=? AND status!='REVOKED'"
          )
          .bind(devName, secretH, now, ownerSiteId, deviceId, publicKeyHex)
          .run();
        if (!updRes.meta || updRes.meta.changes === 0) {
          error("Cihaz yenilənməsi zamanı konflikt aşkarlandı (E_DEVICE_UPDATE_CONFLICT)", 409);
        }
      } else {
        try {
          await db
            .prepare(
              "INSERT INTO devices (id, name, public_key_hex, secret_hash, status, last_seen, pin_ready, owner, created) VALUES (?, ?, ?, ?, 'ACTIVE', ?, 0, ?, ?)"
            )
            .bind(deviceId, devName, publicKeyHex, secretH, now, ownerSiteId, now)
            .run();
        } catch (_) {
          error("Cihaz qeydiyyat yarışı aşkardı (E_DEVICE_TAKEOVER_FORBIDDEN)", 409);
        }
      }

      await logAudit(`agent:${deviceId}`, "AGENT_REGISTERED", deviceId, `Device registered with Ed25519`);

      return json({
        device_id: deviceId,
        device_secret: rawSecret,
        status: "REGISTERED"
      });
    }

    // =========================================================================
    // 3. AGENT: Ephemeral QR Pair Request (/api/devices/pair-request) -- 64-bit Entropy
    // =========================================================================
    if (path === "devices/pair-request" && post) {
      const dev = await agent();

      // >= 64-bit təsadüfi entropiya (8 bayt / 16 hex simvol)
      const randArr = crypto.getRandomValues(new Uint8Array(8));
      const codeHex = Array.from(randArr).map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
      const pairCode = `WK-${codeHex.slice(0, 4)}-${codeHex.slice(4, 8)}-${codeHex.slice(8, 12)}-${codeHex.slice(12, 16)}`;
      const cleanCode = pairCode.replace(/[-\s]/g, "");
      const pairH = await hash(cleanCode);
      const pairExpires = now + 120000; // 120 saniyəlik birdəfəlik pəncərə

      await db
        .prepare("UPDATE devices SET pair_hash=?, pair_expires=? WHERE id=?")
        .bind(pairH, pairExpires, dev.id)
        .run();

      await logAudit(`agent:${dev.id}`, "PAIR_REQUEST_GENERATED", dev.id, "64-bit QR code generated");

      return json({
        pair_code: pairCode,
        expires_at: Math.floor(pairExpires / 1000),
        device_id: dev.id,
        status: "PAIR_READY"
      });
    }

    // =========================================================================
    // 4. AGENT: Heartbeat & Command Polling (/api/agent/poll)
    // =========================================================================
    if (path === "agent/poll" && post) {
      const dev = await agent();
      const locked = typeof body.locked === "boolean" ? Number(body.locked) : null;
      const pinReady = Number(body.pin_ready === true);

      await db
        .prepare("UPDATE devices SET last_seen=?, locked=?, pin_ready=? WHERE id=?")
        .bind(now, locked, pinReady, dev.id)
        .run();

      // Vaxtı bitmiş köhnə əmrləri təmizlə
      await db
        .prepare("UPDATE commands SET state='expired', finished=? WHERE device_id=? AND state='queued' AND expires<?")
        .bind(now, dev.id, now)
        .run();

      // Növbədəki ən köhnə əmri atomik olaraq 'running' vəziyyətinə keçir
      const command = await one(
        "UPDATE commands SET state='running' WHERE id=(SELECT id FROM commands WHERE device_id=? AND state='queued' AND expires>=? ORDER BY created LIMIT 1) AND state='queued' RETURNING id, action, expires",
        dev.id,
        now
      );

      return json({ paired: true, command: command || null });
    }

    // =========================================================================
    // 5. AGENT: Əmr İcra Nəticəsi (/api/agent/result)
    // =========================================================================
    if (path === "agent/result" && post) {
      const dev = await agent();
      const commandId = String(body.command_id || "").trim();
      const isSuccess = body.success === true;
      const state = isSuccess ? "success" : "failed";
      const resultObj = JSON.stringify({
        status: String(body.status || "COMPLETED").slice(0, 100),
        attempt_id: String(body.attempt_id || "").slice(0, 80),
        ts: now
      });

      await db
        .prepare("UPDATE commands SET state=?, finished=?, result=? WHERE id=? AND device_id=? AND state='running'")
        .bind(state, now, resultObj, commandId, dev.id)
        .run();

      await logAudit(`agent:${dev.id}`, "COMMAND_RESULT", dev.id, `Command ${commandId} result: ${state}`);

      return json({ ok: true, status: state });
    }

    // =========================================================================
    // 6. AGENT: Telemetry & Error Ingest (/api/agent/telemetry)
    // =========================================================================
    if (path === "agent/telemetry" && post) {
      const dev = await agent();
      const level = String(body.level || "INFO").toUpperCase().slice(0, 10);
      const event = String(body.event || "UNKNOWN_EVENT").slice(0, 80);
      let details = typeof body.details === "object" ? JSON.stringify(body.details) : String(body.details || "");

      // Həssas məlumatların (PIN, açar, token) redaktəsi
      details = details
        .replace(/(pin["']?\s*[:=]\s*["']?)\d+/gi, "$1[REDACTED_PIN]")
        .replace(/(password["']?\s*[:=]\s*["']?)[^"'\s,}]+/gi, "$1[REDACTED]")
        .replace(/(secret["']?\s*[:=]\s*["']?)[a-f0-9]{16,}/gi, "$1[REDACTED]")
        .replace(/(token["']?\s*[:=]\s*["']?)[a-zA-Z0-9_\-]{16,}/gi, "$1[REDACTED]")
        .replace(/(nonce["']?\s*[:=]\s*["']?)[a-f0-9]{16,}/gi, "$1[REDACTED]");

      const tId = "tel_" + id().replace(/-/g, "").slice(0, 24);
      await db
        .prepare("INSERT INTO telemetry_events (id, device_id, level, event, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(tId, dev.id, level, event, details.slice(0, 1000), now)
        .run();

      return json({ ok: true, stored: true, id: tId });
    }

    // =========================================================================
    // 7. PUBLIC MOBILE: Kodla Cütləşmə (/api/pair) -- Persistent Rate Limit & 256-bit Token
    // =========================================================================
    if (path === "pair" && post) {
      // Persistent Rate Limiting yoxlanışı
      const rateRow = await one("SELECT attempts, blocked_until FROM pair_attempts WHERE client_ip=?", clientIp);
      if (rateRow && rateRow.blocked_until > now) {
        const retryAfter = Math.ceil((rateRow.blocked_until - now) / 1000);
        return json({
          error: "Çoxlu sayda uğursuz cəhd. Təhlükəsizlik üçün bloklandınız (E_RATE_LIMIT_EXCEEDED)",
          retry_after: retryAfter
        }, 429);
      }

      const rawCode = String(body.code || body.pair_code || "").trim();
      const cleanCode = rawCode.replace(/[-\s]/g, "").toUpperCase();
      if (cleanCode.length < 6) {
        error("Düzgün qoşulma kodunu daxil edin", 400);
      }

      const codeHash = await hash(cleanCode);

      // Atomik consume: Kodu yalnız etibarlı və aktiv olduqda istehlak edirik
      const matchedDevice = await one(
        "UPDATE devices SET pair_hash=NULL, pair_expires=NULL WHERE id=(SELECT id FROM devices WHERE pair_hash=? AND pair_expires>? AND status='ACTIVE' LIMIT 1) RETURNING id, name",
        codeHash,
        now
      );

      if (!matchedDevice) {
        const prevAttempts = (rateRow ? rateRow.attempts : 0) + 1;
        const blockedUntil = prevAttempts >= 5 ? now + 300000 : 0; // 5 uğursuz cəhd -> 300 saniyə blok
        await db
          .prepare(
            "INSERT INTO pair_attempts (client_ip, attempts, last_attempt, blocked_until) VALUES (?, ?, ?, ?) ON CONFLICT(client_ip) DO UPDATE SET attempts=?, last_attempt=?, blocked_until=?"
          )
          .bind(clientIp, prevAttempts, now, blockedUntil, prevAttempts, now, blockedUntil)
          .run();

        await logAudit(clientIp, "PAIR_FAILED", null, `Failed pair attempt ${prevAttempts}`);

        if (blockedUntil > 0) {
          return json({ error: "Çoxlu sayda uğursuz cəhd. Təhlükəsizlik üçün 5 dəqiqəlik bloklandı (E_RATE_LIMIT_EXCEEDED)" }, 429);
        }
        error("Qoşulma kodu yanlışdır, vaxtı bitib və ya artıq istifadə edilib (E_PAIR_CODE_NOT_FOUND)", 404);
      }

      // Uğurlu olduqda IP üçün blok və cəhd sayğacını sıfırla
      await db.prepare("DELETE FROM pair_attempts WHERE client_ip=?").bind(clientIp).run();

      // Device-scoped 256-bit Mobil Bearer Sessiyası verilir
      const sessionToken =
        "sess_" +
        crypto.randomUUID().replace(/-/g, "") +
        "_" +
        Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, "0")).join("");
      const sessionExpires = now + 86400000; // 24 saat etibarlılıq

      await db
        .prepare("INSERT INTO mobile_sessions (token, device_id, created_at, expires_at, scope) VALUES (?, ?, ?, ?, 'mobile_remote')")
        .bind(sessionToken, matchedDevice.id, now, sessionExpires)
        .run();

      await logAudit(`mobile:${matchedDevice.id}`, "DEVICE_PAIRED", matchedDevice.id, "Session created");

      return json({
        ok: true,
        device_id: matchedDevice.id,
        name: matchedDevice.name,
        session_token: sessionToken,
        expires_at: Math.floor(sessionExpires / 1000)
      });
    }

    // =========================================================================
    // 8. PUBLIC MOBILE & ADMIN: Uzaqdan Əmr Göndərilməsi (/api/commands)
    // =========================================================================
    if ((path === "commands" || (path.startsWith("devices/") && path.endsWith("/command"))) && post) {
      const action = String(body.action || "").trim().toLowerCase();
      if (!["unlock", "lock", "wake"].includes(action)) {
        error("Dəstəklənməyən əməliyyat növü", 400);
      }

      const parts = path.split("/");
      const targetDeviceId = (path === "commands" ? String(body.device_id || "") : parts[1]).trim();
      if (!targetDeviceId) error("Hədəf cihaz ID tələb olunur", 400);

      const dev = await one("SELECT * FROM devices WHERE id=?", targetDeviceId);
      if (!dev) error("Kompüter tapılmadı", 404);
      if (dev.status === "REVOKED") error("Kompüter sistemdən silinib və ya ləğv edilib (E_DEVICE_REVOKED)", 403);

      // İcazə yoxlanışı:
      // A: Mobil Sessiya (Device-scoped Bearer token)
      const mobSession = await getMobileSession(targetDeviceId);

      if (!mobSession && !isProjectOwner) {
        if (bearerToken.startsWith("sess_")) {
          error("Mobil sessiya etibarsızdır və ya cihaz revoke edilib (E_UNAUTHORIZED)", 401);
        }
        if (oaiUserId || oaiEmail) {
          error("İstifadəçilərə əmr göndərmə hüququ verilmir. Cihaz yalnız mobil sessiya və ya layihə sahibi tərəfindən idarə olunur (E_FORBIDDEN)", 403);
        }
        error("Giriş icazəsi yoxdur. Telefonla QR kodu oxudun və ya layihə sahibi kimi daxil olun (E_UNAUTHORIZED)", 401);
      }

      // Onlayn yoxlanışı (son 45 saniyə ərzində heartbeat)
      if (now - dev.last_seen > 45000) {
        error("Kompüter hazırda oflayndır (arxa plan xidməti ilə əlaqə kəsilib)", 409);
      }

      if (action === "unlock" && !dev.pin_ready) {
        error("Kompüterdə Windows PIN saxlanılmayıb. Əvvəlcə WinKey Desktop-da PIN-i qeyd edin.", 409);
      }

      // Mövcud aktiv əmr yoxlanışı (Anti-hammering)
      const activeCmd = await one(
        "SELECT id FROM commands WHERE device_id=? AND ((state='queued' AND expires>?) OR (state='running' AND created>?))",
        dev.id,
        now,
        now - 30000
      );
      if (activeCmd) {
        error("Əvvəlki əməliyyat hələ icra olunur, zəhmət olmasa gözləyin.", 409);
      }

      const cmdId = "cmd_" + id().replace(/-/g, "").slice(0, 24);
      const callerIdentity = mobSession ? `mobile:${mobSession.token.slice(0, 12)}` : (isProjectOwner ? (oaiUserId || oaiEmail || "owner") : "admin");

      await db
        .prepare(
          "INSERT INTO commands (id, device_id, owner, action, state, created, expires) VALUES (?, ?, ?, ?, 'queued', ?, ?)"
        )
        .bind(cmdId, dev.id, callerIdentity, action, now, now + 20000)
        .run();

      await logAudit(callerIdentity, "COMMAND_QUEUED", dev.id, `Action: ${action}, Id: ${cmdId}`);

      return json({ ok: true, command_id: cmdId, action, status: "queued" });
    }

    // =========================================================================
    // 9. PUBLIC MOBILE & ADMIN: Əmr Statusunun Yoxlanması (/api/commands/:id)
    // =========================================================================
    if (path.startsWith("commands/") && !post) {
      const cmdId = path.slice(9).trim();
      const row = await one("SELECT id, device_id, action, state, result, expires, created, finished FROM commands WHERE id=?", cmdId);
      if (!row) error("Əməliyyat tapılmadı", 404);

      const dev = await one("SELECT id, owner, status FROM devices WHERE id=?", row.device_id);
      if (!dev || dev.status === "REVOKED") {
        error("Cihaz tapılmadı və ya ləğv edilib (E_DEVICE_REVOKED)", 403);
      }

      const mobSession = await getMobileSession(row.device_id);

      if (!mobSession && !isProjectOwner) {
        error("İcazə yoxdur (E_UNAUTHORIZED)", 401);
      }

      if (row.state === "queued" && row.expires < now) {
        row.state = "expired";
      }
      return json(row);
    }

    // =========================================================================
    // 10. PUBLIC MOBILE: Cihaz Statusu (/api/mobile/status və ya /api/devices/:id)
    // =========================================================================
    if ((path === "mobile/status" || (path.startsWith("devices/") && !path.includes("/command"))) && !post) {
      const targetId = path === "mobile/status"
        ? String(new URL(request.url).searchParams.get("device_id") || "").trim()
        : path.slice(8).trim();

      const dev = await one("SELECT id, name, last_seen, locked, pin_ready, status, owner, created FROM devices WHERE id=?", targetId);
      if (!dev) error("Cihaz tapılmadı", 404);
      if (dev.status === "REVOKED") error("Cihaz ləğv edilib (E_DEVICE_REVOKED)", 403);

      const mobSession = await getMobileSession(targetId);

      if (!mobSession && !isProjectOwner) {
        error("Cihaz statusunu oxumaq üçün icazə tələb olunur (E_UNAUTHORIZED)", 401);
      }

      return json({
        id: dev.id,
        name: dev.name,
        last_seen: dev.last_seen,
        locked: dev.locked,
        pin_ready: dev.pin_ready,
        online: (now - dev.last_seen < 45000),
        status: dev.status
      });
    }

    // =========================================================================
    // 11. ADMIN / OWNER: Cihazlar Siyahısı (/api/devices)
    // =========================================================================
    if (path === "devices" && !post) {
      if (!isProjectOwner) {
        if (!oaiUserId && !oaiEmail && !isAdminToken) {
          error("Admin idarəetmə panelinə daxil olun (oai-authenticated-user-id tələb olunur)", 401);
        }
        // İctimai istifadəçilərə admin hüququ verilməsin!
        error("İstifadəçilərə admin hüququ verilmir. Cihazlar yalnız layihə sahibinin admin panelində görünür (E_FORBIDDEN_NOT_ADMIN)", 403);
      }

      // Layihə sahibinə bütün yeni və mövcud qeydiyyatdan keçmiş aktiv cihazlar görünür
      const rows = await all(
        "SELECT id, name, last_seen, locked, pin_ready, created, status, owner FROM devices WHERE status!='REVOKED' ORDER BY created DESC"
      );

      return json({ devices: rows, now });
    }

    // =========================================================================
    // 12. ADMIN / OWNER: Cihazı Sahiblənmə (/api/devices/claim)
    // =========================================================================
    if (path === "devices/claim" && post) {
      if (!isProjectOwner) error("Yalnız layihə sahibi cihazı sahiblənə bilər (E_FORBIDDEN)", 403);

      const targetDeviceId = String(body.device_id || "").trim();
      const pairCode = String(body.pair_code || "").replace(/[-\s]/g, "").toUpperCase();
      if (!targetDeviceId || !pairCode) error("device_id və pair_code məcburidir", 400);

      const pairH = await hash(pairCode);
      const dev = await one("SELECT id, owner, pair_hash, pair_expires, status FROM devices WHERE id=? AND status='ACTIVE'", targetDeviceId);
      if (!dev) error("Cihaz tapılmadı və ya qeydiyyatda deyil", 404);
      if (!dev.pair_hash || dev.pair_hash !== pairH || (dev.pair_expires && dev.pair_expires < now)) {
        error("Cihazın QR cütləşmə kodu yanlışdır və ya vaxtı bitib", 400);
      }

      await db
        .prepare("UPDATE devices SET owner=?, pair_hash=NULL, pair_expires=NULL WHERE id=?")
        .bind(ownerSiteId, dev.id)
        .run();

      await logAudit(ownerSiteId, "DEVICE_CLAIMED", dev.id, `Device bound to owner ${ownerSiteId}`);
      return json({ ok: true, device_id: dev.id, owner: ownerSiteId });
    }

    // =========================================================================
    // 13. ADMIN / OWNER: Əməliyyat Tarixçəsi (/api/history)
    // =========================================================================
    if (path === "history" && !post) {
      if (!isProjectOwner) {
        if (!oaiUserId && !oaiEmail && !isAdminToken) {
          error("Tarixçəyə baxış üçün icazə tələb olunur", 401);
        }
        error("İstifadəçilərə admin hüququ verilmir. Tarixçə yalnız layihə sahibinə açıqdır (E_FORBIDDEN_NOT_ADMIN)", 403);
      }

      const rows = await all(
        "SELECT c.id, c.action, c.state, c.created, c.finished, c.result, c.device_id, c.owner FROM commands c ORDER BY c.created DESC LIMIT 50"
      );

      return json({ commands: rows });
    }

    // =========================================================================
    // 14. ADMIN: Telemetriya və Auditin İzlənməsi (/api/admin/telemetry)
    // =========================================================================
    if (path === "admin/telemetry" && !post) {
      if (!isProjectOwner) {
        error("Telemetriyaya baxış yalnız layihə sahibinə məxsusdur (E_FORBIDDEN_NOT_ADMIN)", 403);
      }

      const rows = await all("SELECT * FROM telemetry_events ORDER BY timestamp DESC LIMIT 50");
      return json({ events: rows });
    }

    // =========================================================================
    // 15. Cihazın Revoke Edilməsi (/api/devices/revoke) -- Immediate Invalidation
    // =========================================================================
    if (path === "devices/revoke" && post) {
      const deviceId = String(body.device_id || "").trim();
      if (!deviceId) error("Cihaz ID tələb olunur", 400);

      const existingDev = await one("SELECT id, owner, status FROM devices WHERE id=?", deviceId);
      if (!existingDev) error("Cihaz tapılmadı (E_DEVICE_NOT_FOUND)", 404);

      let isAgentForThisDev = false;
      if (bearerToken.length >= 16) {
        const secH = await hash(bearerToken);
        const agentRow = await one("SELECT id FROM devices WHERE id=? AND secret_hash=? AND status='ACTIVE'", deviceId, secH);
        if (agentRow) isAgentForThisDev = true;
      }

      if (!isProjectOwner && !isAgentForThisDev) {
        error("Cihazı ləğv etmək hüququ yalnız layihə sahibinə və ya cihaz agentinə məxsusdur (E_FORBIDDEN_REVOKE)", 403);
      }

      // Qalıqsız ləğv: Status REVOKED edilir, bütün mobil tokenlər dərhal silinir
      await db.prepare("UPDATE devices SET status='REVOKED', pair_hash=NULL, pair_expires=NULL WHERE id=?").bind(deviceId).run();
      await db.prepare("DELETE FROM mobile_sessions WHERE device_id=?").bind(deviceId).run();

      await logAudit(
        isAdminToken ? "admin" : (oaiUserId || oaiEmail || `agent:${deviceId}`),
        "DEVICE_REVOKED",
        deviceId,
        "Device and all active sessions revoked immediately"
      );

      return json({ ok: true, status: "REVOKED", device_id: deviceId });
    }

    return json({ error: "Ünvan tapılmadı" }, 404);
  } catch (cause: any) {
    console.error("[API_ERROR]", cause);
    const status = Number(cause?.status) || 500;
    return json({ error: cause?.message || String(cause) }, status);
  }
}

export const GET = handle;
export const POST = handle;
export const OPTIONS = handle;
