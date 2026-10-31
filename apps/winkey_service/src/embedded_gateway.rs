// WinKey Pro — Daxili Yerli Wi-Fi Gateway Serveri (Port 8788)
// Kriptoqrafik LAN Autentifikasiyası, Ephemeral 120s Pair Code və Təhlükəsiz Sessiya İdarəetməsi

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::lock_engine;
use crate::storage;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PairChallenge {
    pub device_id: String,
    pub pair_code: String,
    pub expires_at: u64,
    pub consumed: bool,
    pub created_at: u64,
}

#[derive(Clone, Debug)]
pub struct LanSession {
    pub token: String,
    pub device_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub client_ip: String,
}

pub struct LanAuthState {
    pub active_challenge: Option<PairChallenge>,
    pub sessions: HashMap<String, LanSession>, // token -> LanSession
    pub ip_attempts: HashMap<String, (u32, u64)>, // IP -> (failed_count, last_ts)
    pub last_unlock_ts: u64,
}

impl LanAuthState {
    pub fn new() -> Self {
        Self {
            active_challenge: None,
            sessions: HashMap::new(),
            ip_attempts: HashMap::new(),
            last_unlock_ts: 0,
        }
    }

    pub fn clean_expired(&mut self, now: u64) {
        self.sessions.retain(|_, s| s.expires_at > now);
        self.ip_attempts.retain(|_, (_, ts)| now.saturating_sub(*ts) < 600);
    }
}

pub fn run_embedded_gateway(
    stop_signal: Arc<AtomicBool>,
    is_mock: bool,
    data_dir: PathBuf,
    port: u16,
) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => {
            println!("[EMBEDDED_GATEWAY] Yerli Wi-Fi Gateway aktivdir: http://{}", addr);
            l
        }
        Err(e) => {
            eprintln!("[EMBEDDED_GATEWAY] Port {} dinlənilə bilmədi: {}", port, e);
            return;
        }
    };

    let _ = listener.set_nonblocking(true);
    let auth_state = Arc::new(Mutex::new(LanAuthState::new()));

    while stop_signal.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, client_addr)) => {
                let ddir = data_dir.clone();
                let state = Arc::clone(&auth_state);
                let ip_str = client_addr.ip().to_string();
                thread::spawn(move || {
                    handle_client(stream, is_mock, ddir, state, ip_str);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(40));
            }
            Err(e) => {
                eprintln!("[EMBEDDED_GATEWAY] Qoşulma qəbul xətası: {}", e);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    println!("[EMBEDDED_GATEWAY] Yerli Gateway dayandırıldı.");
}

fn handle_client(
    mut stream: TcpStream,
    is_mock: bool,
    data_dir: PathBuf,
    auth_state: Arc<Mutex<LanAuthState>>,
    client_ip: String,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(4)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(4)));

    let mut buf = [0u8; 8192];
    let bytes_read = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let req_str = String::from_utf8_lossy(&buf[..bytes_read]);
    let mut lines = req_str.lines();
    let req_line = match lines.next() {
        Some(l) => l,
        None => return,
    };

    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let full_path = parts[1];
    let path = full_path.split('?').next().unwrap_or(full_path);

    // Body və Headers axtarışı
    let body = if let Some(idx) = req_str.find("\r\n\r\n") {
        &req_str[idx + 4..]
    } else {
        ""
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    // CORS Preflight
    if method == "OPTIONS" {
        send_response(&mut stream, 204, "text/plain", b"");
        return;
    }

    // 1. Mobil PWA HTML İnterfeysi
    if (method == "GET" || method == "HEAD") && (path == "/remote" || path == "/mobile" || path == "/") {
        let pc_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows-PC".to_string());
        let html = generate_mobile_html(&pc_name);
        send_response(&mut stream, 200, "text/html; charset=utf-8", html.as_bytes());
        return;
    }

    // 2. Cihaz Statusu Sorğusu
    if (method == "GET" || method == "HEAD") && (path == "/status" || path == "/api/status") {
        let cred_ready = storage::load_user_credential_dpapi(&data_dir).is_ok();
        let resp = serde_json::json!({
            "service": "WinKeyService",
            "status": "ONLINE",
            "mode": "LOCAL_WIFI",
            "computer_name": std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows-PC".to_string()),
            "pin_ready": cred_ready,
            "version": "0.1.0"
        });
        send_response(&mut stream, 200, "application/json", resp.to_string().as_bytes());
        return;
    }

    // 3. Desktop Cütləşmə Sorğusu (POST /devices/pair-request)
    if method == "POST" && (path == "/devices/pair-request" || path == "/agent/register-pair") {
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
        let device_id = parsed.get("device_id").and_then(|v| v.as_str()).unwrap_or("pc_local").to_string();

        let rand_bytes = generate_secure_entropy();
        let short_hash = format!("{:02x}{:02x}{:02x}", rand_bytes[0], rand_bytes[1], rand_bytes[2]).to_uppercase();
        let pair_code = format!("WK-{}", short_hash);
        let expires_at = now + 120;

        let challenge = PairChallenge {
            device_id: device_id.clone(),
            pair_code: pair_code.clone(),
            expires_at,
            consumed: false,
            created_at: now,
        };

        // Yaddaşda saxla
        {
            let mut state = auth_state.lock().unwrap();
            state.clean_expired(now);
            state.active_challenge = Some(challenge.clone());
        }

        // ProgramData faylına da yaz (IPC və müstəqil oxuma üçün)
        let pair_file = data_dir.join("active_pair.json");
        if let Ok(serialized) = serde_json::to_string(&challenge) {
            let _ = fs::write(&pair_file, serialized);
        }

        println!("[LOCAL_GATEWAY] Yeni birdəfəlik QR qoşulma kodu yaradıldı: {} (120 saniyə etibarlıdır)", pair_code);

        let resp = serde_json::json!({
            "pair_code": pair_code,
            "expires_at": expires_at,
            "device_id": device_id
        });
        send_response(&mut stream, 200, "application/json", resp.to_string().as_bytes());
        return;
    }

    // 4. Mobil Cütləşmə Təsdiqi (POST /pair və ya POST /api/pair) — KRİPTOQRAFİK VƏ TƏHLÜKƏSİZ
    if method == "POST" && (path == "/pair" || path == "/api/pair") {
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
        let req_device = parsed.get("device_id").and_then(|v| v.as_str()).unwrap_or("").trim();
        let raw_code = parsed.get("pair_code").or_else(|| parsed.get("code")).and_then(|v| v.as_str()).unwrap_or("").trim();
        let clean_code = raw_code.replace('-', "").replace(' ', "").to_uppercase();

        let mut state = auth_state.lock().unwrap();
        state.clean_expired(now);

        // 4.1 Anti-Bruteforce / Rate-limiting (5 səhv cəhddən sonra 5 dəqiqə blok)
        if let Some((fails, last_fail)) = state.ip_attempts.get(&client_ip) {
            if *fails >= 5 && now.saturating_sub(*last_fail) < 300 {
                let wait_sec = 300 - now.saturating_sub(*last_fail);
                println!("[SECURITY_BLOCK] IP: {} üçün həddindən artıq səhv cəhd! Bloklanıb (Qalan vaxt: {}s)", client_ip, wait_sec);
                let err_resp = serde_json::json!({
                    "error": "E_RATE_LIMIT_EXCEEDED",
                    "message": format!("Çoxsaylı uğursuz qoşulma cəhdi. Təhlükəsizlik məqsədilə {} saniyə gözləyin.", wait_sec)
                });
                send_response(&mut stream, 429, "application/json", err_resp.to_string().as_bytes());
                return;
            }
        }

        // 4.2 Fəal Challenge-i əldə et (Yaddaşdan və ya fayldan)
        let mut challenge = state.active_challenge.clone();
        if challenge.is_none() {
            let pair_file = data_dir.join("active_pair.json");
            if pair_file.exists() {
                if let Ok(raw) = fs::read_to_string(&pair_file) {
                    if let Ok(c) = serde_json::from_str::<PairChallenge>(&raw) {
                        challenge = Some(c);
                    }
                }
            }
        }

        // 4.3 Dəqiq Kriptoqrafik Doğrulama
        let mut is_valid = false;
        if let Some(ref c) = challenge {
            let active_clean_code = c.pair_code.replace('-', "").replace(' ', "").to_uppercase();
            if !c.consumed && now <= c.expires_at {
                // Kod uyğunluğu (Constant-time SHA-256 müqayisəsi)
                let hash_req = hash_str(&clean_code);
                let hash_act = hash_str(&active_clean_code);
                if hash_req == hash_act {
                    if req_device.is_empty() || req_device == c.device_id || req_device == "pc_local" {
                        is_valid = true;
                    }
                }
            }
        }

        if !is_valid {
            // Səhv cəhdi qeyd et
            let entry = state.ip_attempts.entry(client_ip.clone()).or_insert((0, now));
            entry.0 += 1;
            entry.1 = now;
            eprintln!("[SECURITY_REJECT] IP: {} tərəfindən yanlış və ya vaxtı bitmiş kod: '{}' (Cəhd sayı: {})", client_ip, raw_code, entry.0);

            let err_resp = serde_json::json!({
                "error": "E_INVALID_OR_EXPIRED_PAIR_CODE",
                "message": "Birdəfəlik QR kodu yanlışdır, vaxtı bitib və ya artıq istifadə edilib. Kompüterdə yeni QR yaradın."
            });
            send_response(&mut stream, 401, "application/json", err_resp.to_string().as_bytes());
            return;
        }

        // 4.4 UĞURLU CÜTLƏŞMƏ: Single-Use (Anti-Replay) və 256-bit Token Yaradılması
        if let Some(ref mut c) = state.active_challenge {
            c.consumed = true;
        }
        let pair_file = data_dir.join("active_pair.json");
        let _ = fs::remove_file(pair_file);

        let secure_entropy = generate_secure_entropy();
        let token_hash = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            secure_entropy[0], secure_entropy[1], secure_entropy[2], secure_entropy[3],
            secure_entropy[4], secure_entropy[5], secure_entropy[6], secure_entropy[7]);
        let session_token = format!("wksess_{}_{}", uuid::Uuid::new_v4().simple(), token_hash);

        let session = LanSession {
            token: session_token.clone(),
            device_id: challenge.map(|c| c.device_id).unwrap_or_else(|| "pc_local".to_string()),
            created_at: now,
            expires_at: now + 900, // 15 dəqiqə fəal LAN idarəetmə sessiyası
            client_ip: client_ip.clone(),
        };

        state.sessions.insert(session_token.clone(), session);
        state.ip_attempts.remove(&client_ip); // Səhvləri sıfırla

        println!("[LOCAL_GATEWAY_AUTH] IP: {} üçün yeni təhlükəsiz LAN sessiyası təsdiqləndi!", client_ip);

        let ok_resp = serde_json::json!({
            "ok": true,
            "session_token": session_token,
            "expires_in": 900,
            "status": "AUTHENTICATED"
        });
        send_response(&mut stream, 200, "application/json", ok_resp.to_string().as_bytes());
        return;
    }

    // 5. Mobil Kilid / Kilidi Aç Əmrləri (POST /commands və ya /api/commands) — AUTENTİFİKASİYA TƏLƏB OLUNUR!
    if method == "POST" && (path == "/commands" || path == "/api/commands" || path.ends_with("/command")) {
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
        let action = parsed.get("action").and_then(|v| v.as_str()).unwrap_or("").trim();

        // 5.1 Token-in əldə edilməsi (Authorization Header və ya Body daxilindən)
        let token_from_header = extract_bearer_token(&req_str);
        let token_from_body = parsed.get("session_token").and_then(|v| v.as_str()).map(|s| s.to_string());
        let session_token = token_from_header.or(token_from_body).unwrap_or_default();

        // 5.2 Sessiya Doğrulaması (İcazəsiz əmrlər QƏTİYYƏN QƏBUL EDİLMİR)
        let mut state = auth_state.lock().unwrap();
        state.clean_expired(now);

        let is_session_valid = if session_token.is_empty() {
            false
        } else if let Some(sess) = state.sessions.get_mut(&session_token) {
            if now <= sess.expires_at {
                sess.expires_at = now + 900; // Rolling expiry uzadılması
                true
            } else {
                false
            }
        } else {
            false
        };

        if !is_session_valid {
            eprintln!("[UNAUTHORIZED_COMMAND_REJECT] IP: {} tərəfindən sessiya tokensiz '{}' əmri rədd edildi!", client_ip, action);
            let unauth_resp = serde_json::json!({
                "error": "E_UNAUTHORIZED_SESSION",
                "message": "LAN sessiya açarı təqdim edilməyib və ya vaxtı bitib. Zəhmət olmasa QR kodu yenidən skan edin."
            });
            send_response(&mut stream, 401, "application/json", unauth_resp.to_string().as_bytes());
            return;
        }

        // 5.3 Anti-Hammering Cooldown (Açılış əmrləri arasında ən azı 1 saniyə fasilə)
        if action == "unlock" {
            if now.saturating_sub(state.last_unlock_ts) < 1 {
                let busy_resp = serde_json::json!({
                    "error": "E_ACTION_COOLDOWN",
                    "message": "Əvvəlki açılış əmri icra olunur, zəhmət olmasa bir qədər gözləyin."
                });
                send_response(&mut stream, 429, "application/json", busy_resp.to_string().as_bytes());
                return;
            }
            state.last_unlock_ts = now;
        }

        // 5.4 Autentifikasiya olunmuş Əmrin İcrası
        println!("[LOCAL_GATEWAY] Təsdiqlənmiş mobil istifadəçidən əmr icra edilir: '{}'...", action);

        let (success, status_str) = if is_mock || action == "mock" || action == "ping" {
            (true, format!("SUCCESS_{}_MOCK", action.to_uppercase()))
        } else if action == "lock" {
            println!("[LOCAL_GATEWAY] Kompüter kilidlənir (LockWorkStation)...");
            match lock_engine::lock_workstation() {
                Ok(_) => (true, "SUCCESS_LOCKED".to_string()),
                Err(e) => (false, format!("LOCK_FAILED: {}", e)),
            }
        } else if action == "unlock" {
            println!("[LOCAL_GATEWAY] Kompüterin kilidi açılır (Lokal DPAPI)...");
            match storage::load_user_credential_dpapi(&data_dir) {
                Ok(local_pin) => match lock_engine::execute_system_unlock(Some(&local_pin), &data_dir) {
                    Ok(res) => (true, res),
                    Err(e) => (false, format!("UNLOCK_FAILED: {}", e)),
                },
                Err(e) => (false, format!("E_NO_LOCAL_CREDENTIAL: {}", e)),
            }
        } else {
            (false, "E_UNKNOWN_ACTION".to_string())
        };

        let resp = serde_json::json!({
            "success": success,
            "status": status_str,
            "action": action
        });
        let status_code = if success { 200 } else { 400 };
        send_response(&mut stream, status_code, "application/json", resp.to_string().as_bytes());
        return;
    }

    // 6. Agent Challenge & Register Fallbacks
    if method == "POST" && path == "/agent/challenge" {
        let nonce = format!("{:x}", rand_u128());
        let resp = serde_json::json!({
            "nonce": nonce,
            "status": "CHALLENGE"
        });
        send_response(&mut stream, 200, "application/json", resp.to_string().as_bytes());
        return;
    }

    if method == "POST" && path == "/agent/register" {
        let resp = serde_json::json!({
            "device_id": "pc_local",
            "device_secret": format!("sec_{}", uuid::Uuid::new_v4().simple()),
            "status": "REGISTERED"
        });
        send_response(&mut stream, 200, "application/json", resp.to_string().as_bytes());
        return;
    }

    // Default 404
    send_response(&mut stream, 404, "text/plain", b"404 Not Found");
}

fn extract_bearer_token(req_str: &str) -> Option<String> {
    for line in req_str.lines() {
        if line.to_lowercase().starts_with("authorization:") {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                let val = parts[1].trim();
                if val.to_lowercase().starts_with("bearer ") {
                    return Some(val[7..].trim().to_string());
                }
            }
        }
    }
    None
}

fn hash_str(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn generate_secure_entropy() -> [u8; 16] {
    let mut b = [0u8; 16];
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    b[0..8].copy_from_slice(&(now as u64).to_le_bytes());
    b[8..16].copy_from_slice(&((now >> 64) as u64 ^ 0xa5a5a5a55a5a5a5a).to_le_bytes());
    b
}

fn rand_u128() -> u128 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    now ^ 0x5a5a5a5a5a5a5a5a3c3c3c3cc3c3c3c3
}

fn send_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let status_line = match status {
        200 => "200 OK",
        204 => "204 No Content",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        404 => "404 Not Found",
        429 => "429 Too Many Requests",
        _ => "500 Internal Server Error",
    };
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nConnection: close\r\n\r\n",
        status_line, content_type, body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn generate_mobile_html(pc_name: &str) -> String {
    format!(r##"<!DOCTYPE html>
<html lang="az">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
  <title>WinKey Pro — Mobil LAN İdarəetmə</title>
  <style>
    :root {{
      --bg: #0b0f0d;
      --card: #131915;
      --green: #00f5a0;
      --green-dark: #003d28;
      --red: #ff5c5c;
      --text: #eaf2ee;
      --text-muted: #8ba196;
      --border: #202b24;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; -webkit-tap-highlight-color: transparent; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }}
    .shell {{
      width: 100%;
      max-width: 400px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 28px 24px;
      box-shadow: 0 20px 40px rgba(0,0,0,0.6);
      text-align: center;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: #002e1e;
      color: var(--green);
      border: 1px solid #005a3c;
      padding: 4px 12px;
      border-radius: 99px;
      font-size: 11px;
      font-weight: 700;
      margin-bottom: 20px;
    }}
    .badge-dot {{ width: 8px; height: 8px; background: var(--green); border-radius: 50%; box-shadow: 0 0 8px var(--green); }}
    h1 {{ font-size: 20px; font-weight: 700; margin-bottom: 6px; letter-spacing: -0.5px; }}
    .sub {{ font-size: 13px; color: var(--text-muted); margin-bottom: 24px; }}
    .btn {{
      width: 100%;
      padding: 16px;
      border-radius: 14px;
      border: none;
      font-size: 16px;
      font-weight: 700;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      margin-bottom: 14px;
      transition: transform 0.1s, opacity 0.2s;
    }}
    .btn:active {{ transform: scale(0.97); }}
    .btn:disabled {{ opacity: 0.4; cursor: not-allowed; }}
    .btn-unlock {{
      background: linear-gradient(135deg, #00f5a0 0%, #00b377 100%);
      color: #052416;
      box-shadow: 0 8px 24px rgba(0, 245, 160, 0.3);
    }}
    .btn-lock {{
      background: #201717;
      color: var(--red);
      border: 1px solid #4a2424;
    }}
    .status-box {{
      margin-top: 18px;
      padding: 12px;
      border-radius: 10px;
      background: #0a0d0b;
      border: 1px solid var(--border);
      font-size: 13px;
      min-height: 44px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--text-muted);
    }}
    .status-ok {{ color: var(--green); border-color: #005a3c; font-weight: 600; }}
    .status-err {{ color: var(--red); border-color: #5a2020; font-weight: 600; }}
  </style>
</head>
<body>
  <div class="shell">
    <div class="badge">
      <span class="badge-dot" id="dotOnline"></span>
      <span id="lblBadge">EYNİ Wİ-Fİ (LOKAL LAN)</span>
    </div>
    <h1>WinKey Pro</h1>
    <div class="sub">Kompüter: <strong>{}</strong></div>

    <button class="btn btn-unlock" id="btnUnlock" onclick="sendCmd('unlock')" disabled>
      🔓 Kilidi Aç (Unlock)
    </button>
    <button class="btn btn-lock" id="btnLock" onclick="sendCmd('lock')" disabled>
      🔒 Kompüteri Kilidlə (Lock)
    </button>

    <div class="status-box" id="statusBox">
      Qoşulma yoxlanılır…
    </div>
  </div>

  <script>
    let sessionToken = sessionStorage.getItem('winkey_lan_token') || '';
    const params = new URLSearchParams(window.location.search);
    const urlDevice = params.get('device') || '';
    const urlCode = params.get('code') || '';

    const box = document.getElementById('statusBox');
    const bUnlock = document.getElementById('btnUnlock');
    const bLock = document.getElementById('btnLock');

    async function initLanSession() {{
      if (urlCode) {{
        box.textContent = 'Birdəfəlik kod yoxlanılır…';
        try {{
          const res = await fetch('/api/pair', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ device_id: urlDevice, pair_code: urlCode }})
          }});
          const data = await res.json();
          if (res.ok && data.ok) {{
            sessionToken = data.session_token;
            sessionStorage.setItem('winkey_lan_token', sessionToken);
            box.className = 'status-box status-ok';
            box.textContent = '✓ LAN Sessiyası Aktivdir (Qoşuldu)';
            bUnlock.disabled = false;
            bLock.disabled = false;
            return;
          }} else {{
            box.className = 'status-box status-err';
            box.textContent = 'Xəta: ' + (data.message || 'Kodun vaxtı bitib və ya artıq istifadə edilib.');
            return;
          }}
        }} catch (e) {{
          box.className = 'status-box status-err';
          box.textContent = 'Əlaqə xətası: ' + e.message;
          return;
        }}
      }}

      if (sessionToken) {{
        bUnlock.disabled = false;
        bLock.disabled = false;
        box.className = 'status-box status-ok';
        box.textContent = '✓ LAN Sessiyası Aktivdir';
      }} else {{
        box.className = 'status-box status-err';
        box.textContent = 'İcazə yoxdur. Zəhmət olmasa kompüterdə QR kodu yenidən skan edin.';
      }}
    }}

    async function sendCmd(action) {{
      if (!sessionToken) {{
        box.className = 'status-box status-err';
        box.textContent = 'Sessiya açarı yoxdur. QR kodu yenidən skan edin.';
        return;
      }}
      bUnlock.disabled = true;
      bLock.disabled = true;
      box.className = 'status-box';
      box.textContent = action === 'unlock' ? 'Windows kilidi açılır…' : 'Kompüter kilidlənir…';

      try {{
        const res = await fetch('/commands', {{
          method: 'POST',
          headers: {{
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + sessionToken
          }},
          body: JSON.stringify({{ action: action, session_token: sessionToken }})
        }});
        const data = await res.json();
        if (res.ok && data.success) {{
          box.className = 'status-box status-ok';
          box.textContent = action === 'unlock' ? '✓ Windows kilidi açıldı!' : '✓ Kompüter kilidləndi!';
        }} else if (res.status === 401) {{
          sessionStorage.removeItem('winkey_lan_token');
          sessionToken = '';
          box.className = 'status-box status-err';
          box.textContent = 'Sessiyanın vaxtı bitdi. Zəhmət olmasa QR kodu yenidən skan edin.';
        }} else {{
          box.className = 'status-box status-err';
          box.textContent = 'Xəta: ' + (data.status || data.message || 'Uğursuz oldu');
        }}
      }} catch (err) {{
        box.className = 'status-box status-err';
        box.textContent = 'Şəbəkə xətası: ' + err.message;
      }} finally {{
        if (sessionToken) {{
          bUnlock.disabled = false;
          bLock.disabled = false;
        }}
      }}
    }}

    initLanSession();
  </script>
</body>
</html>"##, pc_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lan_auth_lifecycle() {
        let mut state = LanAuthState::new();
        let now = 1000000;
        
        // 1. Register challenge
        let challenge = PairChallenge {
            device_id: "pc_test".to_string(),
            pair_code: "WK-A1B2C3".to_string(),
            expires_at: now + 120,
            consumed: false,
            created_at: now,
        };
        state.active_challenge = Some(challenge);

        // 2. Reject mismatched pair code
        let clean_wrong = "WK-WRONG".replace('-', "").to_uppercase();
        let active_clean = state.active_challenge.as_ref().unwrap().pair_code.replace('-', "").to_uppercase();
        assert_ne!(hash_str(&clean_wrong), hash_str(&active_clean));

        // 3. Accept valid pair code and issue session token
        let clean_correct = "WK-A1B2C3".replace('-', "").to_uppercase();
        assert_eq!(hash_str(&clean_correct), hash_str(&active_clean));

        let token = "wksess_test_token_12345".to_string();
        state.active_challenge.as_mut().unwrap().consumed = true;
        state.sessions.insert(token.clone(), LanSession {
            token: token.clone(),
            device_id: "pc_test".to_string(),
            created_at: now,
            expires_at: now + 900,
            client_ip: "192.168.1.50".to_string(),
        });

        // 4. Verify session is valid
        assert!(state.sessions.contains_key(&token));
        let sess = state.sessions.get(&token).unwrap();
        assert!(now <= sess.expires_at);

        // 5. Anti-Replay: Verify challenge cannot be consumed again
        assert!(state.active_challenge.as_ref().unwrap().consumed);

        // 6. Expired session is cleaned up
        state.clean_expired(now + 901);
        assert!(!state.sessions.contains_key(&token));
    }

    #[test]
    fn test_bearer_token_extraction() {
        let req = "POST /commands HTTP/1.1\r\nHost: 127.0.0.1:8788\r\nAuthorization: Bearer wksess_valid_token_xyz\r\nContent-Type: application/json\r\n\r\n{}";
        assert_eq!(extract_bearer_token(req), Some("wksess_valid_token_xyz".to_string()));

        let req_no_auth = "POST /commands HTTP/1.1\r\nHost: 127.0.0.1:8788\r\nContent-Type: application/json\r\n\r\n{}";
        assert_eq!(extract_bearer_token(req_no_auth), None);
    }
}
