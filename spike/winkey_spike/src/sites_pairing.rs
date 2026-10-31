// WinKey Pro — OS CSPRNG, Real Ed25519 Cihaz Açar Cütü, İmzalı Challenge, Gateway və Multi-Tenant İdarəetmə

use ed25519_dalek::{Signature, VerifyingKey};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PairingSession {
    pub session_id: String,
    pub bound_device_public_key: VerifyingKey,
    pub random_challenge_bytes: [u8; 32],
    pub expires_at_epoch: u64,
    pub is_claimed: Arc<AtomicBool>,
}

impl PairingSession {
    /// OS CSPRNG (Windows BCryptGenRandom) ilə 32 baytlıq təsadüfi challenge yaradır (REAL_API / CRYPTO).
    /// Cihazın public key-i sessiya yaradılarkən etibarlı kontekstə bağlanır!
    pub fn new_csprng_challenge(
        session_id: &str,
        bound_device_public_key: VerifyingKey,
        current_epoch: u64,
    ) -> Self {
        use rand::RngCore;
        let mut random_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut random_bytes);

        Self {
            session_id: session_id.to_string(),
            bound_device_public_key,
            random_challenge_bytes: random_bytes,
            expires_at_epoch: current_epoch + 120, // 120 saniyə etibarlılıq
            is_claimed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Kriptoqrafik imzalanmış challenge ilə pairing-i təsdiqləyir.
    /// DİQQƏT: Vaxt, format və imza yoxlaması UĞURLU OLDUQDAN SONRA atomik claim edilir.
    /// Səhv sorğu challenge-i yandırmır! now >= expires_at olduqda rədd edilir.
    pub fn claim_pairing(
        &self,
        current_epoch: u64,
        signature_bytes: &[u8],
    ) -> Result<(), &'static str> {
        // 1. Müddət yoxlaması: now >= expires_at olduqda rədd et
        if current_epoch >= self.expires_at_epoch {
            return Err("E_PAIRING_EXPIRED: 120 saniyəlik enrollment pəncərəsi bitib");
        }

        // 2. Format yoxlaması: İmza formatı düzgün olmalıdır
        let sig = Signature::from_slice(signature_bytes)
            .map_err(|_| "E_INVALID_SIGNATURE_FORMAT")?;

        // 3. Kriptoqrafik imza yoxlaması: Sessiyaya bağlanmış etibarlı public key ilə yoxlanılır!
        // Səhv/saxta imza olduqda is_claimed DƏYİŞMİR (challenge yanmır)
        self.bound_device_public_key
            .verify_strict(&self.random_challenge_bytes, &sig)
            .map_err(|_| "E_CHALLENGE_VERIFICATION_FAILED: Cihaz imzası challenge ilə uyğun gəlmir")?;

        // 4. Bütün yoxlamalar keçdikdən sonra atomik false -> true claim
        if self
            .is_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("E_PAIRING_ALREADY_CLAIMED: Bu birdəfəlik kod artıq istifadə edilib");
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ServerTokenRecord {
    pub token: String,
    pub bound_device_id: String,
    pub bound_user_id: String,
    pub expires_at_epoch: u64,
    pub is_revoked: bool,
}

pub struct ServerTokenManager {
    tokens: Mutex<HashMap<String, ServerTokenRecord>>,
}

impl ServerTokenManager {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue_token(&self, device_id: &str, user_id: &str, current_epoch: u64) -> String {
        use rand::RngCore;
        let mut token_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut token_bytes);
        let token_str = format!("tok_{}", hex::encode(token_bytes));

        let record = ServerTokenRecord {
            token: token_str.clone(),
            bound_device_id: device_id.to_string(),
            bound_user_id: user_id.to_string(),
            expires_at_epoch: current_epoch + 86400, // 24 saat
            is_revoked: false,
        };

        self.tokens.lock().unwrap().insert(token_str.clone(), record);
        token_str
    }

    pub fn revoke_token(&self, token_str: &str) {
        if let Some(record) = self.tokens.lock().unwrap().get_mut(token_str) {
            record.is_revoked = true;
        }
    }

    /// Server tərəfindən token və əməliyyat səlahiyyətinin doğrulanması
    pub fn authorize_request(
        &self,
        token_str: &str,
        target_device_id: &str,
        requested_action: &str,
        current_epoch: u64,
    ) -> Result<(), &'static str> {
        let tokens = self.tokens.lock().unwrap();
        let record = tokens.get(token_str).ok_or("E_TOKEN_NOT_FOUND")?;

        if record.is_revoked {
            return Err("E_TOKEN_REVOKED: Bu mobil token server tərəfindən ləğv edilib");
        }
        if current_epoch > record.expires_at_epoch {
            return Err("E_TOKEN_EXPIRED: Tokenin etibarlılıq müddəti bitib");
        }
        if requested_action.starts_with("ADMIN_") {
            return Err("E_FORBIDDEN_SCOPE: Mobil token inzibatçı hüquqlarına malik deyil");
        }
        if record.bound_device_id != target_device_id {
            return Err("E_IDOR_REJECTED: Mobil token başqa cihazın idarə edilməsi üçün istifadə edilə bilməz");
        }
        if requested_action != "LOCK" && requested_action != "UNLOCK" && requested_action != "STATUS" {
            return Err("E_INVALID_ACTION: Yalnız LOCK/UNLOCK/STATUS əmrləri icazəlidir");
        }

        Ok(())
    }
}

/// Çoxistifadəçili İzolyasiya Edilmiş Gateway (Multi-Tenant Device Gateway & Owner Admin)
#[derive(Debug, Clone)]
pub struct RegisteredDevice {
    pub device_id: String,
    pub name: String,
    pub owner_user_id: Option<String>,
    pub public_key: VerifyingKey,
    pub last_seen_epoch: u64,
    pub locked_status: Option<bool>,
    pub pin_ready: bool,
    pub app_version: String,
}

#[derive(Debug, Clone)]
pub struct GatewayCommand {
    pub command_id: String,
    pub device_id: String,
    pub sender_user_id: String,
    pub action: String,
    pub state: String, // "queued", "running", "success", "failed", "expired"
    pub created_epoch: u64,
    pub expires_epoch: u64,
    pub result: Option<String>,
}

pub struct MultiTenantGateway {
    pub devices: Mutex<HashMap<String, RegisteredDevice>>,
    pub commands: Mutex<HashMap<String, GatewayCommand>>,
    pub token_mgr: ServerTokenManager,
    pub owner_admin_token: String,
}

impl MultiTenantGateway {
    pub fn new(owner_admin_token: &str) -> Self {
        Self {
            devices: Mutex::new(HashMap::new()),
            commands: Mutex::new(HashMap::new()),
            token_mgr: ServerTokenManager::new(),
            owner_admin_token: owner_admin_token.to_string(),
        }
    }

    /// Cihazın ilkin qeydiyyatı (Agent Registration)
    pub fn register_device(
        &self,
        name: &str,
        public_key: VerifyingKey,
        current_epoch: u64,
    ) -> String {
        use rand::RngCore;
        let mut dev_id_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut dev_id_bytes);
        let device_id = format!("dev_{}", hex::encode_16(dev_id_bytes));

        let device = RegisteredDevice {
            device_id: device_id.clone(),
            name: name.to_string(),
            owner_user_id: None,
            public_key,
            last_seen_epoch: current_epoch,
            locked_status: Some(true),
            pin_ready: true,
            app_version: "1.0.0".to_string(),
        };

        self.devices.lock().unwrap().insert(device_id.clone(), device);
        device_id
    }

    /// Mobil QR cütləşməsi (Pairing Claim): Cihaz istifadəçiyə bağlanır
    pub fn complete_pairing(
        &self,
        device_id: &str,
        user_id: &str,
        current_epoch: u64,
    ) -> Result<String, &'static str> {
        let mut devs = self.devices.lock().unwrap();
        let dev = devs.get_mut(device_id).ok_or("E_DEVICE_NOT_FOUND")?;

        if dev.owner_user_id.is_some() && dev.owner_user_id.as_deref() != Some(user_id) {
            return Err("E_DEVICE_ALREADY_OWNED: Bu cihaz artıq başqa istifadəçiyə bağlıdır");
        }

        dev.owner_user_id = Some(user_id.to_string());
        dev.last_seen_epoch = current_epoch;

        let token = self.token_mgr.issue_token(device_id, user_id, current_epoch);
        Ok(token)
    }

    /// Əmr göndərilməsi (Tenant Isolation / IDOR Qoruması)
    pub fn submit_command(
        &self,
        token: &str,
        target_device_id: &str,
        action: &str,
        current_epoch: u64,
    ) -> Result<String, &'static str> {
        // 1. Token hüquqlarının yoxlanılması (E_IDOR_REJECTED / E_TOKEN_EXPIRED və s.)
        self.token_mgr.authorize_request(token, target_device_id, action, current_epoch)?;

        let devs = self.devices.lock().unwrap();
        let dev = devs.get(target_device_id).ok_or("E_DEVICE_NOT_FOUND")?;

        // 2. Tenant isolation yoxlanışı
        let tokens = self.token_mgr.tokens.lock().unwrap();
        let tok_rec = tokens.get(token).ok_or("E_TOKEN_NOT_FOUND")?;
        if dev.owner_user_id.as_deref() != Some(&tok_rec.bound_user_id) {
            return Err("E_CROSS_TENANT_IDOR_REJECTED: Başqa istifadəçinin cihazına əmr göndərmək qadağandır");
        }

        use rand::RngCore;
        let mut cmd_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut cmd_bytes);
        let cmd_id = format!("cmd_{}", hex::encode_16(cmd_bytes));

        let cmd = GatewayCommand {
            command_id: cmd_id.clone(),
            device_id: target_device_id.to_string(),
            sender_user_id: tok_rec.bound_user_id.clone(),
            action: action.to_string(),
            state: "queued".to_string(),
            created_epoch: current_epoch,
            expires_epoch: current_epoch + 30, // 30 saniyə
            result: None,
        };

        self.commands.lock().unwrap().insert(cmd_id.clone(), cmd);
        Ok(cmd_id)
    }

    /// Kompüter agentinin növbədəki əmri götürməsi (Agent Polling)
    pub fn agent_poll_command(&self, device_id: &str, current_epoch: u64) -> Option<GatewayCommand> {
        let mut devs = self.devices.lock().unwrap();
        if let Some(dev) = devs.get_mut(device_id) {
            dev.last_seen_epoch = current_epoch;
        }

        let mut cmds = self.commands.lock().unwrap();
        for cmd in cmds.values_mut() {
            if cmd.device_id == device_id && cmd.state == "queued" {
                if current_epoch > cmd.expires_epoch {
                    cmd.state = "expired".to_string();
                } else {
                    cmd.state = "running".to_string();
                    return Some(cmd.clone());
                }
            }
        }
        None
    }

    /// Kompüter agentinin əmr nəticəsini təqdim etməsi
    pub fn agent_submit_result(
        &self,
        device_id: &str,
        command_id: &str,
        success: bool,
        status: &str,
    ) -> Result<(), &'static str> {
        let mut cmds = self.commands.lock().unwrap();
        let cmd = cmds.get_mut(command_id).ok_or("E_COMMAND_NOT_FOUND")?;

        if cmd.device_id != device_id {
            return Err("E_COMMAND_DEVICE_MISMATCH");
        }

        cmd.state = if success { "success".to_string() } else { "failed".to_string() };
        cmd.result = Some(status.to_string());
        Ok(())
    }

    /// YALNIZ SAHİBƏ AÇIQ İNZİBATÇI GÖRÜNÜŞÜ (Owner-Only Admin Surface)
    /// DİQQƏT: Admində PC adı, status, son görünmə, versiya görünür, PIN QƏTİYYƏN YOXDUR!
    pub fn owner_admin_view_devices(
        &self,
        provided_admin_token: &str,
    ) -> Result<Vec<(String, String, Option<String>, u64, String)>, &'static str> {
        if provided_admin_token != self.owner_admin_token {
            return Err("E_ADMIN_UNAUTHORIZED: Yalnız layihə sahibi admin panelinə daxil ola bilər");
        }

        let devs = self.devices.lock().unwrap();
        let list = devs.values().map(|d| {
            (
                d.device_id.clone(),
                d.name.clone(),
                d.owner_user_id.clone(),
                d.last_seen_epoch,
                d.app_version.clone(),
            )
        }).collect();

        Ok(list)
    }
}

pub fn get_current_epoch_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// Sadə hex helper (əlavə asılılıqsız)
pub mod hex {
    pub fn encode(data: [u8; 24]) -> String {
        let mut s = String::with_capacity(48);
        for b in data {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    pub fn encode_16(data: [u8; 16]) -> String {
        let mut s = String::with_capacity(32);
        for b in data {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}
