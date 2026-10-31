from pathlib import Path
p = Path('apps/desktop_tauri/src-tauri/src/main.rs')
s = p.read_text(encoding='utf-8')
a = s.index('    let origin = cfg_val.get("gateway_origin")', s.index('fn generate_qr_pairing'))
b = s.index('    // Mobil qoşulma üçün real LAN IP', a)
s = s[:a] + r'''
    // Dev Run origin takes precedence over stale config from previous builds.
    let origin = std::env::var("WINKEY_GATEWAY_ORIGIN").ok()
        .or_else(|| cfg_val.get("gateway_origin").and_then(|v| v.as_str()).map(String::from))
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "E_GATEWAY_NOT_CONFIGURED".to_string())?
        .trim().trim_end_matches('/').to_string();
    let request = |path: &str, payload: serde_json::Value, token: Option<&str>| -> Result<serde_json::Value, String> {
        eprintln!("[PAIRING] POST {} started", path);
        let mut req = ureq::post(&format!("{}{}", origin, path))
            .timeout(std::time::Duration::from_secs(4));
        if let Some(t) = token { req = req.set("Authorization", &format!("Bearer {}", t)); }
        match req.send_json(payload) {
            Ok(resp) => {
                eprintln!("[PAIRING] POST {} HTTP={}", path, resp.status());
                resp.into_json().map_err(|_| format!("E_RESPONSE_JSON {}", path))
            }
            Err(ureq::Error::Status(status, resp)) => {
                let body = resp.into_json::<serde_json::Value>().unwrap_or_default();
                let code = body.get("error").and_then(|v| v.as_str()).unwrap_or("E_GATEWAY_RESPONSE");
                eprintln!("[PAIRING] POST {} HTTP={} code={}", path, status, code);
                Err(format!("{} HTTP={} {}", path, status, code))
            }
            Err(_) => { eprintln!("[PAIRING] POST {} transport/timeout failure", path); Err(format!("E_GATEWAY_CONNECTION {}", path)) }
        }
    };
    let (signing_key, verifying_key) = get_or_create_device_keypair()?;
    let public_key_hex = verifying_key.to_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let device_id = format!("pc_{}", &public_key_hex[..24]);
    let computer_name = cfg_val.get("computer_name").and_then(|v| v.as_str()).map(String::from)
        .unwrap_or_else(|| std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows-PC".to_string()));
    let secret_file = get_app_data_dir().join("device_secret.dpapi");
    let old_secret = if cfg_val.get("device_id").and_then(|v| v.as_str()) == Some(device_id.as_str()) {
        fs::read(&secret_file).ok().and_then(|b| dpapi_unprotect(&b).ok()).and_then(|b| String::from_utf8(b).ok())
    } else { None };
    let secret = if let Some(secret) = old_secret {
        secret
    } else {
        let challenge = request("/agent/challenge", serde_json::json!({"purpose":"register", "device_id":device_id}), None)?;
        let nonce = challenge.get("nonce").and_then(|v| v.as_str()).ok_or("E_MISSING_NONCE")?;
        let proof = signing_key.sign(format!("WINKEY_REGISTER:{}:{}", nonce, device_id).as_bytes());
        let proof_hex = proof.to_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let registered = request("/agent/register", serde_json::json!({
            "device_id":device_id, "computer_name":computer_name, "public_key_hex":public_key_hex,
            "nonce":nonce, "proof_signature_hex":proof_hex
        }), None)?;
        registered.get("device_secret").and_then(|v| v.as_str()).ok_or("E_MISSING_DEVICE_SECRET")?.to_string()
    };
    let pair = request("/devices/pair-request", serde_json::json!({"device_id":device_id}), Some(&secret))?;
    let pair_code = pair.get("pair_code").and_then(|v| v.as_str()).ok_or("E_MISSING_PAIR_CODE")?.to_string();
    let expires_at = pair.get("expires_at").and_then(|v| v.as_f64()).ok_or("E_MISSING_PAIR_EXPIRY")? as u64;
    let challenge_hex = String::new();
    let encrypted = dpapi_protect(secret.as_bytes())?;
    fs::write(&secret_file, encrypted).map_err(|e| format!("E_DEVICE_SECRET_SAVE: {}", e))?;
    cfg_val["device_id"] = serde_json::json!(device_id);
    cfg_val["computer_name"] = serde_json::json!(computer_name);
    cfg_val["gateway_origin"] = serde_json::json!(origin);
    cfg_val["server_confirmed"] = serde_json::json!(true);
    if let Some(obj) = cfg_val.as_object_mut() { obj.remove("device_secret"); }
    fs::write(&cfg_file, cfg_val.to_string()).map_err(|e| format!("E_CONFIG_SAVE: {}", e))?;
    match provision_device_to_service_ipc(&device_id, &secret) {
        Ok(_) => eprintln!("[PAIRING] trusted service provisioning OK"),
        Err(_) => eprintln!("[PAIRING] E_SERVICE_PROVISION_FAILED: QR may pair, but PC commands require the installed service"),
    }
''' + s[b:]
p.write_text(s, encoding='utf-8')
