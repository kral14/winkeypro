use std::{fs, path::PathBuf, time::Duration};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn origin() -> Result<String, String> {
    #[cfg(debug_assertions)]
    if let Ok(value) = std::env::var("WINKEY_DEV_ACCOUNT_ORIGIN") {
        let value = super::gateway_config::normalize(&value)?;
        let url = tauri::Url::parse(&value).map_err(|_| "E_ACCOUNT_ORIGIN")?;
        if matches!(url.host_str(), Some("127.0.0.1") | Some("localhost") | Some("[::1]")) {
            return Ok(value);
        }
        return Err("E_DEV_ACCOUNT_ORIGIN: yalnız localhost qəbul edilir".into());
    }
    let cfg: Value = fs::read(super::get_app_data_dir().join("config.json")).ok()
        .and_then(|v| serde_json::from_slice(&v).ok()).unwrap_or(json!({}));
    let origin = super::gateway_config::cloud_origin(cfg.get("cloud_gateway_origin").and_then(Value::as_str));
    let url = tauri::Url::parse(&origin).map_err(|_| "E_ACCOUNT_ORIGIN")?;
    let host = url.host_str().unwrap_or("");
    let is_trusted = host == "158.101.172.228" || matches!(url.host_str(), Some("127.0.0.1") | Some("localhost") | Some("[::1]"));
    if url.scheme() != "https" && !is_trusted {
        return Err("Qeydiyyat üçün etibarlı HTTPS serveri lazımdır. VM-də HTTPS qurduqdan sonra hesab ekranında server ünvanını dəyişin.".into());
    }
    Ok(origin)
}

fn session_path(origin: &str) -> Result<PathBuf, String> {
    let base = std::env::var_os("LOCALAPPDATA").ok_or("E_ACCOUNT_PROFILE")?;
    let directory = PathBuf::from(base).join("WinKey").join("accounts");
    fs::create_dir_all(&directory).map_err(|_| "E_ACCOUNT_STORAGE")?;
    Ok(directory.join(format!("{:x}.dpapi", Sha256::digest(origin.as_bytes()))))
}

fn post(origin: &str, path: &str, body: Value, token: Option<&str>) -> Result<Value, String> {
    let mut request = ureq::post(&format!("{}{}", origin, path)).timeout(Duration::from_secs(12));
    if let Some(token) = token { request = request.set("Authorization", &format!("Bearer {}", token)); }
    match request.send_json(body) {
        Ok(response) => response.into_json().map_err(|_| "E_ACCOUNT_RESPONSE".into()),
        Err(ureq::Error::Status(_, response)) => {
            let value = response.into_json::<Value>().unwrap_or_default();
            Err(value.get("message").or_else(|| value.get("error")).and_then(Value::as_str)
                .unwrap_or("Hesaba giriş alınmadı.").to_string())
        }
        Err(_) => Err("Hesab serverinə qoşulmaq alınmadı.".into()),
    }
}

fn stored(origin: &str) -> Result<Value, String> {
    let bytes = fs::read(session_path(origin)?).map_err(|_| "E_ACCOUNT_REQUIRED")?;
    let mut plain = super::dpapi_unprotect(&bytes)?;
    let result = serde_json::from_slice(&plain).map_err(|_| "E_ACCOUNT_REQUIRED".into());
    use zeroize::Zeroize;
    plain.zeroize();
    result
}

fn local_device_id() -> String {
    fs::read(super::get_app_data_dir().join("config.json")).ok()
        .and_then(|raw|serde_json::from_slice::<Value>(&raw).ok())
        .and_then(|value|value.get("device_id").and_then(Value::as_str).map(String::from)).unwrap_or_default()
}

#[tauri::command]
pub fn account_status() -> Result<Value, String> {
    let origin = origin()?;
    let session = stored(&origin)?;
    let token = session["account_token"].as_str().ok_or("E_ACCOUNT_REQUIRED")?;
    let mut account = post(&origin, "/accounts/session", json!({}), Some(token))?;
    account["current_device_id"] = json!(local_device_id());
    Ok(account)
}

#[tauri::command]
pub fn account_authenticate(action: String, email: String, mut password: String) -> Result<Value, String> {
    if !matches!(action.as_str(), "login" | "register") { return Err("E_ACCOUNT_ACTION".into()); }
    let origin = origin()?;
    let response = post(&origin, &format!("/accounts/{}", action), json!({"email":email,"password":password}), None);
    use zeroize::Zeroize;
    password.zeroize();
    let response = response?;
    let encrypted = super::dpapi_protect(response.to_string().as_bytes())?;
    fs::write(session_path(&origin)?, encrypted).map_err(|_| "E_ACCOUNT_STORAGE")?;
    let account = post(&origin,"/accounts/session",json!({}),response["account_token"].as_str())?;
    let current = local_device_id();
    if !current.is_empty() && account["devices"].as_array().map(|list|list.iter().any(|d|d["device_id"].as_str()==Some(current.as_str()))).unwrap_or(false) {
        let (key,_) = super::get_or_create_device_keypair()?;
        bind_device(&current,&key)?;
    }
    Ok(json!({"email":response["email"],"account_id":response["account_id"]}))
}

pub fn require_account() -> Result<(), String> {
    account_status().map(|_| ())
}

#[tauri::command]
pub fn account_logout() -> Result<Value,String> {
    let origin = origin()?;
    let session = stored(&origin)?;
    let result = post(&origin,"/accounts/logout",json!({"device_id":local_device_id()}),session["account_token"].as_str())?;
    fs::remove_file(session_path(&origin)?).map_err(|_|"E_ACCOUNT_STORAGE")?;
    Ok(result)
}

#[tauri::command]
pub fn account_device_action(device_id: String, action: String, name: Option<String>) -> Result<Value,String> {
    let origin = origin()?;
    let session = stored(&origin)?;
    let result = post(&origin,"/accounts/device-action",json!({"device_id":device_id,"action":action,"name":name}),session["account_token"].as_str())?;
    if action == "rename" && device_id == local_device_id() {
        if let Some(name) = name { super::set_computer_name(name)?; }
    }
    Ok(result)
}

pub fn bind_device(device_id: &str, signing_key: &ed25519_dalek::SigningKey) -> Result<(), String> {
    use ed25519_dalek::Signer;
    let origin = origin()?;
    let session = stored(&origin)?;
    let token = session["account_token"].as_str().ok_or("E_ACCOUNT_REQUIRED")?;
    let account_id = session["account_id"].as_str().ok_or("E_ACCOUNT_REQUIRED")?;
    let challenge = post(&origin, "/agent/challenge", json!({"purpose":"account-bind","device_id":device_id}), None)?;
    let nonce = challenge["nonce"].as_str().ok_or("E_BIND_CHALLENGE")?;
    let proof = signing_key.sign(format!("WINKEY_ACCOUNT_BIND:{}:{}:{}", nonce, device_id, account_id).as_bytes());
    let proof_hex = proof.to_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let config: Value = fs::read(super::get_app_data_dir().join("config.json")).ok()
        .and_then(|raw|serde_json::from_slice(&raw).ok()).unwrap_or_default();
    post(&origin, "/accounts/device", json!({"device_id":device_id,"nonce":nonce,"proof":proof_hex,"name":config["computer_name"]}), Some(token))?;
    Ok(())
}
