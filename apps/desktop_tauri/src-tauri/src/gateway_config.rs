pub const CLOUD_ORIGIN: &str = "http://158.101.172.228:8080";
const LEGACY_ORIGIN: &str = "https://winkey-remote-nesib.beigesong32770.chatgpt.site";

pub fn normalize(origin: &str) -> Result<String, String> {
    let clean = origin.trim().trim_end_matches('/');
    let url = tauri::Url::parse(clean).map_err(|_| "E_INVALID_GATEWAY_ORIGIN".to_string())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none()
        || !url.username().is_empty() || url.password().is_some()
        || url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
        return Err("E_INVALID_GATEWAY_ORIGIN: yalnız http(s)://server:port yazın".into());
    }
    Ok(clean.to_string())
}

pub fn cloud_origin(saved: Option<&str>) -> String {
    if let Some(value) = saved {
        if let Ok(origin) = normalize(value) {
            if origin != LEGACY_ORIGIN {
                return origin;
            }
        }
    }
    #[cfg(debug_assertions)]
    if let Ok(value) = std::env::var("WINKEY_DEV_GATEWAY_ORIGIN") {
        if let Ok(origin) = normalize(&value) { return origin; }
    }
    CLOUD_ORIGIN.to_string()
}

pub fn record_registration(cfg: &mut serde_json::Value, origin: &str, local: bool) {
    cfg["connection_mode"] = serde_json::json!(if local { "wifi" } else { "cloud" });
    if !local {
        cfg["gateway_origin"] = serde_json::json!(origin);
        cfg["cloud_gateway_origin"] = serde_json::json!(origin);
        cfg["server_confirmed"] = serde_json::json!(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cloud_migrates_legacy_and_preserves_custom_origin() {
        assert_eq!(cloud_origin(Some(LEGACY_ORIGIN)), CLOUD_ORIGIN);
        assert_eq!(cloud_origin(None), CLOUD_ORIGIN);
        assert_eq!(cloud_origin(Some("https://custom.example/")), "https://custom.example");
        assert!(normalize("http://user:password@example.com").is_err());
        assert!(normalize("http://example.com/admin").is_err());
        assert!(normalize("file:///secret").is_err());
    }
    #[test]
    fn wifi_pairing_does_not_replace_cloud_registration() {
        let mut cfg = serde_json::json!({});
        record_registration(&mut cfg, CLOUD_ORIGIN, false);
        record_registration(&mut cfg, "http://127.0.0.1:8788", true);
        assert_eq!(cfg["gateway_origin"], CLOUD_ORIGIN);
        assert_eq!(cfg["cloud_gateway_origin"], CLOUD_ORIGIN);
        assert_eq!(cfg["server_confirmed"], true);
        assert_eq!(cfg["connection_mode"], "wifi");
        record_registration(&mut cfg, "https://new.example", false);
        assert_eq!(cfg["gateway_origin"], "https://new.example");
        assert_eq!(cfg["connection_mode"], "cloud");
    }
}
