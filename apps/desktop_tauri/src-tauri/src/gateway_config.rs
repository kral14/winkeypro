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
    saved.and_then(|value| normalize(value).ok())
        .filter(|value| value != LEGACY_ORIGIN)
        .unwrap_or_else(|| CLOUD_ORIGIN.to_string())
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
}
