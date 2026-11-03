//! Desktop follows only committed, pinned-signature-verified update slots.
use std::{fs,path::{Path,PathBuf}};
use sha2::{Digest,Sha256};
fn normalize_crlf(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            out.push(b'\n');
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}


pub fn verified_release_version(data: &serde_json::Value) -> Result<String,String> {
    let raw=data.get("manifest_raw").and_then(|v|v.as_str()).ok_or("E_UPDATE_MANIFEST")?;
    let signature=data.get("manifest_sig_hex").and_then(|v|v.as_str()).ok_or("E_UPDATE_SIGNATURE")?;
    if signature.len()!=128 {return Err("E_UPDATE_SIGNATURE".into());}
    let mut signature_bytes=[0u8;64];
    for (i,b) in signature_bytes.iter_mut().enumerate() {
        *b=u8::from_str_radix(&signature[i*2..i*2+2],16).map_err(|_|"E_UPDATE_SIGNATURE")?;
    }
    let pin="56524c1040e3a8309e938332037d0a0167cc2da30761abcfb77c93a899ad61da";
    let mut key=[0u8;32];
    for (i,b) in key.iter_mut().enumerate() {*b=u8::from_str_radix(&pin[i*2..i*2+2],16).map_err(|_|"E_UPDATE_KEY")?;}
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_|"E_UPDATE_KEY")?;
    let sig = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    let mut v_res = vk.verify_strict(raw.as_bytes(), &sig);
    if v_res.is_err() && raw.contains("\r\n") {
        let norm = raw.replace("\r\n", "\n");
        v_res = vk.verify_strict(norm.as_bytes(), &sig);
    }
    v_res.map_err(|_|"E_UPDATE_SIGNATURE")?;
    let manifest:serde_json::Value=serde_json::from_str(raw).map_err(|_|"E_UPDATE_MANIFEST")?;
    let version=manifest.get("version").and_then(|v|v.as_str()).ok_or("E_UPDATE_VERSION")?;
    version_tuple(version)?;
    Ok(version.to_string())
}

pub fn version_tuple(version:&str)->Result<Vec<u64>,String> {
    let values=version.split('.').map(|p|p.parse::<u64>().map_err(|_|"E_UPDATE_VERSION".to_string())).collect::<Result<Vec<_>,_>>()?;
    if values.len()!=3 {return Err("E_UPDATE_VERSION".into());}
    Ok(values)
}

pub fn active_desktop(base: &Path) -> Option<PathBuf> {
    active_desktop_with_key(base, "56524c1040e3a8309e938332037d0a0167cc2da30761abcfb77c93a899ad61da")
}

fn verify_slot_desktop(base: &Path, slot: &str, key_hex: &str) -> Option<(PathBuf, Vec<u64>)> {
    let directory = base.join("versions").join(slot);
    let raw = fs::read(directory.join("manifest.json")).ok()?;
    let signature = ed25519_dalek::Signature::from_slice(&fs::read(directory.join("manifest.sig")).ok()?).ok()?;
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&key_hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    let vk2 = ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()?;
    let mut v2_res = vk2.verify_strict(&raw, &signature);
    if v2_res.is_err() && raw.windows(2).any(|w| w == b"\r\n") {
        let norm = normalize_crlf(&raw);
        v2_res = vk2.verify_strict(&norm, &signature);
    }
    v2_res.ok()?;
    let manifest: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let ver_str = manifest.get("version")?.as_str()?;
    let ver = version_tuple(ver_str).ok()?;
    let entry = manifest.get("files")?.as_array()?.iter().find(|e| e.get("path").and_then(|v| v.as_str()) == Some("winkey_desktop.exe"))?;
    let executable = directory.join("winkey_desktop.exe");
    let payload = fs::read(&executable).ok()?;
    if payload.len() as u64 != entry.get("size")?.as_u64()? { return None; }
    let digest = format!("{:x}", Sha256::digest(&payload));
    if digest != entry.get("sha256")?.as_str()? { return None; }
    let canon = executable.canonicalize().ok()?;
    Some((canon, ver))
}

fn active_desktop_with_key(base: &Path, key_hex: &str) -> Option<PathBuf> {
    // 1. Əgər update_journal.json oxuna bilirsə:
    if let Ok(raw) = fs::read(base.join("update_journal.json")) {
        if let Ok(journal) = serde_json::from_slice::<serde_json::Value>(&raw) {
            let state = journal.get("state").and_then(|v| v.as_str()).unwrap_or("");
            if matches!(state, "IDLE" | "COMMITTED" | "ROLLED_BACK") {
                if let Some(slot) = journal.get("current_slot").and_then(|v| v.as_str()) {
                    if matches!(slot, "slot_a" | "slot_b") {
                        if let Some((path, _)) = verify_slot_desktop(base, slot, key_hex) {
                            return Some(path);
                        }
                    }
                }
            } else {
                // Yenilənmə hələ tamamlanmayıb (məs. STAGING, PENDING_ACTIVATION, PROBATION).
                // Köhnə və ya yarımçıq slota erkən keçidin qarşısını almaq üçün None qaytarırıq.
                return None;
            }
        }
    }

    // 2. Fallback: update_journal.json faylı icazə (ACL) səbəbilə oxunmadıqda belə,
    // hər iki slotu Ed25519 rəsmi açarı ilə yoxlayıb ən son bütöv versiyanı seçirik
    let opt_a = verify_slot_desktop(base, "slot_a", key_hex);
    let opt_b = verify_slot_desktop(base, "slot_b", key_hex);

    match (opt_a, opt_b) {
        (Some((path_a, ver_a)), Some((path_b, ver_b))) => {
            if ver_b >= ver_a { Some(path_b) } else { Some(path_a) }
        }
        (None, Some((path_b, _))) => Some(path_b),
        (Some((path_a, _)), None) => Some(path_a),
        (None, None) => None,
    }
}

pub fn current_version() -> String {
    static VERSION:std::sync::OnceLock<String>=std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        std::env::current_exe().ok().and_then(|p|p.parent().map(|p|p.join("manifest.json")))
            .and_then(|p|fs::read(p).ok()).and_then(|raw|serde_json::from_slice::<serde_json::Value>(&raw).ok())
            .and_then(|v|v.get("version").and_then(|v|v.as_str()).map(String::from))
            .unwrap_or_else(||env!("CARGO_PKG_VERSION").to_string())
    }).clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    #[test]
    fn only_committed_signed_matching_desktop_is_selected() {
        let base=std::env::temp_dir().join(format!("winkey-desktop-update-{}-{}",std::process::id(),rand::random::<u64>()));
        let slot=base.join("versions/slot_b"); fs::create_dir_all(&slot).unwrap();
        let key=ed25519_dalek::SigningKey::from_bytes(&[7u8;32]);
        let public=key.verifying_key().to_bytes().iter().map(|b|format!("{:02x}",b)).collect::<String>();
        let payload=b"DESKTOP_EXE_BINARY";
        let raw=serde_json::to_vec(&serde_json::json!({"version":"0.2.0","files":[{"path":"winkey_desktop.exe",
            "sha256":format!("{:x}",Sha256::digest(payload)),"size":payload.len()}]})).unwrap();
        fs::write(slot.join("manifest.json"),&raw).unwrap();
        fs::write(slot.join("manifest.sig"),key.sign(&raw).to_bytes()).unwrap();
        fs::write(slot.join("winkey_desktop.exe"),payload).unwrap();
        fs::write(base.join("update_journal.json"),br#"{"state":"PROBATION","current_slot":"slot_b"}"#).unwrap();
        assert!(active_desktop_with_key(&base,&public).is_none());
        fs::write(base.join("update_journal.json"),br#"{"state":"COMMITTED","current_slot":"slot_b"}"#).unwrap();
        assert!(active_desktop_with_key(&base,&public).is_some());
        // Production pin rejects the synthetic key.
        assert!(active_desktop(&base).is_none());
        fs::write(slot.join("winkey_desktop.exe"),b"tampered").unwrap();
        assert!(active_desktop_with_key(&base,&public).is_none());
        fs::remove_dir_all(base).unwrap();
    }
}

pub fn installed_base() -> PathBuf {
    std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(||PathBuf::from(r"C:\ProgramData")).join("WinKey")
}

pub fn different_active_desktop() -> Option<PathBuf> {
    let current = std::env::current_exe().ok()?.canonicalize().ok()?;
    // Dev/test builds must never redirect into the installed production app.
    if !current.components().any(|c| c.as_os_str().eq_ignore_ascii_case("Program Files") || c.as_os_str().eq_ignore_ascii_case("ProgramData")) {
        return None;
    }
    let target = active_desktop(&installed_base())?;
    if current == target {
        return None;
    }

    // Yalnız və yalnız hədəf versiya cari işləyən versiyadan BÖYÜK olduqda keçid edilməlidir!
    let cur_ver = version_tuple(&current_version()).ok()?;
    let target_manifest = target.parent()?.join("manifest.json");
    let target_raw = fs::read(target_manifest).ok()?;
    let target_json: serde_json::Value = serde_json::from_slice(&target_raw).ok()?;
    let target_ver_str = target_json.get("version")?.as_str()?;
    let target_ver = version_tuple(target_ver_str).ok()?;
    if target_ver > cur_ver {
        Some(target)
    } else {
        None
    }
}
