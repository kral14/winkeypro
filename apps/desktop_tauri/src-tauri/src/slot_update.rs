//! Desktop follows only committed, pinned-signature-verified update slots.
use std::{fs,path::{Path,PathBuf}};
use sha2::{Digest,Sha256};

pub fn verified_release_version(data: &serde_json::Value) -> Result<String,String> {
    let raw=data.get("manifest_raw").and_then(|v|v.as_str()).ok_or("E_UPDATE_MANIFEST")?;
    let signature=data.get("manifest_sig_hex").and_then(|v|v.as_str()).ok_or("E_UPDATE_SIGNATURE")?;
    if signature.len()!=128 {return Err("E_UPDATE_SIGNATURE".into());}
    let mut signature_bytes=[0u8;64];
    for (i,b) in signature_bytes.iter_mut().enumerate() {
        *b=u8::from_str_radix(&signature[i*2..i*2+2],16).map_err(|_|"E_UPDATE_SIGNATURE")?;
    }
    let pin="4c7fa3c7a37b79b840e939741138f0748087ae0f06fa94e728557ec2a558fc54";
    let mut key=[0u8;32];
    for (i,b) in key.iter_mut().enumerate() {*b=u8::from_str_radix(&pin[i*2..i*2+2],16).map_err(|_|"E_UPDATE_KEY")?;}
    ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_|"E_UPDATE_KEY")?
        .verify_strict(raw.as_bytes(),&ed25519_dalek::Signature::from_bytes(&signature_bytes))
        .map_err(|_|"E_UPDATE_SIGNATURE")?;
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
    active_desktop_with_key(base, "4c7fa3c7a37b79b840e939741138f0748087ae0f06fa94e728557ec2a558fc54")
}

fn active_desktop_with_key(base: &Path, key_hex: &str) -> Option<PathBuf> {
    let journal:serde_json::Value=serde_json::from_slice(&fs::read(base.join("update_journal.json")).ok()?).ok()?;
    if !matches!(journal.get("state")?.as_str()?,"IDLE"|"COMMITTED"|"ROLLED_BACK") {return None;}
    let slot=journal.get("current_slot")?.as_str()?;
    if !matches!(slot,"slot_a"|"slot_b") {return None;}
    let directory=base.join("versions").join(slot);
    let raw=fs::read(directory.join("manifest.json")).ok()?;
    let signature=ed25519_dalek::Signature::from_slice(&fs::read(directory.join("manifest.sig")).ok()?).ok()?;
    let mut bytes=[0u8;32];
    for (i,b) in bytes.iter_mut().enumerate() {*b=u8::from_str_radix(&key_hex[i*2..i*2+2],16).ok()?;}
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()?.verify_strict(&raw,&signature).ok()?;
    let manifest:serde_json::Value=serde_json::from_slice(&raw).ok()?;
    let entry=manifest.get("files")?.as_array()?.iter().find(|e|e.get("path").and_then(|v|v.as_str())==Some("winkey_desktop.exe"))?;
    let executable=directory.join("winkey_desktop.exe");
    let payload=fs::read(&executable).ok()?;
    if payload.len() as u64 != entry.get("size")?.as_u64()? {return None;}
    let digest=format!("{:x}",Sha256::digest(&payload));
    if digest != entry.get("sha256")?.as_str()? {return None;}
    executable.canonicalize().ok()
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
        let public=key.verifying_key().as_bytes().iter().map(|b|format!("{:02x}",b)).collect::<String>();
        let payload=b"FAKE_NOT_EXECUTABLE";
        fs::write(slot.join("winkey_desktop.exe"),payload).unwrap();
        let raw=serde_json::to_vec(&serde_json::json!({"version":"0.2.0","files":[{"path":"winkey_desktop.exe",
            "sha256":format!("{:x}",Sha256::digest(payload)),"size":payload.len()}]})).unwrap();
        fs::write(slot.join("manifest.json"),&raw).unwrap();
        fs::write(slot.join("manifest.sig"),key.sign(&raw).to_bytes()).unwrap();
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
    let current=std::env::current_exe().ok()?.canonicalize().ok()?;
    // Dev/test builds must never redirect into the installed production app.
    if !current.components().any(|c| c.as_os_str().eq_ignore_ascii_case("Program Files") || c.as_os_str().eq_ignore_ascii_case("ProgramData")) {
        return None;
    }
    let target=active_desktop(&installed_base())?;
    if current==target {None} else {Some(target)}
}
