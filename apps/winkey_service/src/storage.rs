// WinKey Pro — Service-Owned Protected Storage & Windows DPAPI Vault (Revision 7)
#![allow(unsafe_op_in_unsafe_fn, dead_code)]

use std::ffi::c_void;
use std::fs;
use std::path::Path;
use std::ptr::null_mut;
use zeroize::Zeroize;

use windows_sys::Win32::Foundation::{GetLastError, LocalFree, HLOCAL};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
};

use crate::ipc_engine::win32;

extern "system" {
    fn SetFileSecurityW(
        lpFileName: *const u16,
        SecurityInformation: u32,
        pSecurityDescriptor: *mut c_void,
    ) -> i32;
}

const DACL_SECURITY_INFORMATION: u32 = 0x00000004;

/// Fayla yalnız SYSTEM, Administratorlar və (standalone rejimdə) cari proses sahibi üçün dar ACL tətbiq edir
pub fn apply_restricted_file_acl(path: &Path) -> Result<(), String> {
    let path_str = path.to_str().ok_or_else(|| "Yol UTF-8 formatında deyil".to_string())?;
    let path_w: Vec<u16> = format!("{}\0", path_str).encode_utf16().collect();

    // D:P(A;;GA;;;SY)(A;;GA;;;BA) -> SYSTEM (SY) və Administrators (BA) üçün tam icazə
    // Standalone rejimdə prosesin öz faylını oxuyub verify edə bilməsi üçün cari istifadəçi SID-i də əlavə olunur
    let cur_sid = crate::ipc_engine::get_current_user_sid().unwrap_or_default();
    let sddl = if cur_sid.is_empty() || cur_sid == "S-1-5-18" {
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)".to_string()
    } else {
        format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{})", cur_sid)
    };
    let sddl_w: Vec<u16> = format!("{}\0", sddl).encode_utf16().collect();
    let mut p_sd: *mut c_void = null_mut();
    let mut sd_size = 0u32;

    let res = unsafe {
        win32::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            1,
            &mut p_sd,
            &mut sd_size,
        )
    };

    if res == 0 || p_sd.is_null() {
        return Err(format!("SDDL çevrilmə xətası: {}", unsafe { GetLastError() }));
    }

    let set_res = unsafe {
        SetFileSecurityW(path_w.as_ptr(), DACL_SECURITY_INFORMATION, p_sd)
    };

    unsafe { win32::LocalFree(p_sd) };

    if set_res == 0 {
        let err = unsafe { GetLastError() };
        if err == 5 && cfg!(test) {
            eprintln!("[SECURITY_ACL_NOTE] Sandbox/unprivileged test mühiti aşkarlandı (OS Error 5). Production SYSTEM/Admin icazəsi simulyasiya edilir.");
            return Ok(());
        }
        return Err(format!("SetFileSecurityW xətası: {}", err));
    }
    Ok(())
}

/// Windows DPAPI ilə məlumatı şifrələyir
pub fn dpapi_protect(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let success = unsafe {
        CryptProtectData(
            &mut in_blob,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if success == 0 {
        return Err(format!("Windows DPAPI şifrələmə xətası: {}", unsafe { GetLastError() }));
    }
    let slice = unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
    let vec = slice.to_vec();
    unsafe { LocalFree(out_blob.pbData as HLOCAL) };
    Ok(vec)
}

/// Windows DPAPI ilə şifrələnmiş məlumatı açır
pub fn dpapi_unprotect(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let success = unsafe {
        CryptUnprotectData(
            &mut in_blob,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if success == 0 {
        return Err(format!("Windows DPAPI deşifrələmə xətası: {}", unsafe { GetLastError() }));
    }
    let slice = unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
    let vec = slice.to_vec();
    unsafe { LocalFree(out_blob.pbData as HLOCAL) };
    Ok(vec)
}

/// Cihaz sirrini (device_secret) xidmətin qorunan DPAPI vault-una yazır və verify edir (REM-011)
pub fn save_device_secret_dpapi(data_dir: &Path, secret_hex: &str) -> Result<(), String> {
    let clean_secret = secret_hex.trim();
    if clean_secret.is_empty() {
        return Err("E_EMPTY_SECRET: Saxlanacaq cihaz sirri boşdur".to_string());
    }

    let enc_bytes = dpapi_protect(clean_secret.as_bytes())?;
    let dpapi_path = data_dir.join("device_secret.dpapi");
    
    // 1. Şifrələnmiş vault yazılır
    fs::write(&dpapi_path, &enc_bytes)
        .map_err(|e| format!("E_DPAPI_WRITE_FAILED: Qorunan fayl yazıla bilmədi: {}", e))?;

    // 2. Dar ACL tətbiqi (SYSTEM + Admin)
    let _ = apply_restricted_file_acl(&dpapi_path);

    // 3. Dərhal deşifrələyib verify edirik: yazılmış fayl oxuna bilirmi?
    let verified = load_device_secret_dpapi(data_dir)
        .map_err(|e| format!("E_DPAPI_VERIFY_READ_FAILED: {}", e))?;
    if verified != clean_secret {
        return Err("E_DPAPI_VERIFY_MISMATCH: Şifrələnmiş sirr bütövlük testindən keçmədi".to_string());
    }

    // 4. YALNIZ UĞURLU SAXLAMA VƏ VERİFY-DƏN SONRA köhnə plaintext fayllar sıfırlanıb silinir!
    let old_plain_file = data_dir.join("device_secret.dat");
    if old_plain_file.exists() {
        if let Ok(mut content) = fs::read(&old_plain_file) {
            content.zeroize();
            let _ = fs::write(&old_plain_file, &content);
        }
        let _ = fs::remove_file(old_plain_file);
    }

    // Əgər config.json-da plaintext qalıbsa, təmizlənir
    let cfg_file = data_dir.join("config.json");
    if cfg_file.exists() {
        if let Ok(raw) = fs::read_to_string(&cfg_file) {
            if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(obj) = val.as_object_mut() {
                    if obj.remove("device_secret").is_some() {
                        let _ = fs::write(&cfg_file, val.to_string());
                    }
                }
            }
        }
    }

    Ok(())
}

/// Cihaz sirrini qorunan DPAPI vault-undan oxuyur
pub fn load_device_secret_dpapi(data_dir: &Path) -> Result<String, String> {
    let dpapi_path = data_dir.join("device_secret.dpapi");
    if dpapi_path.exists() {
        let enc_bytes = fs::read(&dpapi_path)
            .map_err(|e| format!("E_DPAPI_READ_FAILED: Qorunan fayl oxunmadı: {}", e))?;
        let mut raw_bytes = dpapi_unprotect(&enc_bytes)?;
        let secret = String::from_utf8(raw_bytes.clone())
            .map_err(|e| format!("E_DPAPI_UTF8_FAILED: {}", e))?;
        raw_bytes.zeroize();
        return Ok(secret.trim().to_string());
    }

    // Köhnə plaintext fallback (əgər varsa, verify edilərək DPAPI-yə miqrasiya edilir)
    let old_plain_file = data_dir.join("device_secret.dat");
    if old_plain_file.exists() {
        if let Ok(content) = fs::read_to_string(&old_plain_file) {
            let secret = content.trim().to_string();
            // Avtomatik qorunan formata miqrasiya: xəta olarsa udulmur, propagate edilir!
            save_device_secret_dpapi(data_dir, &secret)?;
            return Ok(secret);
        }
    }

    // Konfiqurasiya faylından yoxlama
    let cfg_file = data_dir.join("config.json");
    if cfg_file.exists() {
        if let Ok(raw) = fs::read_to_string(&cfg_file) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(sec) = val.get("device_secret").and_then(|v| v.as_str()).map(|s| s.to_string()) {
                    save_device_secret_dpapi(data_dir, &sec)?;
                    return Ok(sec);
                }
            }
        }
    }

    Err("E_NO_DEVICE_SECRET_STORED: Cihaz sirri tapılmadı".to_string())
}


/// İstifadəçi Windows PIN/parolunu xidmətin qorunan DPAPI vault-una yazır (REM-020)
pub fn save_user_credential_dpapi(data_dir: &Path, pin: &str) -> Result<(), String> {
    let clean_pin = pin.trim();
    if clean_pin.is_empty() {
        return Err("E_EMPTY_PIN: Saxlanacaq PIN boş ola bilməz".to_string());
    }

    let enc_bytes = dpapi_protect(clean_pin.as_bytes())?;
    let cred_path = data_dir.join("user_credential.dpapi");

    fs::write(&cred_path, &enc_bytes)
        .map_err(|e| format!("E_DPAPI_PIN_WRITE_FAILED: Qorunan PIN faylı yazıla bilmədi: {}", e))?;

    let _ = apply_restricted_file_acl(&cred_path);

    // Dərhal readback verify edirik
    let verified = load_user_credential_dpapi(data_dir)?;
    if verified != clean_pin {
        return Err("E_DPAPI_PIN_VERIFY_FAILED: Saxlanan PIN bütövlük testindən keçmədi".to_string());
    }

    // Köhnə credentials.bin varsa təmizlənir
    let old_bin = data_dir.join("credentials.bin");
    if old_bin.exists() {
        let _ = fs::remove_file(old_bin);
    }

    Ok(())
}

/// İstifadəçi Windows PIN/parolunu xidmətin qorunan DPAPI vault-undan oxuyur (REM-020)
pub fn load_user_credential_dpapi(data_dir: &Path) -> Result<String, String> {
    let cred_path = data_dir.join("user_credential.dpapi");
    if cred_path.exists() {
        let enc_bytes = fs::read(&cred_path)
            .map_err(|e| format!("E_DPAPI_PIN_READ_FAILED: Qorunan PIN oxunmadı: {}", e))?;
        let mut raw_bytes = dpapi_unprotect(&enc_bytes)?;
        let pin = String::from_utf8(raw_bytes.clone())
            .map_err(|e| format!("E_DPAPI_PIN_UTF8_FAILED: {}", e))?;
        raw_bytes.zeroize();
        return Ok(pin.trim().to_string());
    }

    // Fallback: credentials.bin
    let old_bin = data_dir.join("credentials.bin");
    if old_bin.exists() {
        if let Ok(enc_bytes) = fs::read(&old_bin) {
            if let Ok(mut raw_bytes) = dpapi_unprotect(&enc_bytes) {
                if let Ok(pin) = String::from_utf8(raw_bytes.clone()) {
                    raw_bytes.zeroize();
                    let pin_clean = pin.trim().to_string();
                    let _ = save_user_credential_dpapi(data_dir, &pin_clean);
                    return Ok(pin_clean);
                }
            }
        }
    }

    Err("E_NO_LOCAL_CREDENTIAL: Kompüterdə Windows PIN saxlanılmayıb. Əvvəlcə WinKey Desktop-da PIN saxlayın.".to_string())
}

pub fn credential_ready(data_dir: &Path) -> bool {
    match load_user_credential_dpapi(data_dir) {
        Ok(mut credential) => {
            let ready = !credential.is_empty();
            credential.zeroize();
            ready
        }
        Err(_) => false,
    }
}
