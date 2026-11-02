// WinKey Pro — Native Boot Recovery & Slot Lifecycle Engine (Revision 9)
#![allow(dead_code)]

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::storage::apply_restricted_file_acl;

pub const MAX_ALLOWED_CRASH_COUNT: u32 = 3;
pub fn normalize_crlf(bytes: &[u8]) -> Vec<u8> {
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


// Rəsmi Pinned Release Ed25519 İctimai Açarı (deploy/keys/prod_release_ed25519_pub.hex)
pub const DEFAULT_PINNED_RELEASE_PUBKEY_HEX: &str =
    "56524c1040e3a8309e938332037d0a0167cc2da30761abcfb77c93a899ad61da";

extern "system" {
    fn MoveFileExW(lpExistingFileName: *const u16, lpNewFileName: *const u16, dwFlags: u32) -> i32;
    fn GetLastError() -> u32;
}

const MOVEFILE_REPLACE_EXISTING: u32 = 0x00000001;
const MOVEFILE_WRITE_THROUGH: u32 = 0x00000008;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpdateJournal {
    pub schema_version: u32,
    pub current_slot: String,           // "slot_a" | "slot_b"
    pub last_known_good_slot: String,   // "slot_a" | "slot_b"
    pub state: String,                  // "IDLE" | "STAGING" | "PENDING_ACTIVATION" | "PROBATION" | "COMMITTED" | "ROLLED_BACK" | "CORRUPTED_RECOVERED" | "FATAL_NO_VALID_SLOT"
    pub active_version: Option<String>,
    pub candidate_version: Option<String>,
    pub quarantined_versions: Vec<String>,
    pub crash_count: u32,
    pub last_update_ts: f64,
    #[serde(default)]
    pub last_checkpoint: Option<String>, // "BOOTING", "HEALTHY", "ROLLED_BACK", "CRASHED"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFileEntry {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotManifest {
    pub version: String,
    #[serde(default)]
    pub timestamp: f64,
    pub files: Vec<ManifestFileEntry>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SlotValidationResult {
    pub is_valid: bool,
    pub version: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RecoveryAction {
    NormalBoot {
        slot: String,
        version: String,
    },
    RolledBackToLkg {
        from_slot: String,
        to_slot: String,
        quarantined_version: Option<String>,
        reason: String,
    },
    RecoveredCorruptedJournal {
        chosen_slot: String,
        reason: String,
    },
    FatalNoValidSlot {
        reason: String,
    },
}

fn current_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub const HOST_PROTOCOL_VERSION: u64 = 1;

pub fn get_pinned_public_key_bytes() -> Result<[u8; 32], String> {
    #[cfg(debug_assertions)]
    let hex_str = std::env::var("WINKEY_RELEASE_PUBKEY_HEX")
        .unwrap_or_else(|_| DEFAULT_PINNED_RELEASE_PUBKEY_HEX.to_string());
    #[cfg(not(debug_assertions))]
    let hex_str = DEFAULT_PINNED_RELEASE_PUBKEY_HEX.to_string();
    let hex_clean = hex_str.trim();
    if hex_clean.len() != 64 {
        return Err(format!("Etibarsız public key hex uzunluğu: {}", hex_clean.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex_clean[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("Hex parse xətası: {}", e))?;
    }
    Ok(out)
}

/// Slot qovluğunun manifestini, Ed25519 imzasını və bütün fayllarının bütövlüyünü yoxlayır
pub fn validate_slot(slot_dir: &Path, expected_pubkey: Option<&[u8; 32]>) -> SlotValidationResult {
    if !slot_dir.exists() || !slot_dir.is_dir() {
        return SlotValidationResult {
            is_valid: false,
            version: None,
            error: Some(format!("Slot qovluğu mövcud deyil: {:?}", slot_dir)),
        };
    }

    let manifest_path = slot_dir.join("manifest.json");
    if !manifest_path.exists() {
        return SlotValidationResult {
            is_valid: false,
            version: None,
            error: Some("manifest.json faylı tapılmadı".to_string()),
        };
    }

    // 1. MÜTLƏQ ED25519 İMZA YOXLANILIŞI (P0 Tələbi)
    let sig_path = slot_dir.join("manifest.sig");
    if !sig_path.exists() {
        return SlotValidationResult {
            is_valid: false,
            version: None,
            error: Some("E_UNSIGNED_MANIFEST: manifest.sig imza faylı tapılmadı (unsigned slot qəbul edilmir)".to_string()),
        };
    }

    let manifest_bytes = match fs::read(&manifest_path) {
        Ok(b) => b,
        Err(e) => {
            return SlotValidationResult {
                is_valid: false,
                version: None,
                error: Some(format!("manifest.json oxuna bilmədi: {}", e)),
            };
        }
    };

    let sig_raw = match fs::read(&sig_path) {
        Ok(s) => s,
        Err(e) => {
            return SlotValidationResult {
                is_valid: false,
                version: None,
                error: Some(format!("manifest.sig oxuna bilmədi: {}", e)),
            };
        }
    };

    let mut sig_64 = [0u8; 64];
    if sig_raw.len() == 64 {
        sig_64.copy_from_slice(&sig_raw);
    } else {
        // Hex formatında ola bilər (128 simvol)
        let sig_str = String::from_utf8_lossy(&sig_raw);
        let trimmed = sig_str.trim();
        if trimmed.len() == 128 {
            for i in 0..64 {
                match u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16) {
                    Ok(val) => sig_64[i] = val,
                    Err(e) => {
                        return SlotValidationResult {
                            is_valid: false,
                            version: None,
                            error: Some(format!("manifest.sig hex parse xətası: {}", e)),
                        };
                    }
                }
            }
        } else {
            return SlotValidationResult {
                is_valid: false,
                version: None,
                error: Some(format!("manifest.sig ölçüsü etibarsızdır (gözlənən 64 bayt və ya 128 hex, faktiki {})", sig_raw.len())),
            };
        }
    }

    let pubkey_bytes = match expected_pubkey {
        Some(k) => *k,
        None => match get_pinned_public_key_bytes() {
            Ok(k) => k,
            Err(e) => {
                return SlotValidationResult {
                    is_valid: false,
                    version: None,
                    error: Some(format!("Pinned public key alına bilmədi: {}", e)),
                };
            }
        },
    };

    let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(vk) => vk,
        Err(e) => {
            return SlotValidationResult {
                is_valid: false,
                version: None,
                error: Some(format!("VerifyingKey parse xətası: {}", e)),
            };
        }
    };

    let signature = Signature::from_bytes(&sig_64);
    let mut verify_res = verifying_key.verify(&manifest_bytes, &signature);
    if verify_res.is_err() && manifest_bytes.windows(2).any(|w| w == b"\r\n") {
        let normalized = normalize_crlf(&manifest_bytes);
        verify_res = verifying_key.verify(&normalized, &signature);
    }
    if let Err(e) = verify_res {
        return SlotValidationResult {
            is_valid: false,
            version: None,
            error: Some(format!("E_INVALID_SIGNATURE: Manifest Ed25519 imzası təsdiqlənmədi: {}", e)),
        };
    }

    // 2. MANİFEST STRUKTURU VƏ FAYL DOĞRULANMASI
    let manifest: SlotManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            return SlotValidationResult {
                is_valid: false,
                version: None,
                error: Some(format!("manifest.json formatı etibarsızdır: {}", e)),
            };
        }
    };

    if manifest.files.is_empty() {
        return SlotValidationResult {
            is_valid: false,
            version: Some(manifest.version),
            error: Some("Manifestdə heç bir fayl siyahısı yoxdur".to_string()),
        };
    }

    // Əsas icra binarının mövcudluğu tələbi (service binarı olmalıdır)
    let has_required_binary = manifest.files.iter().any(|f| {
        f.path == "winkey_service.exe" || f.path == "service.exe"
    });
    if !has_required_binary {
        return SlotValidationResult {
            is_valid: false,
            version: Some(manifest.version),
            error: Some("E_MISSING_ENTRYPOINT: Manifestdə məcburi winkey_service.exe və ya service.exe tapılmadı".to_string()),
        };
    }

    for entry in &manifest.files {
        // Path traversal və Reparse point / Symlink qadağası
        if entry.path.contains("..") || entry.path.starts_with('/') || entry.path.starts_with('\\') {
            return SlotValidationResult {
                is_valid: false,
                version: Some(manifest.version),
                error: Some(format!("Path traversal cəhdi aşkarlandı: {}", entry.path)),
            };
        }

        let file_path = slot_dir.join(&entry.path);
        if !file_path.exists() {
            return SlotValidationResult {
                is_valid: false,
                version: Some(manifest.version),
                error: Some(format!("Fayl mövcud deyil: {}", entry.path)),
            };
        }

        // Symlink / Reparse Point yoxlanışı
        if let Ok(meta) = fs::symlink_metadata(&file_path) {
            if meta.file_type().is_symlink() {
                return SlotValidationResult {
                    is_valid: false,
                    version: Some(manifest.version),
                    error: Some(format!("Reparse point / Symlink aşkarlandı (qadağandır): {}", entry.path)),
                };
            }
            if meta.len() != entry.size {
                return SlotValidationResult {
                    is_valid: false,
                    version: Some(manifest.version),
                    error: Some(format!(
                        "Ölçü uyğunsuzluğu {}: manifest {}, faktiki {}",
                        entry.path, entry.size, meta.len()
                    )),
                };
            }
        }

        let mut f = match File::open(&file_path) {
            Ok(file) => file,
            Err(e) => {
                return SlotValidationResult {
                    is_valid: false,
                    version: Some(manifest.version),
                    error: Some(format!("Fayl açıla bilmədi {}: {}", entry.path, e)),
                };
            }
        };

        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        let mut total_read = 0u64;
        let mut first_two_bytes = [0u8; 2];
        let mut checked_pe = false;

        loop {
            match f.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if !checked_pe && total_read == 0 && n >= 2 {
                        first_two_bytes[0] = buffer[0];
                        first_two_bytes[1] = buffer[1];
                        checked_pe = true;
                    }
                    hasher.update(&buffer[..n]);
                    total_read += n as u64;
                }
                Err(e) => {
                    return SlotValidationResult {
                        is_valid: false,
                        version: Some(manifest.version),
                        error: Some(format!("Fayl oxunma xətası {}: {}", entry.path, e)),
                    };
                }
            }
        }

        let actual_hash = format!("{:x}", hasher.finalize());
        if !actual_hash.eq_ignore_ascii_case(&entry.sha256) {
            return SlotValidationResult {
                is_valid: false,
                version: Some(manifest.version),
                error: Some(format!(
                    "SHA-256 hash uyğunsuzluğu {}: gözlənən {}, faktiki {}",
                    entry.path, entry.sha256, actual_hash
                )),
            };
        }

        // PE Binar doğrulanması: .exe və ya .dll faylları MZ başlığına malik olmalıdır
        if (entry.path.ends_with(".exe") || entry.path.ends_with(".dll")) && total_read >= 2 {
            if &first_two_bytes != b"MZ" {
                return SlotValidationResult {
                    is_valid: false,
                    version: Some(manifest.version),
                    error: Some(format!("Fayl etibarlı Windows PE binarı deyil (MZ başlığı yoxdur): {}", entry.path)),
                };
            }
        }
    }

    SlotValidationResult {
        is_valid: true,
        version: Some(manifest.version),
        error: None,
    }
}

/// Jurnalı disklə tam atomik və crash-safe şəkildə əvəzləyir (MoveFileExW REPLACE + backup fallback)
pub fn save_journal_atomic(base_dir: &Path, journal: &UpdateJournal) -> Result<(), String> {
    let journal_path = base_dir.join("update_journal.json");
    let random_id = uuid::Uuid::new_v4().to_string();
    let tmp_path = base_dir.join(format!("update_journal.json.tmp.{}", random_id));
    let bak_path = base_dir.join("update_journal.json.bak");

    let json_bytes = serde_json::to_vec_pretty(journal)
        .map_err(|e| format!("Jurnal seriyalaşdırma xətası: {}", e))?;

    {
        let mut f = File::create(&tmp_path)
            .map_err(|e| format!("Müvəqqəti jurnal yaradıla bilmədi: {}", e))?;
        f.write_all(&json_bytes)
            .map_err(|e| format!("Jurnal yazıla bilmədi: {}", e))?;
        f.sync_all()
            .map_err(|e| format!("Jurnal sync edilə bilmədi: {}", e))?;
    }

    let _ = apply_restricted_file_acl(&tmp_path);

    // Win32 MoveFileExW ilə atomik replace (MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
    let tmp_w: Vec<u16> = tmp_path.to_str().unwrap().encode_utf16().chain(std::iter::once(0)).collect();
    let journal_w: Vec<u16> = journal_path.to_str().unwrap().encode_utf16().chain(std::iter::once(0)).collect();

    let success = unsafe {
        MoveFileExW(
            tmp_w.as_ptr(),
            journal_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };

    if success != 0 {
        let _ = apply_restricted_file_acl(&journal_path);
        return Ok(());
    }

    // Windows fallback: .bak protokolundan istifadə edirik (fayl heç vaxt silinib itmir!)
    if journal_path.exists() {
        let _ = fs::copy(&journal_path, &bak_path);
    }

    match fs::rename(&tmp_path, &journal_path) {
        Ok(_) => {
            let _ = fs::remove_file(&bak_path);
            let _ = apply_restricted_file_acl(&journal_path);
            Ok(())
        }
        Err(e) => {
            // Əgər rename uğursuz olarsa, dərhal .bak-ı bərpa edirik!
            if bak_path.exists() && !journal_path.exists() {
                let _ = fs::rename(&bak_path, &journal_path);
            }
            let _ = fs::remove_file(&tmp_path);
            Err(format!("Durable atomic replace xətası: {}", e))
        }
    }
}

/// Jurnalı oxuyur; əgər zədələnibsə, arxivləşdirir və etibarlı slotu bərpa edir
pub fn read_or_recover_journal(base_dir: &Path, expected_pubkey: Option<&[u8; 32]>) -> (UpdateJournal, bool) {
    let journal_path = base_dir.join("update_journal.json");
    let versions_dir = base_dir.join("versions");
    let slot_a_dir = versions_dir.join("slot_a");
    let slot_b_dir = versions_dir.join("slot_b");

    if journal_path.exists() {
        if let Ok(content) = fs::read_to_string(&journal_path) {
            if let Ok(journal) = serde_json::from_str::<UpdateJournal>(content.trim_start_matches('\u{feff}')) {
                return (journal, false);
            }
        }

        // Zədələnmiş jurnal aşkarlandı -> Audit və forensika üçün arxivləyirik
        let corrupt_name = format!("update_journal.json.corrupt.{}", current_timestamp() as u64);
        let corrupt_path = base_dir.join(corrupt_name);
        let _ = fs::copy(&journal_path, corrupt_path);
    }

    // Slotların salamatlığı mütləq Ed25519 imzası ilə yoxlanılır
    let slot_a_val = validate_slot(&slot_a_dir, expected_pubkey);
    let slot_b_val = validate_slot(&slot_b_dir, expected_pubkey);

    let (chosen_slot, chosen_version, state) = if slot_a_val.is_valid {
        ("slot_a".to_string(), slot_a_val.version, "IDLE".to_string())
    } else if slot_b_val.is_valid {
        ("slot_b".to_string(), slot_b_val.version, "IDLE".to_string())
    } else {
        ("slot_a".to_string(), Some("0.1.0".to_string()), "IDLE".to_string())
    };

    let recovered = UpdateJournal {
        schema_version: 1,
        current_slot: chosen_slot.clone(),
        last_known_good_slot: chosen_slot,
        state,
        active_version: chosen_version,
        candidate_version: None,
        quarantined_versions: Vec::new(),
        crash_count: 0,
        last_update_ts: current_timestamp(),
        last_checkpoint: Some("INITIALIZED".to_string()),
    };

    let _ = save_journal_atomic(base_dir, &recovered);
    (recovered, true)
}

/// Xidmət açılışı zamanı boot vəziyyətini yoxlayır, lazım gələrsə avtomatik native rollback icra edir
pub fn evaluate_and_prepare_active_slot(
    base_dir: &Path,
    expected_pubkey: Option<&[u8; 32]>,
) -> Result<(UpdateJournal, RecoveryAction), String> {
    let (mut journal, was_recovered) = read_or_recover_journal(base_dir, expected_pubkey);
    let versions_dir = base_dir.join("versions");
    let slot_a_dir = versions_dir.join("slot_a");
    let slot_b_dir = versions_dir.join("slot_b");

    if was_recovered {
        return Ok((
            journal.clone(),
            RecoveryAction::RecoveredCorruptedJournal {
                chosen_slot: journal.current_slot.clone(),
                reason: "Jurnal faylı bərpa olundu və ya ilkin vəziyyətdə yaradıldı".to_string(),
            },
        ));
    }

    // 1. Namizəd sınaq müddətindədirsə (PROBATION və ya UPDATING)
    if journal.state == "PROBATION" || journal.state == "UPDATING" {
        let current_slot_dir = if journal.current_slot == "slot_b" { &slot_b_dir } else { &slot_a_dir };
        let lkg_slot_dir = if journal.last_known_good_slot == "slot_b" { &slot_b_dir } else { &slot_a_dir };

        let crashed_previously = journal.last_checkpoint.as_deref() == Some("BOOTING");
        if crashed_previously {
            journal.crash_count += 1;
        }

        let slot_validity = validate_slot(current_slot_dir, expected_pubkey);
        let must_rollback = !slot_validity.is_valid || journal.crash_count >= MAX_ALLOWED_CRASH_COUNT;

        if must_rollback {
            let reason = if !slot_validity.is_valid {
                format!("Namizəd slot imzası və ya bütövlüyü pozulub: {:?}", slot_validity.error)
            } else {
                format!("Namizəd versiya {} dəfə crash edib (maksimum icazə {})", journal.crash_count, MAX_ALLOWED_CRASH_COUNT)
            };

            // LKG slotunun sağlamlığını Ed25519 imzası ilə təsdiq edirik
            let lkg_validity = validate_slot(lkg_slot_dir, expected_pubkey);
            if !lkg_validity.is_valid {
                journal.state = "FATAL_NO_VALID_SLOT".to_string();
                let _ = save_journal_atomic(base_dir, &journal);
                return Ok((
                    journal,
                    RecoveryAction::FatalNoValidSlot {
                        reason: format!("Rollback uğursuz: LKG slotu da etibarsızdır ({:?})", lkg_validity.error),
                    },
                ));
            }

            let failed_version = journal.candidate_version.take();
            if let Some(ref ver) = failed_version {
                if !journal.quarantined_versions.contains(ver) {
                    journal.quarantined_versions.push(ver.clone());
                }
            }

            let from_slot = journal.current_slot.clone();
            let to_slot = journal.last_known_good_slot.clone();

            journal.current_slot = to_slot.clone();
            journal.state = "ROLLED_BACK".to_string();
            journal.crash_count = 0;
            journal.last_update_ts = current_timestamp();
            journal.last_checkpoint = Some("ROLLED_BACK".to_string());

            save_journal_atomic(base_dir, &journal)?;

            return Ok((
                journal,
                RecoveryAction::RolledBackToLkg {
                    from_slot,
                    to_slot,
                    quarantined_version: failed_version,
                    reason,
                },
            ));
        }

        // Probation sınaq checkpoint-i
        journal.last_checkpoint = Some("BOOTING".to_string());
        journal.last_update_ts = current_timestamp();
        save_journal_atomic(base_dir, &journal)?;

        return Ok((
            journal.clone(),
            RecoveryAction::NormalBoot {
                slot: journal.current_slot,
                version: slot_validity.version.unwrap_or_else(|| "unknown".to_string()),
            },
        ));
    }

    // 2. Normal vəziyyət (IDLE, COMMITTED, ROLLED_BACK)
    let current_slot_dir = if journal.current_slot == "slot_b" { &slot_b_dir } else { &slot_a_dir };
    let slot_val = validate_slot(current_slot_dir, expected_pubkey);

    if !slot_val.is_valid {
        let lkg_slot_dir = if journal.last_known_good_slot == "slot_b" { &slot_b_dir } else { &slot_a_dir };
        let lkg_val = validate_slot(lkg_slot_dir, expected_pubkey);

        if lkg_val.is_valid {
            let from_slot = journal.current_slot.clone();
            let to_slot = journal.last_known_good_slot.clone();

            journal.current_slot = to_slot.clone();
            journal.state = "ROLLED_BACK".to_string();
            journal.last_checkpoint = Some("ROLLED_BACK".to_string());
            journal.last_update_ts = current_timestamp();
            let quarantined = journal.active_version.clone();
            save_journal_atomic(base_dir, &journal)?;

            return Ok((
                journal,
                RecoveryAction::RolledBackToLkg {
                    from_slot,
                    to_slot,
                    quarantined_version: quarantined,
                    reason: format!("Cari slot faylları zədələnib: {:?}", slot_val.error),
                },
            ));
        } else {
            return Ok((
                journal,
                RecoveryAction::FatalNoValidSlot {
                    reason: "Nə cari slot, nə də LKG slotu etibarlıdır (İmza və ya fayl xətası)".to_string(),
                },
            ));
        }
    }

    journal.active_version = slot_val.version.clone();
    journal.last_checkpoint = Some("BOOTING".to_string());
    save_journal_atomic(base_dir, &journal)?;

    Ok((
        journal.clone(),
        RecoveryAction::NormalBoot {
            slot: journal.current_slot,
            version: slot_val.version.unwrap_or_else(|| "0.1.0".to_string()),
        },
    ))
}

/// Sınaq müddəti (probation) uğurla başa çatdıqda namizəd versiyanı rəsmi LKG kimi təsdiqləyir
pub fn mark_boot_healthy(base_dir: &Path, expected_pubkey: Option<&[u8; 32]>) -> Result<UpdateJournal, String> {
    let (mut journal, _) = read_or_recover_journal(base_dir, expected_pubkey);

    if journal.state == "PROBATION" || journal.state == "UPDATING" {
        journal.state = "COMMITTED".to_string();
        journal.last_known_good_slot = journal.current_slot.clone();
        if let Some(candidate) = journal.candidate_version.take() {
            journal.active_version = Some(candidate);
        }
    }

    journal.crash_count = 0;
    journal.last_checkpoint = Some("HEALTHY".to_string());
    journal.last_update_ts = current_timestamp();

    save_journal_atomic(base_dir, &journal)?;
    Ok(journal)
}

/// Host prosesi namizəd worker-in qəzasını aşkar etdikdə dərhal rollback icra edir
pub fn record_candidate_crash_and_rollback(
    base_dir: &Path,
    expected_pubkey: Option<&[u8; 32]>,
    reason: &str,
) -> Result<(UpdateJournal, RecoveryAction), String> {
    let (mut journal, _) = read_or_recover_journal(base_dir, expected_pubkey);
    let from_slot = journal.current_slot.clone();
    let to_slot = journal.last_known_good_slot.clone();

    journal.crash_count += 1;
    let quarantined = journal.candidate_version.take();
    if let Some(ref ver) = quarantined {
        if !journal.quarantined_versions.contains(ver) {
            journal.quarantined_versions.push(ver.clone());
        }
    }

    // LKG slotunun mövcudluğunu və bütövlüyünü yoxlayırıq
    let lkg_dir = base_dir.join("versions").join(&to_slot);
    let lkg_val = validate_slot(&lkg_dir, expected_pubkey);
    if !lkg_val.is_valid {
        journal.state = "FATAL_NO_VALID_SLOT".to_string();
        let _ = save_journal_atomic(base_dir, &journal);
        return Ok((
            journal,
            RecoveryAction::FatalNoValidSlot {
                reason: format!("Rollback uğursuz: LKG slotu ({}) etibarsızdır: {:?}", to_slot, lkg_val.error),
            },
        ));
    }

    journal.current_slot = to_slot.clone();
    journal.state = "ROLLED_BACK".to_string();
    journal.last_update_ts = current_timestamp();
    journal.last_checkpoint = Some(format!("ROLLED_BACK_FROM_{}", from_slot));

    save_journal_atomic(base_dir, &journal)?;

    Ok((
        journal,
        RecoveryAction::RolledBackToLkg {
            from_slot,
            to_slot,
            quarantined_version: quarantined,
            reason: reason.to_string(),
        },
    ))
}

/// Seçilmiş slotun icra olunan əsas binar yolunu qaytarır
pub fn get_slot_executable_path(base_dir: &Path, slot_name: &str) -> PathBuf {
    let slot_dir = base_dir.join("versions").join(slot_name);
    let p = slot_dir.join("winkey_service.exe");
    if p.exists() {
        p
    } else {
        slot_dir.join("service.exe")
    }
}

fn parse_version_tuple(v: &str) -> Vec<u64> {
    v.split('.')
        .map(|s| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>())
        .filter_map(|s| s.parse::<u64>().ok())
        .collect()
}

pub fn compare_semver(v1: &str, v2: &str) -> std::cmp::Ordering {
    let t1 = parse_version_tuple(v1);
    let t2 = parse_version_tuple(v2);
    t1.cmp(&t2)
}

/// Native Auto-Update Staging Pipeline (Downgrade qoruması, Karantin və Interrupted Download müdafiəsi ilə)

pub fn normalize_path_for_compare(p: &Path) -> String {
    let s = p.to_string_lossy().replace('/', "\\").to_lowercase();
    if let Some(stripped) = s.strip_prefix("\\\\?\\unc\\") {
        format!("\\\\{}", stripped)
    } else if let Some(stripped) = s.strip_prefix("\\\\?\\") {
        stripped.to_string()
    } else {
        s
    }
}

pub fn clean_lingering_slot_processes(
    target_dir: &Path,
    active_slot: Option<&str>,
    lkg_slot: Option<&str>,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if let Ok(meta) = fs::symlink_metadata(target_dir) {
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err("E_TARGET_DIR_IS_REPARSE_POINT_PROHIBITED: Reparse point və ya qovluq keçidi qadağandır".to_string());
            }
        }
    }

    let canonical = match fs::canonicalize(target_dir) {
        Ok(p) => p,
        Err(_) => target_dir.to_path_buf(),
    };
    let norm_target = normalize_path_for_compare(&canonical);
    let trimmed = norm_target.trim_end_matches('\\');
    if trimmed.is_empty() || trimmed.len() <= 3 || trimmed.ends_with(':') {
        return Err("E_TARGET_DIR_IS_ROOT_PROHIBITED: Kök qovluğu təmizləmək qadağandır".to_string());
    }
    if trimmed.contains("\\windows") || trimmed.contains("\\system32") {
        return Err("E_TARGET_DIR_IS_SYSTEM_PROHIBITED: Sistem qovluğunu təmizləmək qadağandır".to_string());
    }

    if let Some(act) = active_slot {
        let norm_act = normalize_path_for_compare(Path::new(act));
        if trimmed.ends_with(&format!("\\{}", act)) || trimmed == act || trimmed == norm_act {
            return Err(format!("E_CANNOT_TOUCH_ACTIVE_SLOT: Aktiv slot ({}) dayandırıla və ya dəyişdirilə bilməz", act));
        }
    }
    if let Some(lkg) = lkg_slot {
        let norm_lkg = normalize_path_for_compare(Path::new(lkg));
        if trimmed.ends_with(&format!("\\{}", lkg)) || trimmed == lkg || trimmed == norm_lkg {
            return Err(format!("E_CANNOT_TOUCH_LKG_SLOT: LKG slotu ({}) dayandırıla və ya dəyişdirilə bilməz", lkg));
        }
    }

    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        use windows_sys::Win32::Foundation::CloseHandle;

        let target_prefix = format!("{}\\", trimmed);

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err("E_CREATE_PROCESS_SNAPSHOT_FAILED".to_string());
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut has_next = Process32FirstW(snapshot, &mut entry);
        let current_pid = std::process::id();

        while has_next != 0 {
            if entry.th32ProcessID != current_pid && entry.th32ProcessID != 0 {
                let h_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID);
                if !h_proc.is_null() {
                    let mut path_buf = [0u16; 1024];
                    let mut size = 1024u32;
                    if windows_sys::Win32::System::Threading::QueryFullProcessImageNameW(
                        h_proc,
                        0,
                        path_buf.as_mut_ptr(),
                        &mut size,
                    ) != 0 {
                        let raw_path = String::from_utf16_lossy(&path_buf[..size as usize]);
                        let norm_proc = normalize_path_for_compare(Path::new(&raw_path));

                        if norm_proc.starts_with(&target_prefix) {
                            let bin_name = Path::new(&norm_proc)
                                .file_name()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_default();

                            eprintln!("[SLOT_IN_USE] Hədəf slotda işləyən proses aşkarlandı: PID={} binar={} yol={}", entry.th32ProcessID, bin_name, norm_proc);
                            CloseHandle(h_proc);
                            CloseHandle(snapshot);
                            return Err(format!("E_TARGET_SLOT_IN_USE: Inaktiv slotda işləyən proses var (PID={} binar={}), yeniləmə təxirə salınır", entry.th32ProcessID, bin_name));
                        }
                    }
                    CloseHandle(h_proc);
                }
            }
            has_next = Process32NextW(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
    }
    Ok(())
}

pub fn stage_native_update_bundle(
    base_dir: &Path,
    manifest_bytes: &[u8],
    sig_bytes: &[u8],
    payload_files: &[(String, Vec<u8>)],
    expected_pubkey: Option<&[u8; 32]>,
) -> Result<String, String> {
    let pubkey = match expected_pubkey {
        Some(k) => *k,
        None => get_pinned_public_key_bytes()?,
    };

    // 1. Ed25519 Manifest İmza Doğrulanması (Pinned public key ilə)
    let ver_key = match VerifyingKey::from_bytes(&pubkey) {
        Ok(k) => k,
        Err(e) => return Err(format!("E_PUBKEY_PARSE: {}", e)),
    };
    let mut sig_64 = [0u8; 64];
    if sig_bytes.len() == 64 {
        sig_64.copy_from_slice(sig_bytes);
    } else {
        return Err("E_INVALID_SIG_LEN".to_string());
    }
    let sig = Signature::from_bytes(&sig_64);
    let mut verify_res = ver_key.verify(manifest_bytes, &sig);
    if verify_res.is_err() && manifest_bytes.windows(2).any(|w| w == b"\r\n") {
        let normalized = normalize_crlf(manifest_bytes);
        verify_res = ver_key.verify(&normalized, &sig);
    }
    if let Err(e) = verify_res {
        return Err(format!("E_INVALID_SIGNATURE: {}", e));
    }

    let manifest: SlotManifest = match serde_json::from_slice(manifest_bytes) {
        Ok(m) => m,
        Err(e) => return Err(format!("E_MANIFEST_PARSE: {}", e)),
    };

    let candidate_ver = manifest.version.clone();

    // 2. Jurnal Oxunuşu və Karantin / Downgrade / LKG Qorunması Yoxlanışı
    let (mut journal, _) = read_or_recover_journal(base_dir, Some(&pubkey));

    // LKG Qorunması: PROBATION, STAGING və ya PENDING_ACTIVATION vəziyyətində təkrar staging qadağandır!
    // Bu vəziyyətlərdə inaktiv slotda cari LKG nüsxəsi yerləşir; onu silmək rollback təhlükəsizliyini məhv edir.
    if journal.state == "PROBATION" || journal.state == "STAGING" || journal.state == "PENDING_ACTIVATION" {
        return Err(format!(
            "E_UPDATE_IN_PROGRESS: Cari yenilənmə hələ təsdiqlənməyib (vəziyyət: {}). LKG qorunması üçün yeni staging bloklandı.",
            journal.state
        ));
    }

    if journal.quarantined_versions.contains(&candidate_ver) {
        return Err(format!("E_VERSION_QUARANTINED: Versiya {} karantindədir", candidate_ver));
    }

    if let Some(ref act_ver) = journal.active_version {
        // Namizəd <= Cari versiyadırsa rədd edilir (Downgrade və eyni versiya qadağandır)
        if compare_semver(&candidate_ver, act_ver) != std::cmp::Ordering::Greater {
            return Err(format!(
                "E_DOWNGRADE_OR_SAME_VERSION_REJECTED: Namizəd v{} aktiv v{}-dən böyük deyil",
                candidate_ver, act_ver
            ));
        }
    }

    // 3. Hədəf Inactive Slot Təyini
    let target_slot = if journal.current_slot == "slot_a" { "slot_b" } else { "slot_a" };
    let versions_dir = base_dir.join("versions");
    let target_dir = versions_dir.join(target_slot);

    // Host protokol versiyası yoxlanışı (min_host_protocol_version)
    if let Ok(manifest_val) = serde_json::from_slice::<serde_json::Value>(manifest_bytes) {
        if let Some(min_proto_val) = manifest_val.get("min_host_protocol_version") {
            let min_proto = match min_proto_val.as_u64() {
                Some(p) => p,
                None => {
                    return Err("E_INVALID_PROTOCOL_VERSION_TYPE: min_host_protocol_version müsbət tam ədəd olmalıdır".to_string());
                }
            };
            if min_proto > HOST_PROTOCOL_VERSION {
                journal.state = "SETUP_REQUIRED".to_string();
                let _ = save_journal_atomic(base_dir, &journal);
                return Err(format!(
                    "E_HOST_UPGRADE_REQUIRED: Bu versiya minimum host protokol v{} tələb edir (cari: {}). Quraşdırıcı (Setup.exe) ilə yeniləyin.",
                    min_proto, HOST_PROTOCOL_VERSION
                ));
            }
        }
    }

    // Əgər əvvəlki ardıcıl yenilənmədən qalan proseslər varsa dayandırılır
    clean_lingering_slot_processes(&target_dir, Some(&journal.current_slot), Some(&journal.last_known_good_slot))?;
    let mut cleared = false;
    for _ in 0..3 {
        if !target_dir.exists() || fs::remove_dir_all(&target_dir).is_ok() {
            cleared = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    if !cleared && target_dir.exists() {
        return Err(format!("E_TARGET_SLOT_LOCKED: Hədəf slot ({}) faylları kilidlidir, təmizlənə bilmədi", target_slot));
    }
    if let Err(e) = fs::create_dir_all(&target_dir) {
        return Err(format!("E_CREATE_TARGET_DIR_FAILED: {}", e));
    }

    // Jurnal STAGING
    journal.state = "STAGING".to_string();
    journal.candidate_version = Some(candidate_ver.clone());
    let _ = save_journal_atomic(base_dir, &journal);

    // 4. Faylların yazılması və Interrupted/Incomplete Download yoxlanışı
    for entry in &manifest.files {
        // Path traversal guard
        if entry.path.contains("..") || entry.path.starts_with('/') || entry.path.starts_with('\\') || entry.path.contains(':') {
            let _ = fs::remove_dir_all(&target_dir);
            return Err(format!("E_SECURITY_PATH_TRAVERSAL: {}", entry.path));
        }

        let payload_opt = payload_files.iter().find(|(name, _)| name == &entry.path);
        let payload = match payload_opt {
            Some((_, bytes)) => bytes,
            None => {
                // Interrupted download fail-closed
                let _ = fs::remove_dir_all(&target_dir);
                return Err(format!("E_INTERRUPTED_DOWNLOAD_MISSING_PAYLOAD: {}", entry.path));
            }
        };

        // Ölçü yoxlanışı
        if payload.len() as u64 != entry.size {
            let _ = fs::remove_dir_all(&target_dir);
            return Err(format!("E_INTERRUPTED_DOWNLOAD_SIZE_MISMATCH: {} ({} != {})", entry.path, payload.len(), entry.size));
        }

        // SHA-256 hash yoxlanışı
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let hash_hex = format!("{:x}", hasher.finalize());
        if hash_hex.to_lowercase() != entry.sha256.to_lowercase() {
            let _ = fs::remove_dir_all(&target_dir);
            return Err(format!("E_INTEGRITY_HASH_MISMATCH: {}", entry.path));
        }

        let dest_path = target_dir.join(&entry.path);
        if let Some(parent) = dest_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Err(e) = fs::write(&dest_path, payload) {
            let _ = fs::remove_dir_all(&target_dir);
            return Err(format!("E_WRITE_PAYLOAD_FAILED: {}", e));
        }
    }

    // Manifest və imza fayllarını target slot-a yazırıq
    let _ = fs::write(target_dir.join("manifest.json"), manifest_bytes);
    let _ = fs::write(target_dir.join("manifest.sig"), sig_bytes);

    // 5. Slotun tam doğrulanması (PE header b"MZ" və bütövlük)
    let validation = validate_slot(&target_dir, Some(&pubkey));
    if !validation.is_valid {
        let _ = fs::remove_dir_all(&target_dir);
        return Err(format!("E_SLOT_VALIDATION_FAILED: {:?}", validation.error));
    }

    // Jurnal PENDING_ACTIVATION
    journal.state = "PENDING_ACTIVATION".to_string();
    journal.last_update_ts = current_timestamp();
    let _ = save_journal_atomic(base_dir, &journal);

    Ok(format!("STAGED_NATIVE_SUCCESS: {} -> {}", target_slot, candidate_ver))
}

/// Hazırlanmış (staged) namizəd versiyanı rəsmi aktiv slota keçirir və PROBATION başladır
pub fn activate_pending_update(
    base_dir: &Path,
    expected_pubkey: Option<&[u8; 32]>,
) -> Result<(UpdateJournal, String), String> {
    let (mut journal, _) = read_or_recover_journal(base_dir, expected_pubkey);
    if journal.state != "PENDING_ACTIVATION" && journal.state != "STAGING" {
        return Err(format!("E_NOT_PENDING_ACTIVATION: Cari vəziyyət {}", journal.state));
    }
    let _candidate = journal.candidate_version.clone().ok_or("E_NO_CANDIDATE_VERSION")?;
    let target_slot = if journal.current_slot == "slot_a" { "slot_b" } else { "slot_a" };

    let target_dir = base_dir.join("versions").join(target_slot);
    let val = validate_slot(&target_dir, expected_pubkey);
    if !val.is_valid {
        return Err(format!("E_ACTIVATION_SLOT_INVALID: {:?}", val.error));
    }

    journal.current_slot = target_slot.to_string();
    journal.state = "PROBATION".to_string();
    journal.crash_count = 0;
    journal.last_update_ts = current_timestamp();
    journal.last_checkpoint = Some("BOOTING".to_string());
    save_journal_atomic(base_dir, &journal)?;

    Ok((journal, target_slot.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use std::fs::File;
    use std::io::Write;

    struct TempTestDir {
        path: PathBuf,
    }

    impl TempTestDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("winkey_{}_{}", name, uuid::Uuid::new_v4()));
            let _ = fs::create_dir_all(&path);
            Self { path }
        }
    }

    impl Drop for TempTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn generate_test_keypair() -> (SigningKey, [u8; 32]) {
        let rng = [42u8; 32]; // Deterministic test seed
        let signing_key = SigningKey::from_bytes(&rng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key.to_bytes())
    }

    fn create_signed_test_slot(
        slot_path: &Path,
        version: &str,
        file_content: &[u8],
        is_pe: bool,
        signing_key: &SigningKey,
    ) {
        fs::create_dir_all(slot_path).unwrap();
        let bin_name = "winkey_service.exe";
        let bin_path = slot_path.join(bin_name);

        let mut data = Vec::new();
        if is_pe {
            data.extend_from_slice(b"MZ\x90\x00\x03\x00\x00\x00"); // Valid PE signature prefix
        }
        data.extend_from_slice(file_content);

        File::create(&bin_path).unwrap().write_all(&data).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = format!("{:x}", hasher.finalize());

        let manifest = SlotManifest {
            version: version.to_string(),
            timestamp: 123456789.0,
            files: vec![ManifestFileEntry {
                path: bin_name.to_string(),
                sha256: hash,
                size: data.len() as u64,
            }],
        };

        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        File::create(slot_path.join("manifest.json")).unwrap().write_all(&manifest_bytes).unwrap();

        // İmzalayırıq və manifest.sig faylına yazırıq
        let signature = signing_key.sign(&manifest_bytes);
        File::create(slot_path.join("manifest.sig")).unwrap().write_all(&signature.to_bytes()).unwrap();
    }

    #[test]
    fn test_signed_slot_validation_success() {
        let (signer, pubkey) = generate_test_keypair();
        let temp_dir = TempTestDir::new("signed_slot_val");
        let slot_path = temp_dir.path.join("slot_a");

        create_signed_test_slot(&slot_path, "1.0.0", b"test_payload", true, &signer);
        let res = validate_slot(&slot_path, Some(&pubkey));
        assert!(res.is_valid, "Valid slot rədd edildi: {:?}", res.error);
        assert_eq!(res.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn test_unsigned_manifest_rejected() {
        let (signer, pubkey) = generate_test_keypair();
        let temp_dir = TempTestDir::new("unsigned_slot");
        let slot_path = temp_dir.path.join("slot_a");

        create_signed_test_slot(&slot_path, "1.0.0", b"test_payload", true, &signer);
        // İmza faylını silirik
        let _ = fs::remove_file(slot_path.join("manifest.sig"));

        let res = validate_slot(&slot_path, Some(&pubkey));
        assert!(!res.is_valid);
        assert!(res.error.unwrap().contains("E_UNSIGNED_MANIFEST"));
    }

    #[test]
    fn test_tampered_manifest_rejected() {
        let (signer, pubkey) = generate_test_keypair();
        let temp_dir = TempTestDir::new("tampered_manifest");
        let slot_path = temp_dir.path.join("slot_a");

        create_signed_test_slot(&slot_path, "1.0.0", b"test_payload", true, &signer);
        // Manifesti dəyişirik
        File::create(slot_path.join("manifest.json")).unwrap().write_all(b"{\"version\":\"2.0.0\",\"files\":[]}").unwrap();

        let res = validate_slot(&slot_path, Some(&pubkey));
        assert!(!res.is_valid);
        assert!(res.error.unwrap().contains("E_INVALID_SIGNATURE"));
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let (signer, pubkey) = generate_test_keypair();
        let temp_dir = TempTestDir::new("tampered_payload");
        let slot_path = temp_dir.path.join("slot_a");

        create_signed_test_slot(&slot_path, "1.0.0", b"test_payload", true, &signer);
        // Binarı dəyişirik
        File::create(slot_path.join("winkey_service.exe")).unwrap().write_all(b"MZ_tampered_bytes").unwrap();

        let res = validate_slot(&slot_path, Some(&pubkey));
        assert!(!res.is_valid);
        let err = res.error.unwrap();
        assert!(err.contains("SHA-256 hash uyğunsuzluğu") || err.contains("Ölçü uyğunsuzluğu"));
    }

    #[test]
    fn test_stage_blocked_during_probation_preserves_lkg() {
        let (signer, pubkey) = generate_test_keypair();
        let temp_dir = TempTestDir::new("probation_lkg_guard");
        let versions = temp_dir.path.join("versions");
        let slot_a = versions.join("slot_a");
        let slot_b = versions.join("slot_b");

        // LKG slot_a v1.0.0
        create_signed_test_slot(&slot_a, "1.0.0", b"lkg_stable_service_payload", true, &signer);
        let lkg_bytes_before = fs::read(slot_a.join("winkey_service.exe")).unwrap();
        let mut hasher_before = Sha256::new();
        hasher_before.update(&lkg_bytes_before);
        let lkg_sha_before = format!("{:x}", hasher_before.finalize());

        // Namizəd slot_b v1.1.0 probation vəziyyətindədir
        create_signed_test_slot(&slot_b, "1.1.0", b"candidate_probation_payload", true, &signer);
        let journal = UpdateJournal {
            schema_version: 1,
            current_slot: "slot_b".to_string(),
            last_known_good_slot: "slot_a".to_string(),
            state: "PROBATION".to_string(),
            active_version: Some("1.0.0".to_string()),
            candidate_version: Some("1.1.0".to_string()),
            quarantined_versions: vec![],
            crash_count: 0,
            last_checkpoint: Some("PROBATION".to_string()),
            last_update_ts: 123456.0,
        };
        save_journal_atomic(&temp_dir.path, &journal).unwrap();

        // Növbəti v1.2.0 yenilənməsini staging etməyə cəhd edirik
        
        let dummy_manifest = SlotManifest {
            version: "1.2.0".to_string(),
            timestamp: 123456789.0,
            files: vec![ManifestFileEntry {
                path: "winkey_service.exe".to_string(),
                sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                size: 10,
            }],
        };
        let m_bytes = serde_json::to_vec_pretty(&dummy_manifest).unwrap();
        let sig = signer.sign(&m_bytes);

        let res = stage_native_update_bundle(
            &temp_dir.path,
            &m_bytes,
            &sig.to_bytes(),
            &[("winkey_service.exe".to_string(), b"MZ_payload".to_vec())],
            Some(&pubkey),
        );

        assert!(res.is_err(), "PROBATION zamanı staging bloklanmalıdır");
        let err = res.err().unwrap();
        assert!(err.contains("E_UPDATE_IN_PROGRESS"), "Gözlənilməyən xəta: {}", err);

        // LKG slot_a faylının toxunulmaz qaldığını təsdiqləyirik
        let lkg_bytes_after = fs::read(slot_a.join("winkey_service.exe")).unwrap();
        let mut hasher_after = Sha256::new();
        hasher_after.update(&lkg_bytes_after);
        let lkg_sha_after = format!("{:x}", hasher_after.finalize());
        assert_eq!(lkg_sha_before, lkg_sha_after, "LKG hash-i toxunulmaz qalmalıdır!");
    }

    #[test]
    fn test_candidate_probation_crash_triggers_native_rollback() {
        let (signer, pubkey) = generate_test_keypair();
        let temp_dir = TempTestDir::new("probation_crash");
        let base_dir = &temp_dir.path;
        let slot_a = base_dir.join("versions").join("slot_a");
        let slot_b = base_dir.join("versions").join("slot_b");

        // Slot A (LKG): v1.0.0
        create_signed_test_slot(&slot_a, "1.0.0", b"lkg_code", true, &signer);
        // Slot B (Candidate): v1.1.0
        create_signed_test_slot(&slot_b, "1.1.0", b"candidate_code", true, &signer);

        let initial_journal = UpdateJournal {
            schema_version: 1,
            current_slot: "slot_b".to_string(),
            last_known_good_slot: "slot_a".to_string(),
            state: "PROBATION".to_string(),
            active_version: Some("1.0.0".to_string()),
            candidate_version: Some("1.1.0".to_string()),
            quarantined_versions: Vec::new(),
            crash_count: 2,
            last_update_ts: 1000.0,
            last_checkpoint: Some("BOOTING".to_string()),
        };
        save_journal_atomic(base_dir, &initial_journal).unwrap();

        // 3-cü dəfə boot edir: limit dolur (2 + 1 = 3 >= MAX_ALLOWED_CRASH_COUNT)
        let (journal_out, action) = evaluate_and_prepare_active_slot(base_dir, Some(&pubkey)).unwrap();

        match action {
            RecoveryAction::RolledBackToLkg { from_slot, to_slot, quarantined_version, .. } => {
                assert_eq!(from_slot, "slot_b");
                assert_eq!(to_slot, "slot_a");
                assert_eq!(quarantined_version.as_deref(), Some("1.1.0"));
            }
            _ => panic!("Gözlənilməyən hərəkət: {:?}", action),
        }

        assert_eq!(journal_out.current_slot, "slot_a");
        assert_eq!(journal_out.state, "ROLLED_BACK");
        assert!(journal_out.quarantined_versions.contains(&"1.1.0".to_string()));
    }

    #[test]
    fn test_mark_boot_healthy_commits_candidate() {
        let (signer, pubkey) = generate_test_keypair();
        let temp_dir = TempTestDir::new("boot_healthy");
        let base_dir = &temp_dir.path;
        let slot_b = base_dir.join("versions").join("slot_b");
        create_signed_test_slot(&slot_b, "1.1.0", b"healthy_code", true, &signer);

        let journal = UpdateJournal {
            schema_version: 1,
            current_slot: "slot_b".to_string(),
            last_known_good_slot: "slot_a".to_string(),
            state: "PROBATION".to_string(),
            active_version: Some("1.0.0".to_string()),
            candidate_version: Some("1.1.0".to_string()),
            quarantined_versions: Vec::new(),
            crash_count: 0,
            last_update_ts: 1000.0,
            last_checkpoint: Some("BOOTING".to_string()),
        };
        save_journal_atomic(base_dir, &journal).unwrap();

        let committed = mark_boot_healthy(base_dir, Some(&pubkey)).unwrap();
        assert_eq!(committed.state, "COMMITTED");
        assert_eq!(committed.last_known_good_slot, "slot_b");
        assert_eq!(committed.active_version.as_deref(), Some("1.1.0"));
        assert_eq!(committed.candidate_version, None);
        assert_eq!(committed.last_checkpoint.as_deref(), Some("HEALTHY"));
    }
}
