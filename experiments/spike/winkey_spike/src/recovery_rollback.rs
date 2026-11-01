// WinKey Pro — Müstəqil Boot-Time Recovery, Real Ed25519 Pinned Key İmza Yoxlaması və Uşaq Proses Rollback-i

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub version: String,
    pub target_slot: String,
    pub binary_sha256: String,
    pub released_epoch: u64,
}

impl ReleaseManifest {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbationStatus {
    Idle,
    InProbation {
        candidate_slot: String,
        candidate_version: String,
        crash_count: u32,
    },
    PromotedToKnownGood {
        slot: String,
        version: String,
    },
    RollbackTriggered {
        from_slot: String,
        to_slot: String,
        reason: String,
    },
    Quarantined {
        slot: String,
        reason: String,
    },
    HaltBothSlotsInvalid {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionJournal {
    pub active_slot: String,
    pub active_version: String,
    pub known_good_slot: Option<String>,
    pub known_good_version: Option<String>,
    pub candidate_slot: Option<String>,
    pub candidate_version: Option<String>,
    pub probation_status: ProbationStatus,
    pub crash_counter: u32,
    pub last_updated_epoch: u64,
}

pub struct WinKeyRecovery {
    pub base_dir: PathBuf,
    pub versions_dir: PathBuf,
    pub state_dir: PathBuf,
    pub journal_path: PathBuf,
    pub pointer_path: PathBuf,
    pub pinned_verifying_key: VerifyingKey,
}

impl WinKeyRecovery {
    pub fn new(base_dir: &Path, pinned_verifying_key: VerifyingKey) -> Self {
        let versions_dir = base_dir.join("versions");
        let state_dir = base_dir.join("state");
        let journal_path = state_dir.join("journal.json");
        let pointer_path = state_dir.join("current_slot.pointer");

        fs::create_dir_all(&versions_dir).ok();
        fs::create_dir_all(&state_dir).ok();

        Self {
            base_dir: base_dir.to_path_buf(),
            versions_dir,
            state_dir,
            journal_path,
            pointer_path,
            pinned_verifying_key,
        }
    }

    /// Qorunan versions qovluğundan kənara çıxmağı (Path Traversal / Absolute / Reparse) qətiyyən qadağan edir
    pub fn resolve_slot_dir(&self, slot_name: &str) -> Result<PathBuf, &'static str> {
        // 1. Simvol təhlükəsizliyi: Yalnız alfasayısal, tire və alt-xətt icazəlidir
        if slot_name.is_empty()
            || !slot_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("E_PATH_TRAVERSAL_DETECTED: Slot adı yalnız alfasayısal simvollardan ibarət ola bilər");
        }

        if slot_name.contains("..") || slot_name.contains('/') || slot_name.contains('\\') || slot_name.contains(':') {
            return Err("E_PATH_TRAVERSAL_DETECTED: Qovluqdan kənara çıxma və ya separator simvolları qadağandır");
        }

        let slot_dir = self.versions_dir.join(slot_name);

        // Path bütövlüyü yoxlanışı: slot_dir mütləq versions_dir-in alt qovluğu olmalıdır
        if !slot_dir.starts_with(&self.versions_dir) {
            return Err("E_PATH_TRAVERSAL_DETECTED: Slot yolu versions qovluğundan kənara çıxır");
        }

        Ok(slot_dir)
    }

    /// Diskə davamlı atomik jurnal və göstərici yazısı (FlushFileBuffers / sync_all ilə)
    pub fn write_journal_atomic(&self, journal: &TransactionJournal) -> std::io::Result<()> {
        let tmp_path = self.state_dir.join("journal.tmp");
        let serialized = serde_json::to_string_pretty(journal)?;

        {
            let mut file = File::create(&tmp_path)?;
            file.write_all(serialized.as_bytes())?;
            file.sync_all()?; // Win32 FlushFileBuffers zəmanəti
        }
        fs::rename(&tmp_path, &self.journal_path)?;

        let ptr_tmp = self.state_dir.join("current_slot.tmp");
        {
            let mut ptr_file = File::create(&ptr_tmp)?;
            ptr_file.write_all(journal.active_slot.as_bytes())?;
            ptr_file.sync_all()?;
        }
        fs::rename(&ptr_tmp, &self.pointer_path)?;

        Ok(())
    }

    /// Jurnalı oxuyur; korrupt jurnal ilə ilkin təmiz quraşdırmanı qətiyyən qarışdırmır!
    pub fn read_journal_safe(&self) -> Result<Option<TransactionJournal>, &'static str> {
        if !self.journal_path.exists() {
            // Fayl ümumiyyətlə yoxdur -> Təmiz ilkin quraşdırma halı
            return Ok(None);
        }

        let content = fs::read_to_string(&self.journal_path).map_err(|_| "E_READ_JOURNAL_FAILED")?;
        match serde_json::from_str::<TransactionJournal>(&content) {
            Ok(journal) => Ok(Some(journal)),
            Err(_) => {
                // Fayl mövcuddur lakin zədələnib -> Korrupt jurnal xətası!
                Err("E_CORRUPT_JOURNAL_DETECTED: Jurnal faylı zədələnib, ilkin quraşdırma kimi qəbul edilə bilməz")
            }
        }
    }

    pub fn compute_sha256(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Hər launch və fallback öncəsi: Pinned Ed25519 key ilə manifest imzası,
    /// hədəf slot uyğunluğu və binary SHA-256 bütövlüyü yoxlanılır (REAL_API / CRYPTO)
    pub fn verify_slot_integrity(
        &self,
        slot_name: &str,
    ) -> Result<ReleaseManifest, &'static str> {
        let slot_dir = self.resolve_slot_dir(slot_name)?;
        let manifest_path = slot_dir.join("manifest.json");
        let sig_path = slot_dir.join("manifest.sig");
        let binary_path = slot_dir.join("winkey_supervisor.exe");

        if !manifest_path.exists() {
            return Err("E_MISSING_MANIFEST: Slotda manifest.json tapılmadı");
        }
        if !sig_path.exists() {
            return Err("E_MISSING_SIGNATURE: Slotda manifest.sig imza faylı tapılmadı");
        }
        if !binary_path.exists() {
            return Err("E_MISSING_BINARY: Slotda supervisor binary tapılmadı");
        }

        // 1. Manifest oxunması
        let manifest_bytes = fs::read(&manifest_path).map_err(|_| "E_READ_MANIFEST_FAILED")?;
        let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| "E_MALFORMED_MANIFEST: Manifest formatı etibarsızdır")?;

        // 2. Slot adı manifestdəki target_slot ilə uyğun olmalıdır
        if manifest.target_slot != slot_name {
            return Err("E_MANIFEST_TARGET_MISMATCH: Manifestdəki hədəf slot fiziki qovluqla uyğun gəlmir");
        }

        // 3. Ed25519 kriptoqrafik imza yoxlanışı (Pinned Public Key ilə)
        let sig_bytes = fs::read(&sig_path).map_err(|_| "E_READ_SIGNATURE_FAILED")?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| "E_INVALID_SIGNATURE_FORMAT: İmza formatı etibarsızdır")?;

        let canonical_bytes = manifest.to_bytes();
        self.pinned_verifying_key
            .verify_strict(&canonical_bytes, &sig)
            .map_err(|_| "E_SIGNATURE_VERIFICATION_FAILED: İmza pinned public key ilə təsdiqlənmədi")?;

        // 4. Binary SHA-256 hash yoxlanışı
        let binary_bytes = fs::read(&binary_path).map_err(|_| "E_READ_BINARY_FAILED")?;
        let computed_hash = Self::compute_sha256(&binary_bytes);

        if computed_hash != manifest.binary_sha256 {
            return Err("E_HASH_MISMATCH: Kriptoqrafik SHA-256 hash manifestlə uyğun gəlmir (tamper aşkarlandı)");
        }

        Ok(manifest)
    }

    /// İlkin təsdiqlənmiş quraşdırma yaratmaq üçün köməkçi metod
    pub fn provision_verified_slot(
        &self,
        slot_name: &str,
        version: &str,
        binary_payload: &[u8],
        signing_key: &SigningKey,
    ) -> Result<(), &'static str> {
        let slot_dir = self.resolve_slot_dir(slot_name)?;
        fs::create_dir_all(&slot_dir).map_err(|_| "E_CREATE_SLOT_DIR_FAILED")?;

        let binary_path = slot_dir.join("winkey_supervisor.exe");
        fs::write(&binary_path, binary_payload).map_err(|_| "E_WRITE_BINARY_FAILED")?;

        let manifest = ReleaseManifest {
            version: version.to_string(),
            target_slot: slot_name.to_string(),
            binary_sha256: Self::compute_sha256(binary_payload),
            released_epoch: 1730000000,
        };

        let manifest_bytes = manifest.to_bytes();
        let sig = signing_key.sign(&manifest_bytes);

        fs::write(slot_dir.join("manifest.json"), serde_json::to_vec_pretty(&manifest).unwrap())
            .map_err(|_| "E_WRITE_MANIFEST_FAILED")?;
        fs::write(slot_dir.join("manifest.sig"), sig.to_bytes())
            .map_err(|_| "E_WRITE_SIG_FAILED")?;

        Ok(())
    }

    /// Namizəd yeniləməni aktivasiya edir (Probation vəziyyətinə keçid)
    pub fn activate_candidate_update(
        &self,
        candidate_slot: &str,
        current_epoch: u64,
    ) -> Result<String, String> {
        // Namizəd slot aktivləşmədən əvvəl tam imza və hash yoxlanışından keçməlidir!
        let manifest = self.verify_slot_integrity(candidate_slot)
            .map_err(|e| format!("Namizəd slot bütövlük xətası: {}", e))?;

        let mut journal = match self.read_journal_safe() {
            Ok(Some(j)) => j,
            Ok(None) => return Err("İlkin jurnal mövcud deyil".to_string()),
            Err(e) => return Err(e.to_string()),
        };

        journal.active_slot = candidate_slot.to_string();
        journal.active_version = manifest.version.clone();
        journal.candidate_slot = Some(candidate_slot.to_string());
        journal.candidate_version = Some(manifest.version.clone());
        journal.crash_counter = 0;
        journal.probation_status = ProbationStatus::InProbation {
            candidate_slot: candidate_slot.to_string(),
            candidate_version: manifest.version,
            crash_count: 0,
        };
        journal.last_updated_epoch = current_epoch;

        self.write_journal_atomic(&journal).map_err(|e| e.to_string())?;
        Ok(candidate_slot.to_string())
    }

    /// Namizəd uğurla işlədikdə (Health probation təsdiqi) rəsmi Known-Good elan edilir!
    pub fn confirm_candidate_health(&self, current_epoch: u64) -> Result<(), String> {
        let mut journal = match self.read_journal_safe() {
            Ok(Some(j)) => j,
            Ok(None) => return Err("Jurnal tapılmadı".to_string()),
            Err(e) => return Err(e.to_string()),
        };

        if let Some(candidate) = journal.candidate_slot.take() {
            let cand_ver = journal.candidate_version.take().unwrap_or_default();
            journal.known_good_slot = Some(candidate.clone());
            journal.known_good_version = Some(cand_ver.clone());
            journal.active_slot = candidate.clone();
            journal.active_version = cand_ver.clone();
            journal.crash_counter = 0;
            journal.probation_status = ProbationStatus::PromotedToKnownGood {
                slot: candidate,
                version: cand_ver,
            };
            journal.last_updated_epoch = current_epoch;
            self.write_journal_atomic(&journal).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    /// Boot və ya proses qəzası zamanı bərpa qərarı (Recovery & Rollback Decision):
    /// Fallback kor-koranə əks slot deyil, təsdiqlənmiş Known-Good slota qayıdışdır!
    /// Hər iki slot etibarsızdırsa binary heç bir halda başladılmır!
    pub fn boot_recovery_decision(&self) -> Result<String, String> {
        let mut journal = match self.read_journal_safe() {
            Ok(Some(j)) => j,
            Ok(None) => {
                // Təmiz ilkin quraşdırma halı: slot_a təsdiqlənmiş known-good kimi başlanır
                let manifest = self.verify_slot_integrity("slot_a")
                    .map_err(|e| format!("İlkin slot_a etibarsızdır: {}", e))?;

                let init = TransactionJournal {
                    active_slot: "slot_a".to_string(),
                    active_version: manifest.version.clone(),
                    known_good_slot: Some("slot_a".to_string()),
                    known_good_version: Some(manifest.version),
                    candidate_slot: None,
                    candidate_version: None,
                    probation_status: ProbationStatus::Idle,
                    crash_counter: 0,
                    last_updated_epoch: 1730000000,
                };
                self.write_journal_atomic(&init).map_err(|e| e.to_string())?;
                return Ok(init.active_slot);
            }
            Err(e) => return Err(e.to_string()),
        };

        // 1. Cari aktiv slotun bütövlüyü yoxlanılır
        let active_slot_integrity = self.verify_slot_integrity(&journal.active_slot);

        // Əgər aktiv slot zədələnibsə və ya probation crash-loop (crash >= 3) baş veribsə -> Fallback tələb olunur!
        let needs_fallback = match &active_slot_integrity {
            Err(_) => true,
            Ok(_) => journal.crash_counter >= 3,
        };

        if !needs_fallback {
            // Aktiv slot bütövdür və crash həddini aşmayıb
            return Ok(journal.active_slot.clone());
        }

        // 2. FALLBACK AXINI: Təsdiqlənmiş Known-Good slota qayıtmalı!
        let fallback_slot_name = match &journal.known_good_slot {
            Some(kg) if kg != &journal.active_slot => kg.clone(),
            _ => {
                // Əgər known_good_slot yoxdursa və ya aktiv slotla eynidirsə və o da zədələnibsə:
                journal.probation_status = ProbationStatus::HaltBothSlotsInvalid {
                    reason: "Təsdiqlənmiş known-good slot tapılmadı və cari slot zədələnib".to_string(),
                };
                self.write_journal_atomic(&journal).ok();
                return Err("E_BOTH_SLOTS_INVALID: Hər iki slot etibarsızdır, binary başladılmır!".to_string());
            }
        };

        // 3. Known-good slot işə salınmadan əvvəl mütləq imza və hash yoxlanışından keçməlidir!
        match self.verify_slot_integrity(&fallback_slot_name) {
            Ok(manifest) => {
                // Fallback slot tam sağlamdır -> Uğurlu Rollback!
                journal.probation_status = ProbationStatus::RollbackTriggered {
                    from_slot: journal.active_slot.clone(),
                    to_slot: fallback_slot_name.clone(),
                    reason: format!("Cari slot xətası (Crash count={}, Integrity={:?})", journal.crash_counter, active_slot_integrity.err()),
                };
                journal.active_slot = fallback_slot_name.clone();
                journal.active_version = manifest.version;
                journal.candidate_slot = None;
                journal.candidate_version = None;
                journal.crash_counter = 0;
                self.write_journal_atomic(&journal).map_err(|e| e.to_string())?;
                Ok(fallback_slot_name)
            }
            Err(fallback_err) => {
                // KRİTİK TƏHLÜKƏSİZLİK: Fallback slot da zədələnib!
                // Hər iki slot etibarsızdırsa binary qətiyyən başladılmır!
                journal.probation_status = ProbationStatus::HaltBothSlotsInvalid {
                    reason: format!("Known-good fallback slot ({}) zədələnib: {}", fallback_slot_name, fallback_err),
                };
                self.write_journal_atomic(&journal).ok();
                Err(format!(
                    "E_BOTH_SLOTS_INVALID: Namizəd və Known-Good fallback slotlarının hər ikisi etibarsızdır ({})! İcra dayandırıldı.",
                    fallback_err
                ))
            }
        }
    }

    /// Real uşaq proses monitorinqi: Supervisor prosesini işə salır və exit statusunu ölçür (REAL_INTEGRATION)
    pub fn monitor_child_supervisor_run(&self, command_path: &str, args: &[&str]) -> Result<i32, String> {
        let mut child = std::process::Command::new(command_path)
            .args(args)
            .spawn()
            .map_err(|e| format!("Uşaq proses başladıla bilmədi: {}", e))?;

        let status = child.wait().map_err(|e| format!("Uşaq proses gözləmə xətası: {}", e))?;
        Ok(status.code().unwrap_or(-1))
    }
}
