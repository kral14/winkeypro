// WinKey Pro — Diaqnostika, Təhlükəsiz Canary Scan, Bounded Outbox və Deduplication

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticEvent {
    pub schema_version: String,
    pub event_id: String,
    pub install_run_id: String,
    pub device_id: Option<String>,
    pub operation_id: String,
    pub component: String,
    pub version: String,
    pub stage: String,
    pub event_type: String,
    pub severity: String,
    pub local_time: String,
    pub sequence_no: u64,
    pub error_code: Option<String>,
    pub native_exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
}

pub struct OutboxManager {
    pub outbox_file: PathBuf,
    pub max_file_size_bytes: u64,
}

impl OutboxManager {
    pub fn new(state_dir: &Path, max_file_size_bytes: u64) -> Self {
        let outbox_file = state_dir.join("telemetry_outbox.jsonl");
        Self {
            outbox_file,
            max_file_size_bytes,
        }
    }

    /// Davamlı outbox faylına hadisə əlavə edir; fayl ölçüsü limiti (Bounded Durable Outbox) aşılarsa,
    /// köhnə qeydlər FIFO qaydası ilə rotasiya edilir və fayl hədd daxilində saxlanır.
    pub fn enqueue_event(&self, event: &DiagnosticEvent) -> std::io::Result<()> {
        let line = serde_json::to_string(event)?;
        let line_len = line.len() as u64 + 2;

        // Bounded queue yoxlanışı: Cari ölçü + yeni sətir limiti keçirsə
        if self.outbox_file.exists() {
            let metadata = fs::metadata(&self.outbox_file)?;
            if metadata.len() + line_len > self.max_file_size_bytes {
                // Köhnə hadisələrin bir hissəsini təmizləyərək yeni hadisəyə yer aç (FIFO Drop)
                let existing = self.read_pending_events();
                if !existing.is_empty() {
                    let keep_count = existing.len().saturating_sub(existing.len() / 2 + 1);
                    let to_keep = &existing[keep_count..];

                    let tmp_path = self.outbox_file.with_extension("tmp");
                    {
                        let mut tmp_file = File::create(&tmp_path)?;
                        for evt in to_keep {
                            let l = serde_json::to_string(evt)?;
                            writeln!(tmp_file, "{}", l)?;
                        }
                        tmp_file.sync_all()?;
                    }
                    fs::rename(&tmp_path, &self.outbox_file)?;
                }
            }
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.outbox_file)?;

        writeln!(file, "{}", line)?;
        file.sync_all()?;
        Ok(())
    }

    pub fn read_pending_events(&self) -> Vec<DiagnosticEvent> {
        let mut events = Vec::new();
        if let Ok(file) = fs::File::open(&self.outbox_file) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                if let Ok(evt) = serde_json::from_str::<DiagnosticEvent>(&line) {
                    events.push(evt);
                }
            }
        }
        events
    }

    /// Serverdən ACK alındıqdan sonra göndərilmiş hadisələri outbox-dan atomik silir (ACK-based Pruning)
    pub fn acknowledge_events(&self, acknowledged_event_ids: &[String]) -> std::io::Result<()> {
        let pending = self.read_pending_events();
        let ack_set: HashSet<&String> = acknowledged_event_ids.iter().collect();

        let remaining: Vec<DiagnosticEvent> = pending
            .into_iter()
            .filter(|e| !ack_set.contains(&e.event_id))
            .collect();

        let tmp_path = self.outbox_file.with_extension("tmp");
        {
            let mut tmp_file = File::create(&tmp_path)?;
            for evt in &remaining {
                let line = serde_json::to_string(evt)?;
                writeln!(tmp_file, "{}", line)?;
            }
            tmp_file.sync_all()?;
        }
        fs::rename(&tmp_path, &self.outbox_file)?;
        Ok(())
    }

    pub fn clear_outbox(&self) -> std::io::Result<()> {
        if self.outbox_file.exists() {
            fs::remove_file(&self.outbox_file)?;
        }
        Ok(())
    }

    /// Təhlükəsiz Secret Canary Scan:
    /// DİQQƏT: Aşkar edilən secret-in özü heç bir halda xəta mətninə və ya loglara daxil edilmir!
    /// Yalnız təhlükəsiz kateqoriya qaytarılır.
    pub fn scan_for_secrets(
        &self,
        canary_rules: &[(&'static str, &'static str)], // (category, secret_pattern)
    ) -> Result<(), String> {
        if !self.outbox_file.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&self.outbox_file).map_err(|e| e.to_string())?;
        for (category, secret) in canary_rules {
            if content.contains(secret) {
                // Təhlükəsiz xəta formatı: secret məzmunu gizlədilir!
                return Err(format!(
                    "CANARY_LEAK_DETECTED: Outbox faylında məxfi məlumat aşkarlanaraq bloklandı. Kateqoriya: [{}]",
                    category
                ));
            }
        }
        Ok(())
    }
}

/// Server tərəfində davamlı Deduplication Məntiqi (Server-Side Dedup)
pub struct ServerDedupStorage {
    processed_event_ids: std::sync::Mutex<HashSet<String>>,
}

impl ServerDedupStorage {
    pub fn new() -> Self {
        Self {
            processed_event_ids: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// At-least-once çatdırılma zamanı event_id üzrə dedup yoxlayır
    pub fn ingest_event(&self, event: &DiagnosticEvent) -> bool {
        let mut ids = self.processed_event_ids.lock().unwrap();
        if ids.contains(&event.event_id) {
            false // Duplicate!
        } else {
            ids.insert(event.event_id.clone());
            true // Yeni hadisə qəbul edildi
        }
    }
}

pub fn classify_installer_outcome(
    is_code_started: bool,
    win32_last_error: Option<u32>,
) -> (String, Option<String>) {
    if !is_code_started {
        ("SUSPECTED_STALL".to_string(), None)
    } else if let Some(err) = win32_last_error {
        if err == 1223 {
            ("ELEVATION_CANCELLED".to_string(), Some("E_UAC_REJECTED".to_string()))
        } else {
            ("INSTALL_FAILED".to_string(), Some(format!("E_WIN32_{}", err)))
        }
    } else {
        ("INSTALL_SUCCESS".to_string(), None)
    }
}
