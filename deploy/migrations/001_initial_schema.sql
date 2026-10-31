-- WinKey Pro Production Database Schema (SQLite / PostgreSQL Compatible)
-- Spesifikasiya: plan/GEMINI_FINAL_ALL_REMAINING.md Bölmə 3

-- 1. Cihazlar Cədvəli
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    computer_name TEXT NOT NULL,
    public_key_hex TEXT NOT NULL,
    device_secret_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING', -- PENDING, ACTIVE, REVOKED
    owner_sid TEXT,
    created_at REAL NOT NULL,
    last_seen_at REAL NOT NULL,
    locked INTEGER DEFAULT 0,
    pin_ready INTEGER DEFAULT 0
);

-- 2. Cütləşmə Sorğuları (QR One-Time Pair Codes)
CREATE TABLE IF NOT EXISTS pairing_requests (
    pair_code TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    challenge_hex TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING', -- PENDING, CLAIMED, EXPIRED, REJECTED
    expires_at REAL NOT NULL,
    created_at REAL NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- 3. Mobil Sessiyalar (Device-Scoped Bearer Tokens)
CREATE TABLE IF NOT EXISTS mobile_sessions (
    session_token TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    scope TEXT NOT NULL DEFAULT 'mobile_remote',
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- 4. Komandalar Cədvəli (Lock / Unlock)
CREATE TABLE IF NOT EXISTS commands (
    command_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    action TEXT NOT NULL, -- lock, unlock, mock
    status TEXT NOT NULL DEFAULT 'pending', -- pending, delivered, completed, failed
    created_at REAL NOT NULL,
    completed_at REAL,
    result_status TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- 5. Bounded Telemetriya Hadisələri
CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id TEXT PRIMARY KEY,
    install_run_id TEXT,
    device_id TEXT,
    component TEXT NOT NULL,
    version TEXT NOT NULL,
    stage TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    error_code TEXT,
    native_exit_code INTEGER,
    duration_ms INTEGER,
    local_time REAL,
    received_at REAL NOT NULL
);

-- 6. Audit İzləmə Loqları (Yalnız Sahib Admin)
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_device_id TEXT,
    timestamp REAL NOT NULL,
    details TEXT
);

-- İndekslər
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_commands_device_status ON commands(device_id, status);
CREATE INDEX IF NOT EXISTS idx_telemetry_device ON telemetry_events(device_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_created ON telemetry_events(received_at);
