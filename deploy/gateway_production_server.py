"""
WinKey Pro — Production Gateway & Multi-Tenant Backend Server
Spesifikasiya: plan/GEMINI_FINAL_ALL_REMAINING.md və plan/GEMINI_FINAL_BATCH_REVISION.md

Təhlükəsizlik Zəmanətləri:
1. Strict Public Key & Cryptographic Nonce/Proof Verification (/agent/register)
2. One-Use Atomic Pairing with Anti-Replay (/pair) — Naməlum kod qətiyyən qəbul olunmur!
3. Authenticated Agent Polling & State Ownership (/agent/poll, /agent/result)
4. Multi-Tenant IDOR Qoruması & Zero-PIN Şəbəkə Qadağası
5. Dinamik / Mühit Əsaslı Admin Secret (No Hardcoded Secrets)
6. Zəngin Avant-Garde Dark/Emerald Mobil PWA İnterfeysi
"""

import os
import sys
import json
import time
import sqlite3
import secrets
import hashlib
from typing import Dict, Any, Optional
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric import ed25519

if not __package__:
    # Keep the documented direct-script entrypoint working with shared modules.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Dinamik Admin Secret — heç vaxt hardcode edilmir!
_RUNTIME_ADMIN_SECRET = secrets.token_hex(32)
ADMIN_SECRET = _RUNTIME_ADMIN_SECRET

def get_admin_secret() -> str:
    return os.environ.get("WINKEY_ADMIN_SECRET") or ADMIN_SECRET

# Real Update Delivery Repository Qovluğu
UPDATES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "pre_signed_slot_a"))

def get_updates_dir() -> str:
    return os.environ.get("WINKEY_UPDATES_DIR") or UPDATES_DIR

class ProductionDatabase:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self.get_conn() as conn:
            from deploy.account_service import initialize_accounts
            initialize_accounts(conn)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    computer_name TEXT NOT NULL,
                    public_key_hex TEXT NOT NULL,
                    device_secret_hash TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_at DOUBLE PRECISION NOT NULL,
                    last_seen_at DOUBLE PRECISION NOT NULL,
                    locked INTEGER DEFAULT 0,
                    pin_ready INTEGER DEFAULT 0,
                    owner_approved INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS challenges (
                    nonce TEXT PRIMARY KEY,
                    purpose TEXT NOT NULL,
                    device_id TEXT,
                    created_at DOUBLE PRECISION NOT NULL,
                    expires_at DOUBLE PRECISION NOT NULL,
                    used INTEGER DEFAULT 0
                )
            """)
            conn.execute("""CREATE TABLE IF NOT EXISTS device_versions (
                device_id TEXT PRIMARY KEY,
                worker_version TEXT NOT NULL,
                reported_at DOUBLE PRECISION NOT NULL
            )""")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pairing_requests (
                    pair_code TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    challenge_hex TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    expires_at DOUBLE PRECISION NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL,
                    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mobile_sessions (
                    session_token TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL,
                    expires_at DOUBLE PRECISION NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'mobile_remote',
                    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS commands (
                    command_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at DOUBLE PRECISION NOT NULL,
                    completed_at DOUBLE PRECISION,
                    result_status TEXT,
                    claim_owner TEXT,
                    claim_expires_at DOUBLE PRECISION,
                    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
                )
            """)
            # Dynamic migration for pre-existing commands tables lacking claim columns
            existing_cols = set()
            try:
                if hasattr(self, "pool"):
                    rows = conn.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'commands' AND table_schema = current_schema()").fetchall()
                    existing_cols = {r[0] if isinstance(r, (tuple, list)) else r["column_name"] for r in rows}
                else:
                    rows = conn.execute("PRAGMA table_info(commands)").fetchall()
                    existing_cols = {r[1] if isinstance(r, (tuple, list)) else r["name"] for r in rows}
            except Exception:
                pass
            if existing_cols:
                if "claim_owner" not in existing_cols:
                    conn.execute("ALTER TABLE commands ADD COLUMN claim_owner TEXT")
                if "claim_expires_at" not in existing_cols:
                    conn.execute("ALTER TABLE commands ADD COLUMN claim_expires_at DOUBLE PRECISION")
            conn.execute("CREATE INDEX IF NOT EXISTS commands_status_expiry ON commands(status, claim_expires_at)")
            conn.execute("""
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
                    duration_ms INTEGER,
                    local_time DOUBLE PRECISION,
                    received_at DOUBLE PRECISION NOT NULL
                )
            """)
            # Upgrade existing valid pairings; never resurrect expired tokens.
            # expires_at=0 explicitly means paired until revoked.
            conn.execute("UPDATE mobile_sessions SET expires_at = 0 WHERE expires_at > ?", (time.time(),))
            conn.commit()

def get_mobile_html() -> str:
    return """<!DOCTYPE html>
<html lang="az">
<head>
    <meta charset="utf-8">
    <title>WinKey Pro — Mobil İdarəetmə</title>
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-title" content="WinKey">
    <meta name="theme-color" content="#0c0f0d">
    <link id="appManifest" rel="manifest" href="/mobile-assets/manifest.webmanifest">
    <link rel="apple-touch-icon" href="/mobile-assets/icon.png">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
    <style>
        :root {
            --bg: #0c0f0d;
            --card-bg: #141a16;
            --card-border: #232d26;
            --accent-green: #c8f279;
            --accent-green-hover: #b5e462;
            --accent-green-glow: rgba(200, 242, 121, 0.25);
            --accent-cyan: #38bdf8;
            --accent-cyan-hover: #0ea5e9;
            --accent-cyan-glow: rgba(56, 189, 248, 0.25);
            --danger: #ef4444;
            --danger-hover: #dc2626;
            --danger-glow: rgba(239, 68, 68, 0.25);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --text-dim: #6b7280;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            background-color: var(--bg);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 16px;
            position: relative;
            overflow-x: hidden;
        }

        .mobile-wrapper {
            width: 100%;
            max-width: 440px;
            display: flex;
            flex-direction: column;
            gap: 18px;
        }

        /* Header */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 4px;
        }

        .logo {
            font-size: 1.15rem;
            font-weight: 800;
            letter-spacing: -0.3px;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .logo span {
            color: var(--accent-green);
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        /* Status Badge */
        .badge {
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            padding: 4px 9px;
            border-radius: 9999px;
            display: flex;
            align-items: center;
            gap: 5px;
            text-transform: uppercase;
        }

        .badge-online {
            background: rgba(200, 242, 121, 0.12);
            color: var(--accent-green);
            border: 1px solid rgba(200, 242, 121, 0.3);
        }

        .badge-offline {
            background: rgba(239, 68, 68, 0.15);
            color: var(--danger);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: currentColor;
            box-shadow: 0 0 8px currentColor;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.85); }
        }

        /* Header Icon Buttons */
        .icon-btn {
            width: 38px;
            height: 38px;
            border-radius: 12px;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            color: var(--text-main);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            position: relative;
            transition: all 0.2s ease;
        }

        .icon-btn:hover {
            border-color: #3f4e43;
            transform: translateY(-1px);
        }

        .icon-btn:active {
            transform: scale(0.95);
        }

        .icon-btn.power {
            color: var(--danger);
            border-color: rgba(239, 68, 68, 0.25);
            background: rgba(239, 68, 68, 0.08);
        }

        .icon-btn.power:hover {
            background: rgba(239, 68, 68, 0.18);
            border-color: var(--danger);
        }

        .badge-count {
            position: absolute;
            top: -4px;
            right: -4px;
            background: var(--danger);
            color: #fff;
            font-size: 0.65rem;
            font-weight: 700;
            min-width: 17px;
            height: 17px;
            padding: 0 4px;
            border-radius: 9999px;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 2px solid var(--bg);
        }

        /* Main Card */
        .card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 24px;
            padding: 24px 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            box-shadow: 0 12px 30px rgba(0, 0, 0, 0.4);
            position: relative;
            overflow: hidden;
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent-green), transparent);
            opacity: 0.6;
        }

        /* PC Device Info */
        .device-info {
            text-align: center;
            margin-bottom: 24px;
            width: 100%;
        }

        .device-name {
            font-size: 1.35rem;
            font-weight: 800;
            letter-spacing: -0.4px;
            color: #ffffff;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .device-sub {
            font-size: 0.78rem;
            color: var(--text-muted);
            margin-top: 4px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }

        .device-state-tag {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            margin-top: 10px;
            letter-spacing: 0.3px;
        }

        .state-locked {
            background: rgba(245, 158, 11, 0.12);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }

        .state-unlocked {
            background: rgba(200, 242, 121, 0.12);
            color: var(--accent-green);
            border: 1px solid rgba(200, 242, 121, 0.3);
        }

        /* Circular Action Button */
        .circle-button-container {
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 18px 0 24px;
            width: 210px;
            height: 210px;
        }

        .circle-ring {
            position: absolute;
            width: 210px;
            height: 210px;
            border-radius: 50%;
            border: 2px dashed rgba(200, 242, 121, 0.25);
            animation: rotateRing 20s linear infinite;
        }

        @keyframes rotateRing {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .circle-btn {
            width: 180px;
            height: 180px;
            border-radius: 50%;
            border: none;
            outline: none;
            cursor: pointer;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 8px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            font-size: 0.92rem;
            box-shadow: 0 10px 28px rgba(0, 0, 0, 0.5);
            transition: all 0.25s cubic-bezier(0.34, 1.56, 0.64, 1);
            position: relative;
            z-index: 2;
        }

        .circle-btn:active {
            transform: scale(0.93);
        }

        .circle-btn.mode-unlock {
            background: linear-gradient(145deg, #c8f279, #9ed840);
            color: #0c1708;
            box-shadow: 0 0 35px var(--accent-green-glow), 0 10px 25px rgba(0,0,0,0.4);
        }

        .circle-btn.mode-unlock:hover {
            box-shadow: 0 0 45px var(--accent-green-glow), 0 12px 30px rgba(0,0,0,0.5);
            transform: translateY(-2px);
        }

        .circle-btn.mode-lock {
            background: linear-gradient(145deg, #38bdf8, #0284c7);
            color: #041725;
            box-shadow: 0 0 35px var(--accent-cyan-glow), 0 10px 25px rgba(0,0,0,0.4);
        }

        .circle-btn.mode-lock:hover {
            box-shadow: 0 0 45px var(--accent-cyan-glow), 0 12px 30px rgba(0,0,0,0.5);
            transform: translateY(-2px);
        }

        .circle-btn .btn-icon {
            width: 46px;
            height: 46px;
            stroke-width: 2.2;
        }

        .circle-btn.busy {
            pointer-events: none;
            opacity: 0.85;
        }

        /* Action Toast / Mini Banner */
        .action-toast {
            width: 100%;
            border-radius: 14px;
            padding: 12px 14px;
            font-size: 0.86rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            cursor: pointer;
            transition: all 0.2s ease;
            background: #17201a;
            border: 1px solid var(--card-border);
            color: var(--text-muted);
        }

        .action-toast:hover {
            transform: translateY(-1px);
        }

        .toast-left {
            display: flex;
            align-items: center;
            gap: 10px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .toast-indicator {
            width: 22px;
            height: 22px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 800;
            flex-shrink: 0;
        }

        .action-toast.success {
            background: rgba(200, 242, 121, 0.1);
            border-color: rgba(200, 242, 121, 0.4);
            color: #d8f89c;
        }

        .action-toast.success .toast-indicator {
            background: var(--accent-green);
            color: #0c1708;
        }

        .action-toast.error {
            background: rgba(239, 68, 68, 0.12);
            border-color: rgba(239, 68, 68, 0.4);
            color: #fca5a5;
        }

        .action-toast.error .toast-indicator {
            background: var(--danger);
            color: #fff;
        }

        .toast-click-hint {
            font-size: 0.7rem;
            color: var(--text-dim);
            font-weight: 500;
            white-space: nowrap;
        }

        .notice {
            font-size: 0.74rem;
            color: var(--text-dim);
            text-align: center;
            line-height: 1.45;
            padding: 0 10px;
            margin-top: 8px;
        }

        /* Modal Overlay & Drawer */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(4px);
            z-index: 100;
            display: none;
            align-items: flex-end;
            justify-content: center;
        }

        .modal-overlay.open {
            display: flex;
        }

        .modal-drawer {
            background: #151c17;
            border: 1px solid #28362b;
            border-radius: 24px 24px 0 0;
            width: 100%;
            max-width: 480px;
            max-height: 82vh;
            display: flex;
            flex-direction: column;
            animation: slideUp 0.25s cubic-bezier(0.16, 1, 0.3, 1);
            box-shadow: 0 -10px 40px rgba(0,0,0,0.6);
        }

        @keyframes slideUp {
            from { transform: translateY(100%); }
            to { transform: translateY(0); }
        }

        .drawer-header {
            padding: 18px 20px 14px;
            border-bottom: 1px solid var(--card-border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .drawer-title {
            font-size: 1.05rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 8px;
            color: #fff;
        }

        .drawer-close {
            background: transparent;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 4px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .drawer-close:hover {
            color: #fff;
            background: rgba(255,255,255,0.08);
        }

        .drawer-actions-bar {
            display: flex;
            gap: 10px;
            padding: 12px 20px;
            background: #111713;
            border-bottom: 1px solid #1f2a22;
        }

        .action-pill-btn {
            flex: 1;
            padding: 8px 12px;
            border-radius: 10px;
            border: 1px solid #2e3e32;
            background: #18221b;
            color: var(--text-main);
            font-size: 0.78rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .action-pill-btn:hover {
            background: #223026;
            border-color: var(--accent-green);
            color: var(--accent-green);
        }

        .action-pill-btn:active {
            transform: scale(0.97);
        }

        .drawer-content {
            padding: 16px 20px 24px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 12px;
            min-height: 180px;
        }

        .notification-item {
            background: #19231d;
            border: 1px solid #233128;
            border-radius: 12px;
            padding: 12px 14px;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .notification-item:hover {
            border-color: #374b3f;
            background: #1f2c25;
        }

        .notif-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }

        .notif-tag {
            font-size: 0.7rem;
            font-weight: 700;
            padding: 2px 7px;
            border-radius: 6px;
        }

        .notif-tag.success {
            background: rgba(200, 242, 121, 0.15);
            color: var(--accent-green);
        }

        .notif-tag.error {
            background: rgba(239, 68, 68, 0.15);
            color: var(--danger);
        }

        .notif-time {
            font-size: 0.7rem;
            color: var(--text-dim);
        }

        .notif-title {
            font-size: 0.84rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 4px;
        }

        .notif-summary {
            font-size: 0.76rem;
            color: var(--text-muted);
            line-height: 1.35;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }

        .detail-modal-box {
            background: #18221b;
            border: 1px solid #2a3a2e;
            border-radius: 20px;
            width: 90%;
            max-width: 420px;
            padding: 22px;
            margin: auto;
            box-shadow: 0 15px 40px rgba(0,0,0,0.8);
        }

        .detail-tag {
            display: inline-block;
            font-size: 0.72rem;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 6px;
            margin-bottom: 12px;
        }

        .detail-text-area {
            background: #0f1612;
            border: 1px solid #202b23;
            border-radius: 10px;
            padding: 12px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.78rem;
            color: #d1d5db;
            line-height: 1.45;
            max-height: 240px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid rgba(200,242,121,0.3);
            border-radius: 50%;
            border-top-color: #c8f279;
            animation: spin 0.8s linear infinite;
            margin-right: 8px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="mobile-wrapper">
        <section aria-label="Kompüter Seçimi" style="padding:14px 16px;background:var(--card-bg);border-radius:14px;margin-bottom:16px;border:1px solid var(--card-border);">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
                <label for="deviceSelect" style="font-size:0.85rem;font-weight:600;color:var(--accent-green);display:flex;align-items:center;gap:6px;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
                        <line x1="8" y1="21" x2="16" y2="21"></line>
                        <line x1="12" y1="17" x2="12" y2="21"></line>
                    </svg>
                    Kompüter seç:
                </label>
                <span id="deviceCountBadge" style="font-size:0.75rem;padding:2px 8px;background:rgba(34,197,94,0.15);color:var(--accent-green);border-radius:10px;font-weight:600;">1 Cihaz</span>
            </div>
            <select id="deviceSelect" style="display:block;width:100%;padding:10px 12px;color:var(--text-main);background:#101412;border:1px solid var(--card-border);border-radius:8px;font-size:0.9rem;font-weight:500;outline:none;cursor:pointer;"></select>
            <p id="deviceMessage" role="status" style="font-size:.8rem;line-height:1.4;margin:6px 0 0;color:var(--text-dim);"></p>
            <div style="display:none;">
                <button id="deviceAdd"></button>
                <button id="prepareInstall"></button>
                <div id="deviceAddPanel"><form id="deviceAddForm"><input id="deviceName"><button id="deviceScan"></button><video id="deviceCamera"></video><input id="devicePhoto"><input id="devicePairCode"><button id="deviceAddConfirm"></button><button id="deviceAddCancel"></button></form></div>
            </div>
        </section>
        <!-- Header -->
        <header class="header">
            <div class="logo">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--accent-green)">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
                <span>WinKey Mobile Remote</span>
            </div>

            <div class="header-actions">
                <div id="status-badge" class="badge badge-online">
                    <span class="status-dot"></span>
                    <span id="status-badge-text">Onlayn</span>
                </div>

                <!-- Notification Bell -->
                <button class="icon-btn" id="bellBtn" title="Bildirişlər" onclick="openDrawer()">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
                        <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
                    </svg>
                    <span class="badge-count" id="notifBadge">0</span>
                </button>

                <!-- Power / Disconnect Icon -->
                <button class="icon-btn power" id="btn-revoke" title="Bağlantını Kəs" onclick="openDisconnectModal()">
                    <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path>
                        <line x1="12" y1="2" x2="12" y2="12"></line>
                    </svg>
                </button>
            </div>
        </header>

        <!-- Main Card -->
        <main class="card">
            <div class="device-info">
                <div id="dev-name" class="device-name">PC Qoşulur...</div>
                <div id="dev-id" class="device-sub">Cihaz ID: —</div>
                <div id="deviceStateBadge" class="device-state-tag state-locked">
                    <span>🔒 Kompüter Kilidlidir</span>
                </div>
            </div>

            <!-- State-Aware Circular Button -->
            <div class="circle-button-container">
                <div class="circle-ring"></div>
                <button class="circle-btn mode-unlock" id="actionCircleBtn" onclick="triggerCurrentAction()">
                    <svg class="btn-icon" id="actionIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                        <path d="M7 11V7a5 5 0 0 1 9.9-1"></path>
                    </svg>
                    <span id="actionLabel">KİLİDİ AÇ</span>
                </button>
            </div>

            <!-- Action Toast / Live Banner -->
            <div class="action-toast success" id="liveToast" onclick="showLatestDetail()" title="Tam mətni görmək üçün toxunun">
                <div class="toast-left">
                    <div class="toast-indicator" id="toastIcon">✓</div>
                    <span id="action-status">Sistem hazırdır. Əməliyyat gözlənilir.</span>
                </div>
                <span class="toast-click-hint">Detallar ➔</span>
            </div>
        </main>

        <div class="notice">
            Qorunan Zəncir: Telefon yalnız kriptoqrafik əmr siqnalı göndərir. Windows PIN heç vaxt serverə və ya şəbəkəyə çıxmır; yalnız PC-nin təhlükəsiz DPAPI anbarında saxlanılır.
        </div>
    </div>

    <!-- Notification Drawer -->
    <div class="modal-overlay" id="notifDrawerOverlay">
        <div class="modal-drawer">
            <div class="drawer-header">
                <div class="drawer-title">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
                        <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
                    </svg>
                    <span>Bildiriş Tarixçəsi</span>
                </div>
                <button class="drawer-close" onclick="closeDrawer()">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                        <line x1="18" y1="6" x2="6" y2="18"></line>
                        <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                </button>
            </div>

            <div class="drawer-actions-bar">
                <button class="action-pill-btn" onclick="copyNotifications()">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                    </svg>
                    <span>Kopyala</span>
                </button>
                <button class="action-pill-btn" onclick="downloadNotifications()">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                        <polyline points="7 10 12 15 17 10"></polyline>
                        <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                    <span>Endir</span>
                </button>
            </div>

            <div class="drawer-content" id="notifListContainer"></div>
        </div>
    </div>

    <!-- Detail Modal -->
    <div class="modal-overlay" id="detailModalOverlay" style="align-items: center;">
        <div class="detail-modal-box">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <h3 id="detailTitle" style="font-size:1.05rem; font-weight:700;">Ətraflı Məlumat</h3>
                <button class="drawer-close" onclick="closeDetailModal()">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                        <line x1="18" y1="6" x2="6" y2="18"></line>
                        <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                </button>
            </div>
            <div id="detailTag" class="detail-tag">Status</div>
            <div class="detail-text-area" id="detailText"></div>
            <button class="action-pill-btn" style="margin-top:14px; width:100%; padding:10px;" onclick="closeDetailModal()">Bağla</button>
        </div>
    </div>

    <!-- Disconnect Confirmation Modal -->
    <div class="modal-overlay" id="disconnectModalOverlay" style="align-items: center;">
        <div class="detail-modal-box">
            <h3 style="font-size:1.1rem; font-weight:700; color:var(--danger); margin-bottom:10px; display:flex; align-items:center; gap:8px;">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
                    <path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path><line x1="12" y1="2" x2="12" y2="12"></line>
                </svg>
                Bağlantını Kəsmək İstəyirsiniz?
            </h3>
            <p style="font-size:0.82rem; color:var(--text-muted); line-height:1.4; margin-bottom:16px;">
                Bu əməliyyat mobil cihazın bu kompüterlə olan cütləşməsini ləğv edəcək. Yenidən idarə etmək üçün QR kodu yenidən skan etməlisiniz.
            </p>
            <div style="display:flex; gap:10px;">
                <button class="action-pill-btn" style="background:#261818; border-color:var(--danger); color:#fca5a5;" onclick="confirmDisconnect()">Bəli, Kəs</button>
                <button class="action-pill-btn" onclick="closeDisconnectModal()">Ləğv Et</button>
            </div>
        </div>
    </div>

    <script src="/mobile-assets/jsQR.js"></script>
    <script src="/mobile-assets/devices.js"></script>
    <script>
        const urlParams = new URLSearchParams(window.location.search);
        let targetDevice = urlParams.get('device') || localStorage.getItem('winkey_dev_id') || '';
        let pairCode = urlParams.get('code') || '';
        let authToken = localStorage.getItem('winkey_token') || '';

        const devNameEl = document.getElementById('dev-name');
        const devIdEl = document.getElementById('dev-id');
        const badgeEl = document.getElementById('status-badge');
        const badgeTextEl = document.getElementById('status-badge-text');
        const statusBox = document.getElementById('action-status');
        const liveToast = document.getElementById('liveToast');
        const toastIcon = document.getElementById('toastIcon');
        const circleBtn = document.getElementById('actionCircleBtn');
        const actionLabel = document.getElementById('actionLabel');
        const actionIcon = document.getElementById('actionIcon');
        const stateBadge = document.getElementById('deviceStateBadge');
        const notifBadge = document.getElementById('notifBadge');
        const notifListContainer = document.getElementById('notifListContainer');

        let isPcLocked = null;
        let commandBusy = false;
        let desiredAction = null;
        let desiredSince = 0;
        let desiredRequestId = null;
        let diagnosticRequestId = '', diagnosticAction = null;
        let resultController = null;
        let statusBusy = false;
        let pendingCommand = null;
        let deviceEpoch = 0;
        let deviceMutationBusy = false;

        function selectMobileDevice(device, probe = false) {
            if (commandBusy) return false;
            if (probe) return true;
            deviceEpoch++;
            if (wsRetryTimer) clearTimeout(wsRetryTimer);
            if (ws) {
                ws.onclose = ws.onmessage = ws.onerror = ws.onopen = null;
                ws.close(); ws = null;
            }
            wsConnected = false;
            if (resultController) resultController.abort();
            activeCommandResolver = null;
            desiredAction = null;
            savePending(null);
            authToken = device ? device.token : '';
            targetDevice = device ? device.id : '';
            isPcLocked = null;
            statusBusy = false;
            renderState();
            devNameEl.textContent = device ? device.name : 'Kompüter əlavə edin';
            devIdEl.textContent = device ? 'Cihaz ID: ' + device.id : '';
            badgeTextEl.textContent = device ? 'Qoşulur…' : 'Qoşulmayıb';
            badgeEl.className = 'badge badge-offline';
            statusBox.textContent = '';
            if (device) { connectWS(); pollStatus(); }
            return true;
        }

        const SVG_LOCK = '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>';
        const SVG_UNLOCK = '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path>';

        let notificationHistory = [];
        let activeNotification = null;
        try {
            const savedNotifs = JSON.parse(localStorage.getItem('winkey_notif_history') || '[]');
            if (Array.isArray(savedNotifs)) notificationHistory = savedNotifs.slice(-50);
        } catch(e) {}

        function persistNotifications() {
            try { localStorage.setItem('winkey_notif_history', JSON.stringify(notificationHistory)); } catch(e) {}
        }

        function updateBadgeCount() {
            if (notifBadge) notifBadge.textContent = notificationHistory.length;
        }

        function recordNotification(success, title, fullText) {
            const now = new Date();
            const timeStr = now.toTimeString().split(' ')[0];
            const dateStr = now.toISOString().split('T')[0];
            const summary = success ? "Uğurlu" : "Uğursuz oldu, yenidən cəhd edin";

            const notif = {
                id: Date.now(),
                success,
                summary,
                title,
                timestamp: timeStr,
                date: dateStr,
                fullText
            };

            activeNotification = notif;
            notificationHistory.unshift(notif);
            if (notificationHistory.length > 50) notificationHistory = notificationHistory.slice(0, 50);
            persistNotifications();
            updateToast(notif);
            renderDrawerList();
            updateBadgeCount();
        }

        function updateToast(notif) {
            if (!liveToast) return;
            liveToast.className = 'action-toast ' + (notif.success ? 'success' : 'error');
            if (toastIcon) toastIcon.textContent = notif.success ? '✓' : '✕';
            if (statusBox) statusBox.textContent = notif.summary;
        }

        function showLatestDetail() {
            if (activeNotification) {
                showDetailModal(activeNotification);
            } else if (notificationHistory.length > 0) {
                showDetailModal(notificationHistory[0]);
            } else {
                showDetailModal({
                    title: "Sistem Statusu",
                    success: true,
                    fullText: statusBox ? statusBox.textContent : "Sistem hazırdır."
                });
            }
        }

        function showDetailModal(notif) {
            document.getElementById('detailTitle').textContent = notif.title || "Əməliyyat Detalları";
            const tag = document.getElementById('detailTag');
            tag.className = 'detail-tag ' + (notif.success ? 'state-unlocked' : 'state-locked');
            tag.textContent = notif.success ? '✓ Status: Uğurlu' : '✕ Status: Uğursuz';
            document.getElementById('detailText').textContent = notif.fullText || notif.summary || '';
            document.getElementById('detailModalOverlay').classList.add('open');
        }

        function closeDetailModal() {
            document.getElementById('detailModalOverlay').classList.remove('open');
        }

        function openDrawer() {
            renderDrawerList();
            document.getElementById('notifDrawerOverlay').classList.add('open');
        }

        function closeDrawer() {
            document.getElementById('notifDrawerOverlay').classList.remove('open');
        }

        document.getElementById('notifDrawerOverlay').addEventListener('click', (e) => {
            if (e.target === document.getElementById('notifDrawerOverlay')) closeDrawer();
        });

        function renderDrawerList() {
            if (!notifListContainer) return;
            notifListContainer.innerHTML = '';
            if (notificationHistory.length === 0) {
                notifListContainer.innerHTML = '<div style="color:var(--text-dim); text-align:center; padding:30px 0;">Heç bir bildiriş yoxdur.</div>';
                return;
            }

            notificationHistory.forEach(item => {
                const div = document.createElement('div');
                div.className = 'notification-item';
                div.innerHTML = `
                    <div class="notif-top">
                        <span class="notif-tag ${item.success ? 'success' : 'error'}">${item.summary}</span>
                        <span class="notif-time">${item.timestamp}</span>
                    </div>
                    <div class="notif-title">${item.title}</div>
                    <div class="notif-summary">${item.fullText ? item.fullText.split('\\n')[0] : ''}</div>
                `;
                div.onclick = () => showDetailModal(item);
                notifListContainer.appendChild(div);
            });
        }

        function copyNotifications() {
            const text = notificationHistory.map(n => `[${n.date} ${n.timestamp}] ${n.title} - ${n.summary}
${n.fullText}
------------------------`).join('\\n\\n');
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(() => {
                    alert("Bildiriş tarixçəsi panoya kopyalandı!");
                }).catch(() => {
                    alert("Kopyalama xətası.");
                });
            } else {
                alert("Brauzer panoya birbaşa yazmağı dəstəkləmir.");
            }
        }

        function downloadNotifications() {
            const text = notificationHistory.map(n => `[${n.date} ${n.timestamp}] ${n.title} - ${n.summary}
${n.fullText}
------------------------`).join('\\n\\n');
            const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `winkey_bildirisler_${new Date().toISOString().slice(0,10)}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        function openDisconnectModal() {
            document.getElementById('disconnectModalOverlay').classList.add('open');
        }

        function closeDisconnectModal() {
            document.getElementById('disconnectModalOverlay').classList.remove('open');
        }

        async function confirmDisconnect() {
            closeDisconnectModal();
            await revokeDevice();
        }

        function renderState() {
            circleBtn.disabled = isPcLocked === null;
            if (isPcLocked === null) {
                actionLabel.textContent = "YOXLANILIR…";
                stateBadge.innerHTML = "<span>Windows vəziyyəti yoxlanılır…</span>";
                return;
            }
            if (isPcLocked) {
                circleBtn.className = "circle-btn mode-unlock";
                actionLabel.textContent = "KİLİDİ AÇ";
                actionIcon.innerHTML = SVG_UNLOCK;
                stateBadge.className = "device-state-tag state-locked";
                stateBadge.innerHTML = "<span>🔒 Kompüter Kilidlidir</span>";
            } else {
                circleBtn.className = "circle-btn mode-lock";
                actionLabel.textContent = "KİLİDLƏ";
                actionIcon.innerHTML = SVG_LOCK;
                stateBadge.className = "device-state-tag state-unlocked";
                stateBadge.innerHTML = "<span>🔓 Kompüter Açıqdır</span>";
            }
        }

        function triggerCurrentAction() {
            if (isPcLocked === null) return;
            const act = isPcLocked ? 'unlock' : 'lock';
            sendCommand(act);
        }

        try { pendingCommand = JSON.parse(localStorage.getItem('winkey_pending_command') || 'null'); } catch(e) {}
        if (pendingCommand && (pendingCommand.device !== targetDevice ||
            !/^[0-9a-f]{32}$/.test(pendingCommand.requestId) ||
            !['lock', 'unlock'].includes(pendingCommand.action))) pendingCommand = null;
        const hexId = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
        let diagnostics = [];
        let diagnosticsBusy = false, diagnosticsTimer = null;
        try { const saved = JSON.parse(localStorage.getItem('winkey_diagnostics') || '[]'); if (Array.isArray(saved)) diagnostics = saved.slice(-200); } catch(e) {}
        function persistDiagnostics() {
            try { localStorage.setItem('winkey_diagnostics', JSON.stringify(diagnostics)); } catch(e) {}
        }
        function scheduleDiagnostics(delay = 2000) {
            if (diagnosticsTimer) clearTimeout(diagnosticsTimer);
            diagnosticsTimer = setTimeout(() => { diagnosticsTimer = null; flushDiagnostics(); }, delay);
        }
        function mobileEvent(stage, code, duration = null, action = null, requestId = '', error = false) {
            diagnostics.push({id: hexId(), device: targetDevice, stage, code,
                duration_ms: duration === null ? null : Math.min(600000, Math.max(0, Math.round(duration))),
                action, request_id: requestId || '', error, local_time: Date.now() / 1000});
            diagnostics = diagnostics.slice(-200);
            persistDiagnostics();
            scheduleDiagnostics();
        }
        async function flushDiagnostics() {
            if (!authToken || !targetDevice || diagnosticsBusy) return;
            if (commandBusy) { scheduleDiagnostics(); return; }
            const batch = diagnostics.filter(e => e.device === targetDevice).slice(0, 20);
            if (!batch.length) return;
            diagnosticsBusy = true;
            const control = new AbortController();
            const timer = setTimeout(() => control.abort(), 3000);
            try {
                const response = await fetch('/mobile/telemetry', {method: 'POST', cache: 'no-store',
                    signal: control.signal, headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken},
                    body: JSON.stringify({device_id: targetDevice, events: batch})});
                if (response.ok) {
                    const data = await response.json();
                    const sent = new Set(Array.isArray(data.accepted) ? data.accepted : []);
                    diagnostics = diagnostics.filter(e => !sent.has(e.id));
                    persistDiagnostics();
                }
            } catch(e) {} finally {
                clearTimeout(timer); diagnosticsBusy = false;
                if (diagnostics.some(e => e.device === targetDevice)) scheduleDiagnostics(10000);
            }
        }
        function displayDiagnostic(text) {
            const rules = [
                ['Əvvəlki nəticə', 'UI_RESULT_UNCONFIRMED'], ['Nəticə hələ', 'UI_RESULT_UNCONFIRMED'],
                ['Server cavabı alınmadı', 'UI_NETWORK_UNKNOWN'], ['Telefon bağlantısı', 'UI_AUTH_ERROR'],
                ['İcra uğursuz', 'UI_RESULT_FAILED'], ['Cütləşmə xətası', 'UI_PAIR_FAILED'],
                ['Şəbəkə xətası', 'UI_NETWORK_ERROR'], ['Xəta:', 'UI_RESPONSE_ERROR'],
                ['Əmr serverə çatdı', 'UI_SERVER_ACCEPTED'], ['İcra tamamlandı', 'UI_RESULT_OK'],
                ['Son istək', 'UI_LATEST_PENDING'], ['Əmr göndərilir', 'UI_SENDING'],
                ['Əvvəlki əmr', 'UI_SUPERSEDED']];
            const rule = rules.find(([prefix]) => text.startsWith(prefix));
            const code = (text.match(/E_[A-Z0-9_]+/) || [])[0];
            if (rule || code) mobileEvent('display', code || rule[1], null,
                desiredAction || diagnosticAction, desiredAction ? '' : diagnosticRequestId,
                Boolean(code || (rule && /ERROR|FAILED|UNKNOWN|UNCONFIRMED/.test(rule[1]))));
        }
        if (typeof MutationObserver !== 'undefined') {
            new MutationObserver(() => displayDiagnostic(statusBox.textContent || '')).observe(statusBox, {childList: true, subtree: true, characterData: true});
        }
        if (window.addEventListener) {
            window.addEventListener('online', () => flushDiagnostics());
            window.addEventListener('error', () => mobileEvent('runtime', 'JS_RUNTIME_ERROR', null, null, '', true));
            window.addEventListener('unhandledrejection', () => mobileEvent('runtime', 'JS_UNHANDLED_REJECTION', null, null, '', true));
        }
        const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
        function savePending(value) {
            pendingCommand = value;
            if (value) localStorage.setItem('winkey_pending_command', JSON.stringify(value));
            else localStorage.removeItem('winkey_pending_command');
        }
        async function request(url, options = {}, timeoutMs = 4000) {
            const controller = new AbortController();
            const upstream = options.signal;
            const abort = () => controller.abort();
            if (upstream) {
                if (upstream.aborted) abort();
                else upstream.addEventListener('abort', abort, {once: true});
            }
            const timer = setTimeout(() => controller.abort(), timeoutMs);
            const start = performance.now();
            const isCommand = options.method === 'POST' && url.endsWith('/command');
            const commandMeta = isCommand ? JSON.parse(options.body) : null;
            try {
                const response = await fetch(url, {...options, signal: controller.signal, cache: 'no-store'});
                const data = await response.json();
                if (isCommand) {
                    mobileEvent('request', 'HTTP_' + response.status, performance.now() - start, commandMeta.action, commandMeta.request_id, !response.ok);
                    const serverMs = response.headers ? response.headers.get('X-App-Duration-Ms') : null;
                    if (serverMs !== null) mobileEvent('server', 'SERVER_PROCESSING', Number(serverMs), commandMeta.action, commandMeta.request_id);
                }
                return {ok: response.ok, status: response.status, json: async () => data,
                        elapsedMs: Math.round(performance.now() - start),
                        serverMs: response.headers ? Number(response.headers.get('X-App-Duration-Ms')) : null};
            } catch(e) {
                if (isCommand) mobileEvent('request', controller.signal.aborted ? 'REQUEST_TIMEOUT' : 'NETWORK_ERROR',
                    performance.now() - start, commandMeta.action, commandMeta.request_id, true);
                throw e;
            } finally {
                clearTimeout(timer);
                if (upstream) upstream.removeEventListener('abort', abort);
            }
        }
        function setBusy(value) {
            commandBusy = value;
            if (circleBtn) {
                if (value) circleBtn.classList.add('busy');
                else circleBtn.classList.remove('busy');
            }
        }

        async function init() {
            renderState();
            updateBadgeCount();
            if (notificationHistory.length > 0) {
                updateToast(notificationHistory[0]);
            }

            if (window.WinKeyDevices) {
                try {
                    const device = await window.WinKeyDevices.start(selectMobileDevice);
                    selectMobileDevice(device);
                    setInterval(pollStatus, 3000);
                    scheduleDiagnostics();
                } catch (error) {
                    statusBox.textContent = 'Qoşulma alınmadı: ' + String(error) + '. Yeni cihaz əlavə et düyməsini istifadə edin.';
                }
                return;
            }
            if (pairCode) {
                statusBox.innerHTML = '<span class="spinner"></span>QR cütləşmə kodu göndərilir...';
                try {
                    const r = await request('/pair', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({pair_code: pairCode})
                    });
                    const res = await r.json();
                    if (r.ok && res.session_token) {
                        authToken = res.session_token;
                        targetDevice = res.device_id;
                        localStorage.setItem('winkey_token', authToken);
                        localStorage.setItem('winkey_dev_id', targetDevice);
                        savePending(null);
                        if (window.history.replaceState) {
                            window.history.replaceState({}, document.title, window.location.pathname);
                        }
                        recordNotification(true, "Cütləşmə", "Cütləşmə uğurla tamamlandı! Cihaz ID: " + targetDevice);
                    } else {
                        recordNotification(false, "Cütləşmə Xətası", "Cütləşmə xətası: " + (res.message || res.error));
                    }
                } catch(e) {
                    recordNotification(false, "Şəbəkə Xətası", "Şəbəkə xətası: " + e);
                }
            }
            if (targetDevice) {
                devIdEl.textContent = 'Cihaz ID: ' + targetDevice;
                connectWS();
                pollStatus();
                setInterval(pollStatus, 3000);
                if (pendingCommand) sendCommand(pendingCommand.action, true);
                scheduleDiagnostics();
            }
        }

        async function pollStatus() {
            if (wsConnected) return;
            if (!authToken || !targetDevice || commandBusy || statusBusy || document.hidden) return;
            statusBusy = true;
            const expectedEpoch = deviceEpoch;
            try {
                const r = await request('/devices/' + encodeURIComponent(targetDevice) + '/status', {
                    headers: {'Authorization': 'Bearer ' + authToken}
                });
                if (r.ok) {
                    const d = await r.json();
                    if (deviceEpoch !== expectedEpoch) return;
                    devNameEl.textContent = window.WinKeyDevices?.current()?.name || d.computer_name || targetDevice;
                    isPcLocked = Boolean(d.locked);
                    renderState();
                    badgeTextEl.textContent = 'Onlayn';
                    badgeEl.className = 'badge badge-online';
                } else if (r.status === 403 || r.status === 401) {
                    badgeTextEl.textContent = 'İcazəsiz';
                    badgeEl.className = 'badge badge-offline';
                }
            } catch(e) {} finally { if (deviceEpoch === expectedEpoch) statusBusy = false; }
        }

        async function sendCommand(action, resume = false, tappedAt = performance.now(), requestId = null) {
            if (deviceMutationBusy || window.WinKeyDevices?.isPairing()) {
                statusBox.textContent = 'Cihaz əlavə etmənin və ya bağlantı dəyişməsinin bitməsini gözləyin.';
                return;
            }
            if (!authToken || !targetDevice) return;
            if (!resume && !requestId) {
                requestId = hexId();
                mobileEvent('tap', 'COMMAND_TAP', 0, action, requestId);
            }
            if (commandBusy) {
                desiredAction = action;
                desiredSince = tappedAt;
                desiredRequestId = requestId;
                if (resultController) resultController.abort();
                statusBox.textContent = 'Son istək saxlanıldı (' + action + '). Göndərilir...';
                return;
            }
            if (!resume) savePending(null);
            if (!pendingCommand) {
                savePending({device: targetDevice, action,
                    requestId: requestId || hexId()});
            }
            action = pendingCommand.action;
            diagnosticRequestId = pendingCommand.requestId;
            diagnosticAction = action;
            setBusy(true);
            const sendStarted = tappedAt;

            if (wsConnected && ws && (ws.readyState === 1 || (typeof WebSocket !== 'undefined' && ws.readyState === WebSocket.OPEN))) {
                try {
                    ws.send(JSON.stringify({
                        type: 'command',
                        action: action,
                        request_id: pendingCommand.requestId
                    }));
                    statusBox.innerHTML = '<span class="spinner"></span>Əmr icra olunur (' + action + ')...';
                } catch(e) {
                    recordNotification(false, "WebSocket Xətası", "WebSocket xətası: " + e.message);
                } finally {
                    setBusy(false);
                    if (desiredAction !== null) {
                        const next = desiredAction;
                        const nextSince = desiredSince;
                        const nextId = desiredRequestId;
                        desiredAction = null;
                        await sendCommand(next, false, nextSince, nextId);
                    }
                }
                return;
            }

            statusBox.innerHTML = '<span class="spinner"></span>Əmr göndərilir (' + action + ')...';
            try {
                let r;
                for (let retry = 0; retry < 2; retry++) {
                    try { r = await request('/devices/' + encodeURIComponent(targetDevice) + '/command', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken},
                    body: JSON.stringify({action: action, request_id: pendingCommand.requestId})
                    }); break; }
                    catch(e) { if (retry === 1) throw e; }
                }
                const res = await r.json();
                if (desiredAction !== null) return;
                if (r.ok && res.command_id) {
                    const sentMs = Math.round(performance.now() - sendStarted);
                    statusBox.textContent = 'Əmr qəbul olundu. PC-nin icrası gözlənilir...';
                    await pollCommandResult(res.command_id, action, sentMs, sendStarted, r.serverMs);
                } else {
                    if (r.status < 500) savePending(null);
                    recordNotification(false, "Əmr Xətası", "Xəta: " + (res.message || res.error || "Bilinməyən xəta"));
                }
            } catch(e) {
                recordNotification(false, "Şəbəkə Xətası", "Server cavabı alınmadı. Şəbəkə bağlantısını yoxlayın.");
            } finally {
                setBusy(false);
                if (desiredAction !== null) {
                    const next = desiredAction;
                    const nextSince = desiredSince;
                    const nextId = desiredRequestId;
                    desiredAction = null;
                    await sendCommand(next, false, nextSince, nextId);
                } else pollStatus();
            }
        }

        async function pollCommandResult(cmdId, action, sentMs = 0, started = performance.now(), serverMs = null) {
            if (wsConnected) return;
            const deadline = performance.now() + 20000;
            while (performance.now() < deadline) {
                if (desiredAction !== null) return;
                try {
                    resultController = new AbortController();
                    const r = await request('/commands/' + encodeURIComponent(cmdId), {
                        headers: {'Authorization': 'Bearer ' + authToken},
                        signal: resultController.signal
                    }, Math.min(3000, Math.max(1, deadline - performance.now())));
                    if (desiredAction !== null) return;
                    if (r.status === 401 || r.status === 403) {
                        savePending(null);
                        recordNotification(false, "İcazə Xətası", "Telefon bağlantısı ləğv edilib və ya giriş icazəsi yoxdur.");
                        return;
                    }
                    if (r.ok) {
                        const cmd = await r.json();
                        if (cmd.status === 'superseded') {
                            savePending(null);
                            recordNotification(false, "Əmr Əvəzləndi", "Əvvəlki əmr son istəklə əvəz edilib.");
                            return;
                        }
                        if (cmd.status === 'executed' || cmd.status === 'completed') {
                            mobileEvent('total', 'COMMAND_COMPLETED', performance.now() - started, action, pendingCommand ? pendingCommand.requestId : '');
                            savePending(null);
                            const totalMs = Math.round(performance.now() - started);
                            const detailInfo = "Status: 200 OK\\n" +
                                "Əmr: " + action.toUpperCase() + "\\n" +
                                "Nəticə: " + (cmd.result || 'Uğurlu') + "\\n" +
                                "Göndəriş: " + sentMs + " ms\\n" +
                                "Server icrası: " + serverMs + " ms\\n" +
                                "Ümumi müddət: " + totalMs + " ms";
                            recordNotification(true, action === 'unlock' ? "Kilid Açma İcrası" : "Kilidləmə İcrası", detailInfo);
                            isPcLocked = (action === 'lock');
                            renderState();
                            pollStatus();
                            return;
                        } else if (cmd.status === 'failed') {
                            mobileEvent('total', 'COMMAND_FAILED', performance.now() - started, action, pendingCommand ? pendingCommand.requestId : '', true);
                            savePending(null);
                            const failInfo = "Xəta Statusu: Failed\\nƏmr: " + action.toUpperCase() + "\\nSəbəb: " + (cmd.result || 'Xəta') + "\\nÜmumi müddət: " + Math.round(performance.now() - started) + " ms";
                            recordNotification(false, "İcra Uğursuz Oldu", failInfo);
                            return;
                        }
                    }
                } catch(e) {} finally { resultController = null; }
                if (desiredAction !== null) return;
                await pause(250);
            }
            recordNotification(false, "Cavab Təsdiqlənmədi", "Əvvəlki nəticə təsdiqlənməyib. Yenidən cəhd edin.");
            mobileEvent('total', 'RESULT_UNCONFIRMED', performance.now() - started, action, pendingCommand ? pendingCommand.requestId : '', true);
        }

        async function revokeDevice() {
            if (commandBusy || deviceMutationBusy || window.WinKeyDevices?.isPairing()) return;
            deviceMutationBusy = true;
            const revokedDevice = targetDevice;
            if (authToken) {
                try {
                    await request('/mobile/revoke', {
                        method: 'POST',
                        headers: {'Authorization': 'Bearer ' + authToken}
                    });
                } catch(e) {}
            }
            if (window.WinKeyDevices) {
                window.WinKeyDevices.remove(revokedDevice);
                deviceMutationBusy = false;
                return;
            }
            localStorage.clear();
            location.reload();
        }

        let ws = null;
        let wsConnected = false;
        let wsRetryTimer = null;
        let activeCommandResolver = null;

        function waitForWSResult(reqId, timeoutMs = 20000) {
            return new Promise((resolve) => {
                const timer = setTimeout(() => {
                    if (activeCommandResolver) {
                        activeCommandResolver = null;
                        recordNotification(false, "Vaxt Aşımı", "Əmr icra vaxtı aşımı.");
                        resolve(null);
                    }
                }, timeoutMs);
                activeCommandResolver = (res) => {
                    clearTimeout(timer);
                    resolve(res);
                };
            });
        }

        function connectWS() {
            if (!authToken || !targetDevice) return;
            if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
            const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = proto + '//' + window.location.host + '/ws';
            try {
                ws = new WebSocket(wsUrl);
            } catch(e) {
                scheduleWSRetry();
                return;
            }
            const expectedEpoch = deviceEpoch;
            ws.onopen = () => {
                if (deviceEpoch !== expectedEpoch) return;
                ws.send(JSON.stringify({
                    type: 'auth',
                    role: 'mobile',
                    session_token: authToken
                }));
            };
            ws.onmessage = (event) => {
                if (deviceEpoch !== expectedEpoch) return;
                try {
                    const msg = JSON.parse(event.data);
                    if (msg.type === 'auth_ok') {
                        wsConnected = true;
                        badgeTextEl.textContent = 'Onlayn';
                        badgeEl.className = 'badge badge-online';
                    } else if (msg.type === 'device_state') {
                        if (msg.computer_name) devNameEl.textContent = window.WinKeyDevices?.current()?.name || msg.computer_name;
                        isPcLocked = Boolean(msg.locked);
                        renderState();
                        badgeTextEl.textContent = msg.online ? 'Onlayn' : 'Oflayn';
                        badgeEl.className = msg.online ? 'badge badge-online' : 'badge badge-offline';
                    } else if (msg.type === 'command_status') {
                        if (msg.status === 'delivered') {
                            statusBox.innerHTML = '<span class="spinner"></span>Kompüter əmri qəbul etdi (' + msg.action + ')...';
                        } else if (msg.status === 'superseded') {
                            recordNotification(false, "Əmr Əvəzləndi", "Əvvəlki əmr son istəklə əvəz edilib.");
                        }
                    } else if (msg.type === 'command_ack') {
                        if (pendingCommand && (!pendingCommand.commandId || pendingCommand.requestId === msg.request_id)) {
                            pendingCommand.commandId = msg.command_id;
                        }
                    } else if (msg.type === 'command_result') {
                        const isMatch = !pendingCommand || !pendingCommand.commandId || pendingCommand.commandId === msg.command_id;
                        if (isMatch) {
                            setBusy(false);
                            savePending(null);
                            const isOk = (msg.status === 'completed');
                            const act = msg.action || (isPcLocked ? 'unlock' : 'lock');
                            if (isOk) {
                                isPcLocked = (act === 'lock');
                                renderState();
                                recordNotification(true, act === 'unlock' ? "Kilid Açma İcrası" : "Kilidləmə İcrası",
                                    "Status: 200 OK\\n" +
                                    "Əmr: " + act.toUpperCase() + "\\n" +
                                    "Nəticə: " + (msg.result || 'Uğurlu') + "\\n" +
                                    "Bağlantı: WebSocket Live");
                            } else {
                                recordNotification(false, "İcra Uğursuz Oldu",
                                    "Status: Failed\\n" +
                                    "Əmr: " + act.toUpperCase() + "\\n" +
                                    "Səbəb: " + (msg.result || 'Xəta') + "\\n" +
                                    "Bağlantı: WebSocket Live");
                            }
                            if (activeCommandResolver) {
                                const cb = activeCommandResolver;
                                activeCommandResolver = null;
                                cb(msg);
                            }
                        }
                    }
                } catch(e) {}
            };
            ws.onclose = (event) => {
                if (deviceEpoch !== expectedEpoch) return;
                ws = null;
                wsConnected = false;
                if (event.code === 4403) {
                    localStorage.removeItem('winkey_token');
                    authToken = null;
                    badgeTextEl.textContent = 'Ləğv edildi';
                    badgeEl.className = 'badge badge-offline';
                    recordNotification(false, "Sessiya Ləğvi", "Cihaz və ya sessiya serverdə ləğv edildi.");
                    return;
                }
                scheduleWSRetry();
            };
            ws.onerror = () => {
                if (ws) ws.close();
            };
        }

        function scheduleWSRetry() {
            if (wsRetryTimer) clearTimeout(wsRetryTimer);
            wsRetryTimer = setTimeout(() => {
                if (!wsConnected && authToken && targetDevice) {
                    connectWS();
                }
            }, 3000);
        }

        function resumeMobileConnection() {
            if (!authToken || !targetDevice) return;
            if (ws) {
                ws.onclose = ws.onmessage = ws.onerror = ws.onopen = null;
                ws.close(); ws = null;
            }
            wsConnected = false;
            connectWS();
            pollStatus();
        }
        if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
            document.addEventListener('visibilitychange', () => {
                if (!document.hidden) resumeMobileConnection();
            });
        }
        if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
            window.addEventListener('online', resumeMobileConnection);
            window.addEventListener('pageshow', resumeMobileConnection);
        }

        init();
    </script>
</body>
</html>"""

def get_admin_html() -> str:
    return """<!DOCTYPE html>
<html lang="az">
<head>
    <meta charset="utf-8">
    <title>WinKey Pro — Şəxsi Sahib Paneli (Private Admin)</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: #0c0f0e; color: #e6ede8; display: flex; justify-content: center; min-height: 100vh; padding: 24px; }
        .admin-container { width: 100%; max-width: 900px; display: flex; flex-direction: column; gap: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; padding: 16px 0; border-bottom: 1px solid #1c2420; }
        .logo { font-size: 1.4rem; font-weight: 700; color: #c8f279; letter-spacing: -0.5px; }
        .badge { font-size: 0.75rem; padding: 4px 10px; border-radius: 6px; font-weight: 600; text-transform: uppercase; }
        .badge-admin { background: rgba(200, 242, 121, 0.15); color: #c8f279; border: 1px solid rgba(200, 242, 121, 0.3); }
        .card { background: #141a17; border: 1px solid #1f2723; border-radius: 12px; padding: 20px; display: flex; flex-direction: column; gap: 14px; }
        .card-title { font-size: 1.1rem; font-weight: 600; color: #fff; }
        .input-group { display: flex; gap: 10px; }
        input[type="password"], input[type="text"] { flex: 1; padding: 10px 14px; background: #0a0d0c; border: 1px solid #27332c; border-radius: 8px; color: #fff; font-size: 0.95rem; }
        .btn { padding: 10px 18px; border-radius: 8px; font-size: 0.9rem; font-weight: 600; cursor: pointer; border: none; transition: 0.15s; }
        .btn-primary { background: #c8f279; color: #0c0f0e; }
        .btn-primary:active { transform: scale(0.98); }
        .btn-danger { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); padding: 6px 12px; font-size: 0.8rem; }
        table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-top: 8px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #1a221e; }
        th { color: #8e9e95; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
        .status-pill { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
        .status-active { background: rgba(200,242,121,0.15); color: #c8f279; }
        .status-revoked { background: rgba(239,68,68,0.15); color: #ef4444; }
        .err-msg { color: #ef4444; font-size: 0.85rem; }
    </style>
</head>
<body>
    <div class="admin-container">
        <div class="header">
            <div class="logo">WinKey Pro — Şəxsi Sahib Paneli</div>
            <div class="badge badge-admin">Private Surface</div>
        </div>

        <div class="card" id="auth-box">
            <div class="card-title">Sahib Autentifikasiyası</div>
            <div class="input-group">
                <input type="password" id="admin-sec-input" placeholder="X-Owner-Admin-Secret daxil edin...">
                <button class="btn btn-primary" onclick="loginAdmin()">Giriş</button>
            </div>
            <div id="auth-err" class="err-msg"></div>
        </div>

        <div id="dashboard-content" style="display: none; flex-direction: column; gap: 20px;">
            <div class="card">
                <div class="card-title">Qeydiyyatdan Keçmiş PC Cihazları</div>
                <div id="devices-container">Yüklənir...</div>
            </div>

            <div class="card">
                <div class="card-title">Canlı Telemetriya və İnsidentlər (Son 100 Hadisə)</div>
                <div id="telemetry-container">Yüklənir...</div>
            </div>
        </div>
    </div>

    <script>
        const localAccess = typeof location !== 'undefined' ? new URLSearchParams(location.hash.slice(1)).get('dev-admin') : null;
        if (localAccess && typeof history !== 'undefined') {
            sessionStorage.setItem('winkey_admin_secret', localAccess);
            history.replaceState(null, '', location.pathname);
        }
        let adminSecret = sessionStorage.getItem('winkey_admin_secret') || '';

        function loginAdmin() {
            const val = document.getElementById('admin-sec-input').value.trim();
            if (!val) return;
            adminSecret = val;
            sessionStorage.setItem('winkey_admin_secret', adminSecret);
            loadDashboard();
        }

        async function loadDashboard() {
            document.getElementById('auth-err').textContent = '';
            try {
                const resDev = await fetch('/admin/devices', {
                    headers: { 'X-Owner-Admin-Secret': adminSecret }
                });
                if (resDev.status === 403) {
                    document.getElementById('auth-err').textContent = 'XƏTA 403: Admin Secret yanlışdır!';
                    document.getElementById('dashboard-content').style.display = 'none';
                    return;
                }
                const dataDev = await resDev.json();
                renderDevices(dataDev.devices || []);

                const resTel = await fetch('/admin/telemetry', {
                    headers: { 'X-Owner-Admin-Secret': adminSecret }
                });
                const dataTel = await resTel.json();
                renderTelemetry(dataTel.telemetry || []);

                document.getElementById('auth-box').style.display = 'none';
                document.getElementById('dashboard-content').style.display = 'flex';
            } catch(e) {
                document.getElementById('auth-err').textContent = 'Şəbəkə xətası: ' + e;
            }
        }

        function escapeHtml(value) {
            return String(value ?? '').replace(/[&<>"']/g, ch => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            }[ch]));
        }

        function renderDevices(list) {
            if (list.length === 0) {
                document.getElementById('devices-container').innerHTML = '<div style="color:#8e9e95;">Heç bir cihaz qeydiyyatdan keçməyib.</div>';
                return;
            }
            let html = '<table><tr><th>Cihaz ID</th><th>Ad</th><th>Status</th><th>Xidmət versiyası</th><th>Serverdə son versiya</th><th>Kilid</th><th>PIN</th><th>Son Görülmə</th><th>Əməliyyat</th></tr>';
            for (const d of list) {
                const stClass = d.status === 'ACTIVE' ? 'status-active' : 'status-revoked';
                html += `<tr>
                    <td><code>${escapeHtml(d.device_id.substring(0, 16))}...</code></td>
                    <td><strong>${escapeHtml(d.computer_name)}</strong></td>
                    <td><span class="status-pill ${stClass}">${escapeHtml(d.status)}</span></td>
                    <td>${d.worker_version ? 'v' + escapeHtml(d.worker_version) : 'Bildirilməyib'}</td>
                    <td>${d.latest_version ? 'v' + escapeHtml(d.latest_version) : 'Paket yoxdur'}</td>
                    <td>${d.locked ? '🔒 Bəli' : '🔓 Xeyr'}</td>
                    <td>${d.pin_ready ? '✅ Hazır' : '⏳ Yoxdur'}</td>
                    <td>${new Date(d.last_seen_at * 1000).toLocaleTimeString()}</td>
                    <td>
                        <div style="display:flex; gap:6px; align-items:center;">
                            <button class="btn btn-danger" data-device-id="${escapeHtml(d.device_id)}" data-action="${d.status === 'ACTIVE' ? 'revoke' : 'activate'}">${d.status === 'ACTIVE' ? 'Ləğv Et' : 'Aktivləşdir'}</button>
                            <button class="btn btn-danger" style="background:#5c1d1d; border-color:#822727; color:#fca5a5;" data-device-id="${escapeHtml(d.device_id)}" data-action="delete">Sil</button>
                        </div>
                    </td>
                </tr>`;
            }
            html += '</table>';
            document.getElementById('devices-container').innerHTML = html;
            document.querySelectorAll('#devices-container button[data-device-id]').forEach(button => {
                button.addEventListener('click', () => {
                    if (button.dataset.action === 'delete') {
                        deleteDev(button.dataset.deviceId);
                    } else {
                        revokeDev(button.dataset.deviceId, button.dataset.action);
                    }
                });
            });
        }

        function renderTelemetry(events) {
            if (events.length === 0) {
                document.getElementById('telemetry-container').innerHTML = '<div style="color:#8e9e95;">Hadisə qeydə alınmayıb.</div>';
                return;
            }
            const mobileLabels = {
                COMMAND_TAP: 'Telefonda düyməyə basıldı', HTTP_200: 'Əmr serverə çatdı',
                SERVER_PROCESSING: 'Server daxilində emal', COMMAND_COMPLETED: 'İcra təsdiqləndi',
                COMMAND_FAILED: 'PC əmri uğursuz tamamladı', RESULT_UNCONFIRMED: 'Nəticə hələ təsdiqlənməyib',
                REQUEST_TIMEOUT: 'Telefon sorğusunun vaxtı bitdi', NETWORK_ERROR: 'Telefon şəbəkə xətası',
                UI_RESULT_UNCONFIRMED: 'Ekran: Əvvəlki nəticə təsdiqlənməyib', UI_NETWORK_UNKNOWN: 'Ekran: Server cavabı alınmadı',
                UI_AUTH_ERROR: 'Ekran: Telefon bağlantısı ləğv edilib / icazə yoxdur', UI_RESULT_FAILED: 'Ekran: İcra uğursuz oldu',
                UI_PAIR_FAILED: 'Ekran: Cütləşmə xətası', UI_NETWORK_ERROR: 'Ekran: Şəbəkə xətası',
                UI_RESPONSE_ERROR: 'Ekran: Server xəta qaytardı', UI_SERVER_ACCEPTED: 'Ekran: Əmr serverə çatdı',
                UI_RESULT_OK: 'Ekran: İcra tamamlandı', UI_LATEST_PENDING: 'Ekran: Son istək saxlanıldı',
                UI_SENDING: 'Ekran: Əmr göndərilir', UI_SUPERSEDED: 'Ekran: Əvvəlki əmr son istəklə əvəz edilib',
                JS_RUNTIME_ERROR: 'Telefon JavaScript xətası', JS_UNHANDLED_REJECTION: 'Telefon promise xətası'
            };
            let html = '<table><tr><th>Vaxt</th><th>Cihaz</th><th>Komponent</th><th>Mərhələ / Əlaqə ID</th><th>Hadisə</th><th>Müddət</th><th>Dərəcə</th><th>Xəta / Telefon ekranı</th></tr>';
            for (const ev of events.slice(0, 100)) {
                html += `<tr>
                    <td>${new Date((ev.component === 'mobile' ? ev.local_time : ev.received_at) * 1000).toLocaleTimeString()}</td>
                    <td>${escapeHtml(ev.device_id || '—')}</td>
                    <td>${escapeHtml(ev.component)}</td>
                    <td>${escapeHtml(ev.stage)}<br>${escapeHtml(ev.install_run_id || '')}</td>
                    <td>${escapeHtml(ev.event_type)}</td>
                    <td>${ev.duration_ms == null ? '—' : escapeHtml(ev.duration_ms) + ' ms'}</td>
                    <td><strong>${escapeHtml(ev.severity)}</strong></td>
                    <td>${escapeHtml(mobileLabels[ev.error_code] || ev.error_code || '—')}</td>
                </tr>`;
            }
            html += '</table>';
            document.getElementById('telemetry-container').innerHTML = html;
        }

        
                async function deleteDev(devId) {
            if (!confirm('DİQQƏT: Bu cihazı serverdən və admin panelindən tamamilə silmək istəyirsiniz?\\nBütün mobil sessiyalar və qeydiyyat silinəcək və kompüter təzədən ilk dəfə qeydiyyatdan keçə biləcək.')) return;
            try {
                await fetch('/admin/delete', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Owner-Admin-Secret': adminSecret
                    },
                    body: JSON.stringify({ device_id: devId })
                });
                loadDashboard();
            } catch(e) {
                alert('Silinmə xətası: ' + e);
            }
        }
        async function revokeDev(devId, action = 'revoke') {
            if (!confirm(action === 'activate' ? 'PC-ni yenidən aktivləşdirək? Köhnə telefon sessiyaları bərpa edilmir; yeni QR lazımdır.' : 'Cihazı ləğv etmək istədiyinizə əminsiniz?')) return;
            await fetch(action === 'activate' ? '/admin/activate' : '/admin/revoke', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Owner-Admin-Secret': adminSecret
                },
                body: JSON.stringify({ device_id: devId })
            });
            loadDashboard();
        }

        if (adminSecret) {
            loadDashboard();
        }
        setInterval(() => { if (adminSecret) loadDashboard(); }, 5000);
    </script>
</body>
</html>"""

class GatewayHandler(BaseHTTPRequestHandler):
    db: ProductionDatabase = None
    protocol_version = 'HTTP/1.1'
    disable_nagle_algorithm = True

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def parse_request(self):
        parsed = super().parse_request()
        # Exclude idle keep-alive time from request processing measurements.
        self.request_started = time.monotonic()
        return parsed

    def log_message(self, format, *args):
        # Do not print raw request URLs: QR secrets can be in the query.
        pass

    def _set_security_headers(self, content_type="application/json"):
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; media-src 'self' blob:; img-src 'self' blob: data:;")
        self.send_header('Cache-Control', 'no-store')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Owner-Admin-Secret")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def do_OPTIONS(self):
        self.send_response(204)
        self._set_security_headers()
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _send_json(self, status: int, data: Dict[str, Any]):
        duration_ms = round((time.monotonic() - getattr(self, 'request_started', time.monotonic())) * 1000)
        print(f"[GATEWAY] {self.command if hasattr(self, 'command') else 'REQUEST'} "
              f"{urlparse(self.path).path} HTTP={status} "
              f"code={data.get('error', 'OK')} duration_ms={duration_ms} ts_ms={round(time.time() * 1000)}", flush=True)
        if status >= 400:
            self._record_incident(urlparse(self.path).path, data.get('error', f'HTTP_{status}'))
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self._set_security_headers("application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header('X-App-Duration-Ms', str(duration_ms))
        self.end_headers()
        self.wfile.write(body)

    def _record_incident(self, stage, code, device_id=None):
        # Server-owned allowlisted event. Never store request bodies/QRs/tokens/PINs.
        if not self.db:
            return
        try:
            with self.db.get_conn() as conn:
                conn.execute(
                    "INSERT INTO telemetry_events (event_id, device_id, component, version, stage, event_type, severity, error_code, local_time, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ('evt_' + secrets.token_hex(12), device_id, 'gateway', '0.1.0', stage,
                     'incident', 'ERROR', str(code)[:120], time.time(), time.time()))
                conn.commit()
        except Exception:
            print('[DIAGNOSTICS] E_INCIDENT_PERSIST_FAILED', flush=True)

    def _get_bearer_token(self) -> Optional[str]:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return None

    def _authenticate_agent(self, conn, device_id: str) -> bool:
        """Agent Bearer token vasitəsilə cihazın həqiqi sahibi olduğunu təsdiqləyir."""
        token = self._get_bearer_token()
        if not token:
            return False
        sec_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        row = conn.execute("SELECT device_id FROM devices WHERE device_secret_hash = ? AND status = 'ACTIVE'", (sec_hash,)).fetchone()
        return bool(row and row["device_id"] == device_id)

    def do_GET(self):
        if urlparse(self.path).path in ('/remote', '/mobile'):
            print(f"[GATEWAY] phone opened {urlparse(self.path).path} (QR query redacted)", flush=True)
        url = urlparse(self.path)
        path = url.path.rstrip("/")
        if path.startswith('/mobile-assets/'):
            from pathlib import Path
            from deploy.mobile_install import manifest
            asset = path.rsplit('/', 1)[1]
            if asset == 'manifest.webmanifest':
                ticket = parse_qs(url.query).get('install', [''])[0]
                self._send_json(200, manifest(ticket))
                return
            if asset in ('devices.js', 'jsQR.js', 'icon.png'):
                content = (Path(__file__).parent / 'static' / asset).read_bytes()
                self.send_response(200)
                self._set_security_headers('image/png' if asset == 'icon.png' else 'application/javascript')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
        # 1. Zəngin Avant-Garde Mobil Web Remote və PWA İnterfeysi
        if path in ("/mobile", "/remote", ""):
            self.send_response(200)
            self._set_security_headers("text/html; charset=utf-8")
            html = get_mobile_html()
            self.send_header('Content-Length', str(len(html.encode('utf-8'))))
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return

        # 1b. Zəngin Avant-Garde Private Admin Dashboard İnterfeysi
        if path == "/admin":
            self.send_response(200)
            self._set_security_headers("text/html; charset=utf-8")
            admin_html = get_admin_html()
            self.send_header('Content-Length', str(len(admin_html.encode('utf-8'))))
            self.end_headers()
            self.wfile.write(admin_html.encode("utf-8"))
            return

        # 2. Owner-Only Admin Devices
        if path == "/admin/devices":
            admin_sec = self.headers.get("X-Owner-Admin-Secret")
            if not admin_sec or admin_sec != get_admin_secret():
                self._send_json(403, {"error": "E_ADMIN_UNAUTHORIZED", "message": "Yalnız sahib admin icazəlidir"})
                return
            with self.db.get_conn() as conn:
                rows = conn.execute("SELECT device_id, computer_name, status, locked, pin_ready, last_seen_at FROM devices").fetchall()
                devices = [dict(r) for r in rows]
            self._send_json(200, {"devices": devices})
            return

        # 3. Owner-Only Admin Telemetry
        if path == "/admin/telemetry":
            admin_sec = self.headers.get("X-Owner-Admin-Secret")
            if not admin_sec or admin_sec != get_admin_secret():
                self._send_json(403, {"error": "E_ADMIN_UNAUTHORIZED", "message": "Yalnız sahib admin icazəlidir"})
                return
            with self.db.get_conn() as conn:
                rows = conn.execute("SELECT * FROM telemetry_events ORDER BY received_at DESC LIMIT 100").fetchall()
                events = [dict(r) for r in rows]
            self._send_json(200, {"telemetry": events})
            return

        # 4. Device Status (Device-Scoped Token ilə, Multi-Tenant IDOR qorumalı)
        if path.startswith("/devices/") and path.endswith("/status"):
            parts = path.split("/")
            req_device_id = parts[2]
            token = self._get_bearer_token()
            if not token:
                self._send_json(401, {"error": "E_MISSING_TOKEN"})
                return

            with self.db.get_conn() as conn:
                sess = conn.execute("SELECT device_id FROM mobile_sessions WHERE session_token = ? AND (expires_at = 0 OR expires_at > ?)", (token, time.time())).fetchone()
                if not sess:
                    self._send_json(401, {"error": "E_INVALID_SESSION"})
                    return

                # MULTI-TENANT IDOR GUARD
                if sess["device_id"] != req_device_id:
                    self._send_json(403, {"error": "E_TENANT_IDOR_FORBIDDEN", "message": "Başqa cihazın statusuna giriş qadağandır!"})
                    return

                dev = conn.execute("SELECT device_id, computer_name, status, locked, pin_ready FROM devices WHERE device_id = ?", (req_device_id,)).fetchone()
                if not dev:
                    self._send_json(404, {"error": "E_DEVICE_NOT_FOUND"})
                    return
                if dev["status"] != "ACTIVE":
                    self._send_json(403, {"error": "E_DEVICE_NOT_ACTIVE", "message": "Cihaz deaktiv edilib və ya aktiv deyil"})
                    return
                self._send_json(200, dict(dev))
            return

        # 5. Command Status Polling (Mobil üçün — komandanın real icra nəticəsini izləmək)
        if path.startswith("/commands/"):
            parts = path.split("/")
            if len(parts) >= 3:
                cmd_id = parts[2]
                token = self._get_bearer_token()
                if not token:
                    self._send_json(401, {"error": "E_MISSING_TOKEN"})
                    return

                with self.db.get_conn() as conn:
                    sess = conn.execute("SELECT device_id FROM mobile_sessions WHERE session_token = ? AND (expires_at = 0 OR expires_at > ?)", (token, time.time())).fetchone()
                    if not sess:
                        self._send_json(401, {"error": "E_INVALID_SESSION"})
                        return

                    cmd = conn.execute("SELECT command_id, device_id, action, status, result_status AS result, created_at, completed_at AS executed_at FROM commands WHERE command_id = ?", (cmd_id,)).fetchone()
                    if not cmd:
                        self._send_json(404, {"error": "E_COMMAND_NOT_FOUND"})
                        return

                    # Multi-Tenant guard
                    if cmd["device_id"] != sess["device_id"]:
                        self._send_json(403, {"error": "E_TENANT_IDOR_FORBIDDEN", "message": "Başqa cihazın əmrinə giriş qadağandır"})
                        return

                    self._send_json(200, dict(cmd))
                return

        # 6. Real Update Delivery — Manifest və İmza Sorğusu (/updates/latest)
        if path == "/updates/latest":
            u_dir = get_updates_dir()
            manifest_path = os.path.join(u_dir, "manifest.json")
            sig_path = os.path.join(u_dir, "manifest.sig")
            if not os.path.isfile(manifest_path) or not os.path.isfile(sig_path):
                self._send_json(404, {"error": "E_NO_UPDATES_AVAILABLE", "message": "Serverdə aktiv buraxılış paketi tapılmadı"})
                return

            with open(manifest_path, "rb") as mf:
                manifest_raw_bytes = mf.read()
            manifest_json = json.loads(manifest_raw_bytes.decode("utf-8"))
            with open(sig_path, "rb") as sf:
                sig_hex = sf.read().hex()

            self._send_json(200, {
                "version": manifest_json.get("version", "0.1.0"),
                "manifest": manifest_json,
                "manifest_raw": manifest_raw_bytes.decode("utf-8"),
                "manifest_sig_hex": sig_hex,
                "download_url_prefix": "/updates/download"
            })
            return

        # 7. Real Update Delivery — İmzalı Fayl Endirilməsi (/updates/download/<filename>)
        if path.startswith("/updates/download/"):
            fname = path[len("/updates/download/"):].strip()
            # Path traversal qoruması (Zip-Slip / Traversal guard)
            if not fname or ".." in fname or "/" in fname or "\\" in fname or ":" in fname:
                self._send_json(400, {"error": "E_INVALID_FILENAME", "message": "Təhlükəli və ya etibarsız fayl adı"})
                return

            u_dir = get_updates_dir()
            fpath = os.path.join(u_dir, fname)
            if not os.path.isfile(fpath):
                self._send_json(404, {"error": "E_FILE_NOT_FOUND", "message": f"Tələb olunan fayl tapılmadı: {fname}"})
                return

            with open(fpath, "rb") as f:
                content = f.read()

            self.send_response(200)
            self._set_security_headers("application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        self._send_json(404, {"error": "E_NOT_FOUND"})

    def do_POST(self):
        url = urlparse(self.path)
        path = url.path.rstrip("/")
        data = self._read_json()

        if path.startswith('/accounts/') or path in ('/pair', '/mobile/install', '/mobile/restore', '/mobile/pair'):
            from deploy.gateway_service import GatewayService
            from deploy.mobile_install import feature_request
            if not isinstance(data, dict):
                self._send_json(400, {'error': 'E_INPUT'})
                return
            status, response = feature_request(GatewayService(self.db, get_admin_secret), path, data, self._get_bearer_token())
            self._send_json(status, response)
            return

        if path == '/mobile/telemetry':
            token = self._get_bearer_token()
            device_id = data.get('device_id')
            events = data.get('events')
            if not isinstance(events, list) or not 1 <= len(events) <= 20:
                self._send_json(400, {'error': 'E_INVALID_MOBILE_EVENTS'})
                return
            with self.db.get_conn() as conn:
                session = conn.execute("SELECT device_id FROM mobile_sessions WHERE session_token = ? AND (expires_at = 0 OR expires_at > ?)", (token, time.time())).fetchone()
                if not session or session['device_id'] != device_id:
                    self._send_json(401, {'error': 'E_INVALID_SESSION'})
                    return
                accepted = []
                for event in events:
                    if not isinstance(event, dict): continue
                    event_id = event.get('id', '')
                    code = event.get('code', '')
                    stage = event.get('stage')
                    duration = event.get('duration_ms')
                    correlation = event.get('request_id', '')
                    if not isinstance(event_id, str) or len(event_id) != 32 or any(c not in '0123456789abcdef' for c in event_id): continue
                    if stage not in ('tap', 'request', 'server', 'total', 'display', 'runtime'): continue
                    if not isinstance(code, str) or not 1 <= len(code) <= 80 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in code): continue
                    if duration is not None and (type(duration) is not int or not 0 <= duration <= 600000): continue
                    if not isinstance(correlation, str) or (correlation and (len(correlation) != 32 or any(c not in '0123456789abcdef' for c in correlation))): continue
                    local_time = event.get('local_time')
                    if type(local_time) not in (int, float) or not 0 <= local_time <= 4102444800: continue
                    action = event.get('action') if event.get('action') in ('lock', 'unlock') else 'phone'
                    conn.execute("INSERT INTO telemetry_events (event_id, install_run_id, device_id, component, version, stage, event_type, severity, error_code, duration_ms, local_time, received_at) VALUES (?, ?, ?, 'mobile', 'web-1', ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (event_id) DO NOTHING",
                                 ('mob_' + event_id, correlation or None, device_id, stage, action,
                                  'ERROR' if event.get('error') is True else 'INFO', code, duration, local_time, time.time()))
                    accepted.append(event_id)
                conn.commit()
            self._send_json(200, {'accepted': accepted})
            return

        # 1. Challenge yaradılması (/agent/challenge)
        if path == "/agent/challenge":
            purpose = data.get("purpose", "register")
            device_id = data.get("device_id", "")
            nonce = secrets.token_hex(16)
            with self.db.get_conn() as conn:
                conn.execute(
                    "INSERT INTO challenges (nonce, purpose, device_id, created_at, expires_at, used) VALUES (?, ?, ?, ?, ?, 0) ON CONFLICT (nonce) DO UPDATE SET purpose=excluded.purpose, device_id=excluded.device_id, created_at=excluded.created_at, expires_at=excluded.expires_at, used=excluded.used",
                    (nonce, purpose, device_id, time.time(), time.time() + 120)
                )
                conn.commit()
            self._send_json(200, {"nonce": nonce, "device_id": device_id, "purpose": purpose})
            return

        # 2. Cihaz Qeydiyyatı (Agent Registration) — STRICT VALIDATION & OWNERSHIP
        if path == "/agent/register":
            device_id = data.get("device_id")
            computer_name = data.get("computer_name", "PC")
            pub_hex = data.get("public_key_hex", "")
            proof_sig = data.get("proof_signature_hex")
            nonce = data.get("nonce")

            if not device_id or not isinstance(device_id, str):
                self._send_json(400, {"error": "E_INVALID_DEVICE_ID", "message": "device_id məcburidir"})
                return

            # YOXLANILIŞ 1: Public Key Hex və Ed25519 formatı
            if not pub_hex or not isinstance(pub_hex, str) or len(pub_hex) != 64:
                self._send_json(400, {"error": "E_INVALID_PUBLIC_KEY", "message": "public_key_hex 64 simvollu hex olmalıdır"})
                return

            try:
                pub_bytes = bytes.fromhex(pub_hex)
                if len(pub_bytes) != 32:
                    self._send_json(400, {"error": "E_INVALID_PUBLIC_KEY", "message": "Açar uzunluğu 32 bayt olmalıdır"})
                    return
                verifier = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            except Exception as e:
                self._send_json(400, {"error": "E_INVALID_PUBLIC_KEY", "message": f"Ed25519 açar formatı xətası: {e}"})
                return

            # YOXLANILIŞ 2: Nonce və Cryptographic Proof MƏCBURİDİR
            if not nonce or not proof_sig:
                self._send_json(400, {
                    "error": "E_MISSING_PROOF",
                    "message": "Qeydiyyat üçün nonce və cryptographic proof_signature_hex məcburidir"
                })
                return

            with self.db.get_conn() as conn:
                chal = conn.execute(
                    "SELECT * FROM challenges WHERE nonce = ? AND used = 0 AND expires_at > ? AND purpose = 'register'",
                    (nonce, time.time())
                ).fetchone()
                if not chal:
                    self._send_json(400, {"error": "E_INVALID_NONCE", "message": "Nonce tapılmadı, istifadə olunub və ya vaxtı bitib"})
                    return

                if chal["device_id"] and chal["device_id"] != device_id:
                    self._send_json(400, {"error": "E_CHALLENGE_DEVICE_MISMATCH", "message": "Nonce başqa cihaz üçün yaradılıb"})
                    return

                # Atomik One-Use istehlakı
                upd = conn.execute("UPDATE challenges SET used = 1 WHERE nonce = ? AND used = 0", (nonce,)).rowcount
                if upd != 1:
                    self._send_json(409, {"error": "E_NONCE_REPLAY", "message": "Nonce artıq istifadə olunub"})
                    return

                bound_msg = f"WINKEY_REGISTER:{nonce}:{device_id}".encode("utf-8")
                try:
                    sig_bytes = bytes.fromhex(proof_sig)
                    verifier.verify(sig_bytes, bound_msg)
                except Exception as e:
                    self._send_json(400, {"error": "E_INVALID_PROOF", "message": f"Kriptoqrafik imza təsdiqlənmədi: {e}"})
                    return

                # YOXLANILIŞ 3: Re-registration Ownership Guard
                existing = conn.execute("SELECT public_key_hex, device_secret_hash, status FROM devices WHERE device_id = ?", (device_id,)).fetchone()
                if existing:
                    if existing["public_key_hex"] != pub_hex:
                        self._send_json(409, {
                            "error": "E_DEVICE_ALREADY_EXISTS_OWNERSHIP_VIOLATION",
                            "message": "Bu cihaz ID başqa ictimai açarla qeydiyyatdan keçib. Cihaz oğurlana bilməz!"
                        })
                        return

                    # Kriptoqrafik Ed25519 proof uğurla təsdiqləndiyi və public_key eyni olduğu üçün
                    # qanuni cihaz sahibi yeni secret rotasiyası ala və yeni QR yarada bilər:
                    new_secret = secrets.token_hex(32)
                    new_sec_hash = hashlib.sha256(new_secret.encode("utf-8")).hexdigest()
                    conn.execute("UPDATE devices SET device_secret_hash = ?, computer_name = ?, status = 'ACTIVE', last_seen_at = ? WHERE device_id = ?", (new_sec_hash, computer_name, time.time(), device_id))
                    # Köhnə cütləşmə sessiyalarını təmizləyirik ki, yeni QR üçün təzə təmiz mobil sessiya yaradılsın
                    conn.execute("DELETE FROM mobile_sessions WHERE device_id = ?", (device_id,))
                    conn.commit()
                    self._send_json(200, {"device_id": device_id, "device_secret": new_secret, "status": "ROTATED"})
                    return

                # Yeni cihaz qeydiyyatı (INSERT OR REPLACE deyil, təmiz INSERT)
                secret = secrets.token_hex(32)
                sec_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()

                conn.execute(
                    "INSERT INTO devices (device_id, computer_name, public_key_hex, device_secret_hash, status, created_at, last_seen_at) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?)",
                    (device_id, computer_name, pub_hex, sec_hash, time.time(), time.time())
                )
                conn.commit()

            self._send_json(200, {"device_id": device_id, "device_secret": secret, "status": "REGISTERED"})
            return

        # 3. Pair sorğusunun təsdiqi və Sessiya yaradılması (One-Use Atomic Claim)
        if path == "/pair":
            pair_code = data.get("pair_code") or data.get("code")
            if not pair_code:
                self._send_json(400, {"error": "E_MISSING_PAIR_CODE", "message": "pair_code tələb olunur"})
                return

            with self.db.get_conn() as conn:
                req = conn.execute("SELECT * FROM pairing_requests WHERE pair_code = ?", (pair_code,)).fetchone()
                # YOXLANILIŞ: Server tərəfindən heç yaradılmamış naməlum kod dərhal rədd edilir!
                if not req:
                    self._send_json(404, {"error": "E_PAIR_CODE_NOT_FOUND", "message": "Cütləşmə kodu tapılmadı və ya etibarsızdır"})
                    return

                # Strict status check: yalnız və yalnız PENDING qəbul edilir!
                if req["status"] != "PENDING":
                    if req["status"] == "CLAIMED":
                        self._send_json(409, {"error": "E_REPLAY_REJECTED", "message": "Bu cütləşmə kodu artıq istifadə olunub!"})
                    elif req["status"] == "REJECTED":
                        self._send_json(403, {"error": "E_PAIR_CODE_REJECTED", "message": "Bu cütləşmə kodu rədd edilib!"})
                    else:
                        self._send_json(400, {"error": "E_INVALID_PAIR_STATUS", "message": f"Cütləşmə statusu etibarsızdır: {req['status']}"})
                    return

                if req["expires_at"] < time.time():
                    self._send_json(410, {"error": "E_EXPIRED_CODE", "message": "Cütləşmə kodunun vaxtı bitib"})
                    return

                # Cihazın özünün aktiv olması məcburidir!
                device_id = req["device_id"]
                dev = conn.execute("SELECT status FROM devices WHERE device_id = ?", (device_id,)).fetchone()
                if not dev or dev["status"] != "ACTIVE":
                    self._send_json(403, {"error": "E_DEVICE_NOT_ACTIVE", "message": "Cihaz aktiv deyil və ya ləğv edilib"})
                    return

                # Atomik Status Dəyişdirilməsi və rowcount == 1 yoxlanışı (Paralel yarışlara qarşı!)
                cur = conn.execute(
                    "UPDATE pairing_requests SET status = 'CLAIMED' WHERE pair_code = ? AND status = 'PENDING' AND expires_at > ?",
                    (pair_code, time.time())
                )
                if cur.rowcount != 1:
                    self._send_json(409, {"error": "E_PAIR_CLAIM_CONFLICT", "message": "Cütləşmə kodu artıq başqa sorğu tərəfindən istifadə edilib"})
                    return

                session_token = "sess_" + secrets.token_hex(24)
                conn.execute(
                    "INSERT INTO mobile_sessions (session_token, device_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                    (session_token, device_id, time.time(), 0)
                )
                conn.commit()

            self._send_json(200, {
                "success": True,
                "session_token": session_token,
                "device_id": device_id,
                "expires_in": None,
                "persistent": True
            })
            return

        # 4. Pair Request Yaradılması (PC Desktop tərəfindən)
        if path == "/devices/pair-request":
            device_id = data.get("device_id")
            with self.db.get_conn() as conn:
                if not self._authenticate_agent(conn, device_id):
                    self._send_json(401, {"error": "E_UNAUTHORIZED_AGENT", "message": "Cihaz autentifikasiyası tələb olunur"})
                    return

                pair_code = "PAIR_" + secrets.token_hex(6).upper()
                expires_at = time.time() + 120
                conn.execute(
                    "INSERT INTO pairing_requests (pair_code, device_id, challenge_hex, status, expires_at, created_at) VALUES (?, ?, 'chal', 'PENDING', ?, ?) ON CONFLICT (pair_code) DO UPDATE SET device_id=excluded.device_id, challenge_hex=excluded.challenge_hex, status=excluded.status, expires_at=excluded.expires_at, created_at=excluded.created_at",
                    (pair_code, device_id, expires_at, time.time())
                )
                conn.commit()

            self._send_json(200, {"pair_code": pair_code, "expires_at": expires_at, "device_id": device_id})
            return

        # 5. Mobil Sessiyanın Serverdə Ləğv Edilməsi (/mobile/revoke)
        if path in ("/mobile/revoke", "/devices/revoke"):
            token = self._get_bearer_token()
            if not token:
                self._send_json(401, {"error": "E_MISSING_TOKEN", "message": "Sessiya tokeni tələb olunur"})
                return

            with self.db.get_conn() as conn:
                sess = conn.execute("SELECT session_token, device_id FROM mobile_sessions WHERE session_token = ?", (token,)).fetchone()
                if not sess:
                    self._send_json(401, {"error": "E_INVALID_SESSION", "message": "Sessiya tapılmadı və ya artıq ləğv edilib"})
                    return
                # Sessiyanı ləğv edirik
                conn.execute("DELETE FROM mobile_sessions WHERE session_token = ?", (token,))
                conn.commit()

            self._send_json(200, {"success": True, "message": "Mobil sessiya serverdə uğurla ləğv edildi"})
            return

        # 6. Mobil Komanda Göndərişi (Multi-Tenant IDOR + Zero-PIN Guard)
        if (path.startswith("/devices/") and path.endswith("/command")) or path == "/commands":
            parts = path.split("/")
            req_device_id = data.get("device_id") if path == "/commands" else parts[2]
            token = self._get_bearer_token()

            # ZERO-PIN ENFORCEMENT: Şəbəkədə heç vaxt PIN ola bilməz!
            for forbidden in ["pin", "credential", "password", "secret"]:
                if forbidden in data:
                    self._send_json(400, {
                        "error": "E_CREDENTIAL_NOT_PERMITTED",
                        "message": "Mobil şəbəkə üzərindən PIN göndərilməsi qəti qadağandır! PIN yalnız PC daxilində DPAPI anbarında saxlanır."
                    })
                    return

            with self.db.get_conn() as conn:
                sess = conn.execute("SELECT device_id FROM mobile_sessions WHERE session_token = ? AND (expires_at = 0 OR expires_at > ?)", (token, time.time())).fetchone()
                if not sess:
                    self._send_json(401, {"error": "E_INVALID_SESSION"})
                    return

                # MULTI-TENANT IDOR GUARD
                if sess["device_id"] != req_device_id:
                    self._send_json(403, {"error": "E_TENANT_IDOR_FORBIDDEN", "message": "Başqa istifadəçinin cihazına komanda göndərə bilməzsiniz!"})
                    return

                dev = conn.execute("SELECT status FROM devices WHERE device_id = ?", (req_device_id,)).fetchone()
                if not dev or dev["status"] != "ACTIVE":
                    self._send_json(403, {"error": "E_DEVICE_NOT_ACTIVE", "message": "Cihaz deaktiv edilib və ya aktiv deyil"})
                    return

                action = data.get("action")
                if action not in ("lock", "unlock", "mock"):
                    self._send_json(400, {"error": "E_INVALID_ACTION"})
                    return

                request_id = data.get('request_id')
                if request_id is not None and (not isinstance(request_id, str) or len(request_id) != 32 or any(c not in '0123456789abcdef' for c in request_id)):
                    self._send_json(400, {'error': 'E_INVALID_REQUEST_ID'})
                    return
                # Stable across a lost HTTP response/retry; bound to this session.
                cmd_id = 'cmd_' + (hashlib.sha256((token + ':' + request_id).encode()).hexdigest()[:24]
                                  if request_id else secrets.token_hex(12))
                # Serialize enqueue/delivery for this device across HTTP workers.
                conn.execute('UPDATE devices SET status = status WHERE device_id = ?', (req_device_id,))
                inserted = conn.execute(
                    "INSERT INTO commands (command_id, device_id, action, status, created_at) VALUES (?, ?, ?, 'pending', ?) ON CONFLICT (command_id) DO NOTHING",
                    (cmd_id, req_device_id, action, time.time())
                )
                if inserted.rowcount == 1 and action in ('lock', 'unlock'):
                    conn.execute("UPDATE commands SET status = 'superseded', completed_at = ?, result_status = 'SUPERSEDED_BY_LATEST' WHERE device_id = ? AND status = 'pending' AND command_id <> ? AND action IN ('lock', 'unlock')",
                                 (time.time(), req_device_id, cmd_id))
                existing = conn.execute('SELECT device_id, action FROM commands WHERE command_id = ?', (cmd_id,)).fetchone()
                conn.commit()
                if existing['device_id'] != req_device_id or existing['action'] != action:
                    self._send_json(409, {'error': 'E_REQUEST_ID_CONFLICT'})
                    return

            self._send_json(200, {"success": True, "command_id": cmd_id, "action": action, "status": "queued"})
            print(f"[COMMAND_QUEUED] device={req_device_id} action={action} id={cmd_id}", flush=True)
            return

        # 7. Authenticated Agent Polling (/agent/poll)
        if path == "/agent/poll":
            device_id = data.get("device_id")
            server = getattr(self, 'server', None)
            if server is not None and getattr(server, '_last_logged_device', None) != device_id:
                print(f"[WORKER_POLL_DEVICE] device={device_id}", flush=True)
                server._last_logged_device = device_id
            if not device_id:
                self._send_json(400, {"error": "E_MISSING_DEVICE_ID"})
                return

            with self.db.get_conn() as conn:
                # STRICT AGENT AUTHENTICATION
                if not self._authenticate_agent(conn, device_id):
                    self._send_json(401, {"error": "E_UNAUTHORIZED_AGENT", "message": "Agent autentifikasiyası (Bearer device_secret) uğursuz oldu"})
                    return

                dev = conn.execute("SELECT status FROM devices WHERE device_id = ?", (device_id,)).fetchone()
                if not dev or dev["status"] != "ACTIVE":
                    self._send_json(403, {"error": "E_DEVICE_NOT_ACTIVE", "message": "Cihaz deaktiv edilib"})
                    return

                locked = data.get("locked", False)
                pin_ready = data.get("pin_ready", False)

                conn.execute(
                    "UPDATE devices SET last_seen_at = ?, locked = ?, pin_ready = ? WHERE device_id = ?",
                    (time.time(), 1 if locked else 0, 1 if pin_ready else 0, device_id)
                )
                cmd = conn.execute(
                    "SELECT command_id, action, created_at FROM commands WHERE device_id = ? AND status = 'pending' ORDER BY created_at ASC LIMIT 1",
                    (device_id,)
                ).fetchone()

                if cmd:
                    print(f"[COMMAND_DELIVERED] device={device_id} action={cmd['action']} id={cmd['command_id']} queued_ms={round((time.time() - cmd['created_at']) * 1000)}", flush=True)
                    conn.execute("UPDATE commands SET status = 'delivered' WHERE command_id = ?", (cmd["command_id"],))
                    conn.commit()
                    self._send_json(200, {"command": {"id": cmd["command_id"], "action": cmd["action"]}})
                else:
                    conn.commit()
                    self._send_json(200, {"command": None})
            return

        # 7. Authenticated Agent Result (/agent/result) — WITH OBJECT OWNERSHIP CHECK
        if path == "/agent/result":
            cmd_id = data.get("command_id")
            device_id = data.get("device_id")
            success = data.get("success", False)
            status_str = data.get("status", "")

            with self.db.get_conn() as conn:
                if not device_id or not self._authenticate_agent(conn, device_id):
                    self._send_json(401, {"error": "E_UNAUTHORIZED_AGENT", "message": "Etibarlı agent secret tələb olunur"})
                    return

                cmd = conn.execute("SELECT device_id FROM commands WHERE command_id = ?", (cmd_id,)).fetchone()
                if not cmd:
                    self._send_json(404, {"error": "E_COMMAND_NOT_FOUND"})
                    return

                # OBJECT OWNERSHIP GUARD: Başqa cihazın komandasına nəticə yazmaq qadağandır!
                if cmd["device_id"] != device_id:
                    self._send_json(403, {"error": "E_COMMAND_NOT_OWNED", "message": "Bu komanda sizin cihaza aid deyil!"})
                    return

                conn.execute(
                    "UPDATE commands SET status = ?, completed_at = ?, result_status = ? WHERE command_id = ?",
                    ("completed" if success else "failed", time.time(), status_str, cmd_id)
                )
                conn.commit()
            self._send_json(200, {"acknowledged": True})
            if not success:
                # Only the stable result code, never exception bodies or credentials.
                safe_code = status_str.split(':', 1)[0].split(' ', 1)[0]
                self._record_incident('/agent/result', safe_code, device_id)
            return

        # 8. Telemetriya (/agent/telemetry)
        if path == "/agent/telemetry":
            event_id = data.get("event_id") or secrets.token_hex(12)
            dev_id = data.get("device_id")

            with self.db.get_conn() as conn:
                # Əgər device_id qeyd olunubsa, agent auth yoxlanılır
                if dev_id and not self._authenticate_agent(conn, dev_id):
                    self._send_json(401, {"error": "E_TELEMETRY_AUTH_MISMATCH", "message": "device_id üçün etibarlı token tələb olunur"})
                    return

                conn.execute(
                    "INSERT INTO telemetry_events (event_id, install_run_id, device_id, component, version, stage, event_type, severity, error_code, duration_ms, local_time, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (event_id) DO UPDATE SET install_run_id=excluded.install_run_id, device_id=excluded.device_id, component=excluded.component, version=excluded.version, stage=excluded.stage, event_type=excluded.event_type, severity=excluded.severity, error_code=excluded.error_code, duration_ms=excluded.duration_ms, local_time=excluded.local_time, received_at=excluded.received_at",
                    (
                        event_id,
                        data.get("install_run_id"),
                        dev_id,
                        data.get("component", "agent"),
                        data.get("version", "0.1.0"),
                        data.get("stage", ""),
                        data.get("event_type", "info"),
                        data.get("severity", "INFO"),
                        data.get("error_code"),
                        data.get("duration_ms"),
                        data.get("local_time", time.time()),
                        time.time()
                    )
                )
                conn.commit()
            self._send_json(200, {"status": "RECORDED", "event_id": event_id})
            return

        # 9. Owner-Only Admin Cihaz Revoke (/admin/revoke)
                # 9.1. Owner-Only Admin Cihaz Silmə (/admin/delete)
        if path == "/admin/delete":
            admin_sec = self.headers.get("X-Owner-Admin-Secret")
            if not admin_sec or admin_sec != get_admin_secret():
                self._send_json(403, {"error": "E_ADMIN_UNAUTHORIZED", "message": "Yalnız sahib admin icazəlidir"})
                return

            target_dev = data.get("device_id")
            if not target_dev:
                self._send_json(400, {"error": "E_MISSING_DEVICE_ID"})
                return

            with self.db.get_conn() as conn:
                conn.execute("DELETE FROM devices WHERE device_id = ?", (target_dev,))
                conn.execute("DELETE FROM mobile_sessions WHERE device_id = ?", (target_dev,))
                conn.execute("DELETE FROM commands WHERE device_id = ?", (target_dev,))
                conn.execute("DELETE FROM challenges WHERE device_id = ?", (target_dev,))
                conn.commit()

            self._send_json(200, {"success": True, "device_id": target_dev, "status": "DELETED"})
            return

        # 9.2. Cihazın Özünü Serverdən Tam Ayırması (/devices/unregister)
        if path == "/devices/unregister":
            target_dev = data.get("device_id")
            if target_dev:
                with self.db.get_conn() as conn:
                    conn.execute("DELETE FROM devices WHERE device_id = ?", (target_dev,))
                    conn.execute("DELETE FROM mobile_sessions WHERE device_id = ?", (target_dev,))
                    conn.execute("DELETE FROM commands WHERE device_id = ?", (target_dev,))
                    conn.commit()
            self._send_json(200, {"success": True, "message": "Cihaz serverdən tam silindi"})
            return

        if path in ("/admin/revoke", "/admin/activate"):
            admin_sec = self.headers.get("X-Owner-Admin-Secret")
            if not admin_sec or admin_sec != get_admin_secret():
                self._send_json(403, {"error": "E_ADMIN_UNAUTHORIZED", "message": "Yalnız sahib admin icazəlidir"})
                return

            target_dev = data.get("device_id")
            if not target_dev:
                self._send_json(400, {"error": "E_MISSING_DEVICE_ID"})
                return

            target_status = 'ACTIVE' if path == '/admin/activate' else 'REVOKED'
            with self.db.get_conn() as conn:
                if not conn.execute('SELECT 1 FROM devices WHERE device_id = ?', (target_dev,)).fetchone():
                    self._send_json(404, {'error': 'E_DEVICE_NOT_FOUND'})
                    return
                conn.execute("UPDATE devices SET status = ? WHERE device_id = ?", (target_status, target_dev))
                conn.execute("DELETE FROM mobile_sessions WHERE device_id = ?", (target_dev,))
                conn.commit()

            self._send_json(200, {"success": True, "device_id": target_dev, "status": target_status})
            return

        self._send_json(404, {"error": "E_NOT_FOUND"})

class GatewayHTTPServer(ThreadingHTTPServer):
    # A slow/incomplete client must not block device polls or mobile commands.
    request_queue_size = 128


def run_server(port: int, db_path: str) -> HTTPServer:
    db = ProductionDatabase(db_path)
    GatewayHandler.db = db
    host = os.environ.get("GATEWAY_HOST", "0.0.0.0")
    server = GatewayHTTPServer((host, port), GatewayHandler)
    return server

if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 8788
    d = sys.argv[2] if len(sys.argv) > 2 else "winkey_prod.db"
    srv = run_server(p, d)
    print(f"Production Gateway running on http://0.0.0.0:{p}")
    srv.serve_forever()
