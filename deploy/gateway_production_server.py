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
import urllib.parse
from cryptography.hazmat.primitives.asymmetric import ed25519

if not __package__:
    # Keep the documented direct-script entrypoint working with shared modules.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deploy.gateway_service import GatewayService

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
    <link rel="apple-touch-icon" href="/mobile-assets/apple-touch-icon.png">
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
                <!-- Status Badge: Yalnız canlı ikon (Onlayn / Oflayn sözü yoxdur) -->
                <div id="status-badge" class="badge badge-online" style="padding: 6px; min-width: 28px; height: 28px; justify-content: center;" title="Bağlantı statusu">
                    <span class="status-dot"></span>
                    <span id="status-badge-text" style="display:none;">Onlayn</span>
                </div>

                <!-- Notification Bell -->
                <button class="icon-btn" id="bellBtn" title="Bildirişlər" onclick="openDrawer()">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
                        <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
                    </svg>
                    <span class="badge-count" id="notifBadge">0</span>
                </button>

                <!-- Install App / Add to Home Screen Button -->
                <button class="icon-btn" id="btnInstallApp" title="Tətbiqi Quraşdır / Ana Ekrana Əlavə Et" onclick="triggerAppInstall()" style="border-color: rgba(200, 242, 121, 0.4); color: var(--accent-green);">
                    <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                        <polyline points="7 10 12 15 17 10"></polyline>
                        <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                </button>

                <!-- Account / User Icon -->
                <button class="icon-btn" id="accountBtn" title="Hesab / Giriş" onclick="openAccountModal()">
                    <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                        <circle cx="12" cy="7" r="4"></circle>
                    </svg>
                </button>
            </div>
        </header>

        <!-- Main Card -->
        <main class="card">
            <!-- Vahid Kompüter Seçimi Dropdown -->
            <div id="deviceSelectWrapper" style="display:block; margin-bottom: 14px; text-align: left;">
                <span id="deviceCountBadge" style="display:none;"></span>
                <select id="deviceSelect" style="width:100%; background: #18221b; color: var(--text-main); border: 1px solid #2e3e32; border-radius: 10px; padding: 10px 14px; font-size: 0.9rem; font-weight: 600; outline: none; cursor: pointer;"></select>
            </div>
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

            <!-- iOS / Android Install Guide Modal -->
    <div class="modal-overlay" id="installGuideOverlay" style="align-items: center;">
        <div class="detail-modal-box">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
                <h3 id="installGuideTitle" style="font-size:1.05rem; font-weight:700; display:flex; align-items:center; gap:8px;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-green)" stroke-width="2">
                        <rect x="5" y="2" width="14" height="20" rx="2" ry="2"></rect>
                        <line x1="12" y1="18" x2="12.01" y2="18"></line>
                    </svg>
                    <span>Tətbiqi Quraşdır</span>
                </h3>
                <button class="drawer-close" onclick="closeInstallGuide()">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                        <line x1="18" y1="6" x2="6" y2="18"></line>
                        <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                </button>
            </div>
            <div id="installGuideContent" style="font-size:0.86rem; color:var(--text-main); line-height:1.5;">
            </div>
            <button class="action-pill-btn" style="margin-top:16px; width:100%; padding:10px;" onclick="closeInstallGuide()">Bağla</button>
        </div>
    </div>

    <!-- Account Login & Device Management Modal -->
    <div class="modal-overlay" id="accountModalOverlay" style="align-items: center;">
        <div class="detail-modal-box" style="max-height: 85vh; overflow-y: auto;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
                <h3 id="accountModalTitle" style="font-size:1.1rem; font-weight:700; display:flex; align-items:center; gap:8px;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-green)" stroke-width="2">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                        <circle cx="12" cy="7" r="4"></circle>
                    </svg>
                    <span>Hesab İdarəetməsi</span>
                </h3>
                <button class="drawer-close" onclick="closeAccountModal()">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                        <line x1="18" y1="6" x2="6" y2="18"></line>
                        <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                </button>
            </div>

            <!-- GİRİŞ FORMASI (Giriş edilmədikdə) -->
            <div id="accountAuthSection">
                <div style="display:flex; gap:8px; margin-bottom:14px; background:#121814; padding:4px; border-radius:10px;">
                    <button type="button" id="tabAuthLogin" class="action-pill-btn" style="background:#223026; color:var(--accent-green);" onclick="switchAuthTab('login')">Daxil Ol</button>
                    <button type="button" id="tabAuthRegister" class="action-pill-btn" onclick="switchAuthTab('register')">Qeydiyyat</button>
                </div>
                <div style="display:flex; flex-direction:column; gap:10px;">
                    <div>
                        <label style="font-size:0.75rem; color:var(--text-muted); margin-bottom:4px; display:block;">E-poçt ünvanı:</label>
                        <input type="email" id="txtAuthEmail" placeholder="ad@domain.com" style="width:100%; padding:10px 12px; background:#19231d; border:1px solid #2e3e32; border-radius:10px; color:#fff; font-size:0.9rem; outline:none;" />
                    </div>
                    <div>
                        <label style="font-size:0.75rem; color:var(--text-muted); margin-bottom:4px; display:block;">Şifrə (min. 10 simvol):</label>
                        <input type="password" id="txtAuthPassword" placeholder="••••••••••" style="width:100%; padding:10px 12px; background:#19231d; border:1px solid #2e3e32; border-radius:10px; color:#fff; font-size:0.9rem; outline:none;" />
                    </div>
                    <div id="authErrorMsg" style="color:var(--danger); font-size:0.78rem; min-height:18px;"></div>
                    <button type="button" id="btnSubmitAuth" class="action-pill-btn" style="background:var(--accent-green); color:#0c0f0d; font-weight:700; padding:12px; font-size:0.92rem; border:none; margin-top:4px;" onclick="submitAuth()">
                        Daxil Ol
                    </button>
                    <p style="font-size:0.75rem; color:var(--text-dim); line-height:1.4; text-align:center; margin-top:6px;">
                        Kompüterinizdə daxil olduğunuz eyni hesabla daxil olun. Bütün bağlı kompüterləriniz avtomatik görünəcək.
                    </p>
                </div>
            </div>

            <!-- HESAB PROFİLİ & CİHAZLAR (Giriş edildikdə) -->
            <div id="accountProfileSection" style="display:none;">
                <div style="background:#19231d; border:1px solid #2e3e32; border-radius:12px; padding:12px 14px; margin-bottom:14px; display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <div style="font-size:0.72rem; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.5px;">Aktiv Hesab</div>
                        <div id="lblAccountEmail" style="font-size:0.92rem; font-weight:700; color:#fff; word-break:break-all;">—</div>
                    </div>
                    <button type="button" class="action-pill-btn" style="background:#261818; border-color:var(--danger); color:#fca5a5; padding:6px 12px; font-size:0.78rem;" onclick="logoutAccount()">
                        Çıxış
                    </button>
                </div>

                <div style="font-size:0.8rem; font-weight:700; color:var(--text-muted); margin-bottom:8px; display:flex; justify-content:space-between; align-items:center;">
                    <span>Hesaba Bağlı Kompüterlər</span>
                    <button type="button" class="action-pill-btn" style="padding:4px 8px; font-size:0.72rem;" onclick="refreshAccountDevices()">Yenilə</button>
                </div>
                <div id="accountDevicesList" style="display:flex; flex-direction:column; gap:8px; max-height:240px; overflow-y:auto;">
                    <!-- JS ilə dinamik doldurulur -->
                </div>
            </div>
        </div>
    </div>

    <script src="/mobile-assets/jsQR.js"></script>
    <script src="/mobile-assets/install.js"></script>
    <script src="/mobile-assets/devices.js"></script>
    <script>
        const urlParams = new URLSearchParams(window.location.search);
        let targetDevice = urlParams.get('device') || localStorage.getItem('winkey_dev_id') || '';
        let pairCode = urlParams.get('code') || '';
        let authToken = localStorage.getItem('winkey_token') || '';


        // --- TƏTBİQİN QURAŞDIRILMASI (iOS Ana Ekran & Android App) ---
        let deferredPrompt = null;
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
        });

        function isRunningStandalone() {
            return (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || (window.navigator.standalone === true);
        }

        function checkInstallButtonVisibility() {
            const btn = document.getElementById('btnInstallApp');
            if (btn && isRunningStandalone()) {
                btn.style.display = 'none';
            }
        }

        async function triggerAppInstall() {
            const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
            const overlay = document.getElementById('installGuideOverlay');
            const content = document.getElementById('installGuideContent');
            const title = document.getElementById('installGuideTitle');

            if (isIOS) {
                if (title) title.innerHTML = '<span>📱 iOS: Ana Ekrana Əlavə Et</span>';
                if (content) {
                    content.innerHTML = `
                        <p style="margin-bottom:12px; color:var(--text-muted);">iPhone/iPad-də WinKey-i ayrıca proqram kimi işlətmək üçün:</p>
                        <div style="background:#18221b; border:1px solid #2e3e32; border-radius:10px; padding:12px; display:flex; flex-direction:column; gap:10px;">
                            <div style="display:flex; align-items:center; gap:10px;">
                                <span style="background:var(--accent-green); color:#000; font-weight:800; border-radius:50%; width:24px; height:24px; display:flex; align-items:center; justify-content:center; font-size:12px; flex-shrink:0;">1</span>
                                <span>Safari-nin aşağı menyusunda <strong>Paylaş (Share <svg style="display:inline-block; vertical-align:middle;" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="2" x2="12" y2="15"/></svg>)</strong> düyməsinə basın.</span>
                            </div>
                            <div style="display:flex; align-items:center; gap:10px;">
                                <span style="background:var(--accent-green); color:#000; font-weight:800; border-radius:50%; width:24px; height:24px; display:flex; align-items:center; justify-content:center; font-size:12px; flex-shrink:0;">2</span>
                                <span>Aşağı çəkib <strong>"Ana ekrana əlavə et" (Add to Home Screen ⊞)</strong> seçin.</span>
                            </div>
                            <div style="display:flex; align-items:center; gap:10px;">
                                <span style="background:var(--accent-green); color:#000; font-weight:800; border-radius:50%; width:24px; height:24px; display:flex; align-items:center; justify-content:center; font-size:12px; flex-shrink:0;">3</span>
                                <span>Yuxarı sağda <strong>"Əlavə et" (Add)</strong> basın. Proqram ana ekranınızda hazır olacaq!</span>
                            </div>
                        </div>
                    `;
                }
                if (overlay) overlay.style.display = 'flex';
            } else if (deferredPrompt) {
                deferredPrompt.prompt();
                const choiceResult = await deferredPrompt.userChoice;
                if (choiceResult && choiceResult.outcome === 'accepted') {
                    recordNotification(true, 'Tətbiq Quraşdırıldı', 'WinKey Pro ana ekrana əlavə edildi.');
                }
                deferredPrompt = null;
            } else {
                if (title) title.innerHTML = '<span>🤖 Android: Tətbiqi Quraşdır</span>';
                if (content) {
                    content.innerHTML = `
                        <p style="margin-bottom:12px; color:var(--text-muted);">Android cihazında tətbiq kimi quraşdırmaq üçün:</p>
                        <div style="background:#18221b; border:1px solid #2e3e32; border-radius:10px; padding:12px; display:flex; flex-direction:column; gap:10px;">
                            <div style="display:flex; align-items:center; gap:10px;">
                                <span style="background:var(--accent-green); color:#000; font-weight:800; border-radius:50%; width:24px; height:24px; display:flex; align-items:center; justify-content:center; font-size:12px; flex-shrink:0;">1</span>
                                <span>Brauzerin (Chrome) menyusunda <strong>üç nöqtə (⋮)</strong> işarəsinə toxunun.</span>
                            </div>
                            <div style="display:flex; align-items:center; gap:10px;">
                                <span style="background:var(--accent-green); color:#000; font-weight:800; border-radius:50%; width:24px; height:24px; display:flex; align-items:center; justify-content:center; font-size:12px; flex-shrink:0;">2</span>
                                <span><strong>"Tətbiqi quraşdır"</strong> və ya <strong>"Ana ekrana əlavə et"</strong> seçin.</span>
                            </div>
                        </div>
                    `;
                }
                if (overlay) overlay.style.display = 'flex';
            }
        }

        function closeInstallGuide() {
            const overlay = document.getElementById('installGuideOverlay');
            if (overlay) overlay.style.display = 'none';
        }

        // --- HESAB GİRİŞİ VƏ ÇOXLU CİHAZ İDARƏETMƏSİ ---
        let currentAuthMode = 'login';
        let userAccountDevices = [];

        function openAccountModal() {
            const overlay = document.getElementById('accountModalOverlay');
            if (overlay) overlay.style.display = 'flex';
            checkAccountState();
        }

        function closeAccountModal() {
            const overlay = document.getElementById('accountModalOverlay');
            if (overlay) overlay.style.display = 'none';
        }

        function switchAuthTab(mode) {
            currentAuthMode = mode;
            const tabLogin = document.getElementById('tabAuthLogin');
            const tabReg = document.getElementById('tabAuthRegister');
            const submitBtn = document.getElementById('btnSubmitAuth');
            const errEl = document.getElementById('authErrorMsg');
            if (errEl) errEl.textContent = '';

            if (mode === 'login') {
                if (tabLogin) { tabLogin.style.background = '#223026'; tabLogin.style.color = 'var(--accent-green)'; }
                if (tabReg) { tabReg.style.background = '#18221b'; tabReg.style.color = 'var(--text-main)'; }
                if (submitBtn) submitBtn.textContent = 'Daxil Ol';
            } else {
                if (tabReg) { tabReg.style.background = '#223026'; tabReg.style.color = 'var(--accent-green)'; }
                if (tabLogin) { tabLogin.style.background = '#18221b'; tabLogin.style.color = 'var(--text-main)'; }
                if (submitBtn) submitBtn.textContent = 'Qeydiyyatdan Keç';
            }
        }

        async function checkAccountState() {
            const token = localStorage.getItem('winkey_account_token');
            const email = localStorage.getItem('winkey_account_email');
            const authSec = document.getElementById('accountAuthSection');
            const profSec = document.getElementById('accountProfileSection');
            const emailEl = document.getElementById('lblAccountEmail');

            if (token && email) {
                if (authSec) authSec.style.display = 'none';
                if (profSec) profSec.style.display = 'block';
                if (emailEl) emailEl.textContent = email;
                await refreshAccountDevices();
            } else {
                if (authSec) authSec.style.display = 'block';
                if (profSec) profSec.style.display = 'none';
            }
        }

        async function submitAuth() {
            const emailInput = document.getElementById('txtAuthEmail');
            const passInput = document.getElementById('txtAuthPassword');
            const errEl = document.getElementById('authErrorMsg');
            const submitBtn = document.getElementById('btnSubmitAuth');

            const email = (emailInput?.value || '').trim();
            const password = (passInput?.value || '').trim();

            if (!email || !password) {
                if (errEl) errEl.textContent = 'Zəhmət olmasa e-poçt və şifrəni daxil edin.';
                return;
            }
            if (password.length < 10) {
                if (errEl) errEl.textContent = 'Şifrə ən azı 10 simvol olmalıdır.';
                return;
            }

            if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Gözləyin…'; }
            if (errEl) errEl.textContent = '';

            try {
                let res;
                if (currentAuthMode === 'login') {
                    res = await window.WinKeyDevices?.login(email, password);
                } else {
                    res = await window.WinKeyDevices?.register(email, password);
                }
                if (emailInput) emailInput.value = '';
                if (passInput) passInput.value = '';
                await checkAccountState();
                updateDeviceSwitcher();
                recordNotification(true, 'Hesab Girişi', 'Uğurla daxil oldunuz: ' + (res?.email || email));
            } catch (err) {
                if (errEl) errEl.textContent = String(err.message || err);
            } finally {
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.textContent = currentAuthMode === 'login' ? 'Daxil Ol' : 'Qeydiyyatdan Keç';
                }
            }
        }

        async function logoutAccount() {
            if (confirm('Hesabdan çıxmaq istəyirsiniz?')) {
                await window.WinKeyDevices?.logout();
                await checkAccountState();
                updateDeviceSwitcher();
                recordNotification(false, 'Hesabdan Çıxıldı', 'Hesab sessiyası sonlandırıldı.');
                closeAccountModal();
            }
        }

        async function refreshAccountDevices() {
            const token = localStorage.getItem('winkey_account_token');
            if (!token) return;
            const container = document.getElementById('accountDevicesList');
            if (container) container.innerHTML = '<div style="color:#888; font-size:0.75rem; text-align:center; padding:10px;">Cihazlar yüklənir…</div>';

            try {
                const res = await window.WinKeyDevices?.syncAccount();
                if (res && res.devices) {
                    userAccountDevices = res.devices;
                    renderAccountDevicesList(res.devices);
                    updateDeviceSwitcher();
                } else {
                    if (container) container.innerHTML = '<div style="color:#888; font-size:0.75rem; text-align:center; padding:10px;">Bu hesaba bağlı kompüter yoxdur. PC-də hesabınıza daxil olun.</div>';
                }
            } catch (e) {
                if (container) container.innerHTML = '<div style="color:var(--danger); font-size:0.75rem; text-align:center; padding:10px;">Yüklənmə xətası: ' + e + '</div>';
            }
        }

        function renderAccountDevicesList(devices) {
            const container = document.getElementById('accountDevicesList');
            if (!container) return;
            if (!devices.length) {
                container.innerHTML = '<div style="color:#888; font-size:0.75rem; text-align:center; padding:10px;">Bu hesaba bağlı kompüter tapılmadı.</div>';
                return;
            }
            container.innerHTML = '';
            for (const d of devices) {
                const item = document.createElement('div');
                item.className = 'notification-item';
                item.style.padding = '10px 12px';
                const isOnline = Boolean(d.online);
                const isSelected = (d.device_id === targetDevice);
                const compName = (d.computer_name || 'Kompüter');

                item.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
                        <div style="flex:1; min-width:0;">
                            <div style="font-size:0.86rem; font-weight:700; color:#fff; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${compName} ${isSelected ? '<span style="color:var(--accent-green); font-size:0.75rem;">(Seçilib)</span>' : ''}</div>
                            <div style="font-size:0.72rem; color:var(--text-dim); white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${d.device_id}</div>
                            <div style="font-size:0.72rem; margin-top:2px; color:${isOnline ? 'var(--accent-green)' : 'var(--danger)'};">
                                ${isOnline ? '● Onlayn' : '○ Oflayn'} · ${d.locked ? '🔒 Kilidli' : '🔓 Açıq'}
                            </div>
                        </div>
                        <div style="display:flex; gap:6px; align-items:center; flex-shrink:0;">
                            <button type="button" class="action-pill-btn" style="padding:6px 12px; font-size:0.76rem; ${isSelected ? 'background:var(--accent-green); color:#0c0f0d; font-weight:700;' : ''}" onclick="activateDeviceFromModal('${d.device_id}')">
                                ${isSelected ? 'Aktivdir' : 'Seç'}
                            </button>
                            <button type="button" class="icon-btn" style="border-color:#4a2320; color:var(--danger); background:#1f1414; padding:6px; width:34px; height:34px; display:inline-flex; align-items:center; justify-content:center; border-radius:8px; cursor:pointer;" title="Kompüteri Hesabdan Sil" onclick="deleteDeviceFromModal('${d.device_id}', '${compName.replace(/'/g, "\\'")}')">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <polyline points="3 6 5 6 21 6"></polyline>
                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                                    <line x1="10" y1="11" x2="10" y2="17"></line>
                                    <line x1="14" y1="11" x2="14" y2="17"></line>
                                </svg>
                            </button>
                        </div>
                    </div>
                `;
                container.appendChild(item);
            }
        }

        async function deleteDeviceFromModal(devId, compName) {
            if (!confirm(`"${compName}" kompüterini silmək və telefon girişini ləğv etmək istəyirsiniz?`)) return;
            try {
                const acctToken = localStorage.getItem('winkey_account_token');
                if (acctToken && devId) {
                    await request('/accounts/device-action', {
                        method: 'POST',
                        headers: {'Authorization': 'Bearer ' + acctToken, 'Content-Type': 'application/json'},
                        body: JSON.stringify({device_id: devId, action: 'delete'})
                    });
                }
                if (window.WinKeyDevices) {
                    window.WinKeyDevices.remove(devId);
                }
                recordNotification(false, "Kompüter Silindi", `"${compName}" hesaba bağlı cihazlardan silindi.`);
                await refreshAccountDevices();
            } catch (err) {
                alert("Silinmə zamanı xəta baş verdi: " + err);
            }
        }

        function activateDeviceFromModal(devId) {
            const sel = document.getElementById('deviceSelect');
            if (sel) {
                sel.value = devId;
                sel.dispatchEvent(new Event('change'));
            }
            closeAccountModal();
        }

        function updateDeviceSwitcher() {
            const wrapper = document.getElementById('deviceSelectWrapper');
            const sel = document.getElementById('deviceSelect');
            if (!sel || !wrapper) return;

            if (sel.options.length > 1) {
                wrapper.style.display = 'block';
            } else {
                wrapper.style.display = 'none';
            }
        }


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
        let isPcOnline = null;
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

        function updateMobilePresence(device) {
            if (!device || device.id !== targetDevice) return;
            isPcOnline = Boolean(device.online);
            isPcLocked = Boolean(device.locked);
            devNameEl.textContent = device.name;
            badgeEl.title = isPcOnline ? 'Onlayn' : 'Oflayn';
            badgeEl.className = isPcOnline ? 'badge badge-online' : 'badge badge-offline';
            renderState();
        }

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
            isPcLocked = device && typeof device.locked === 'boolean' ? device.locked : null;
            isPcOnline = device && typeof device.online === 'boolean' ? device.online : null;
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
            circleBtn.disabled = isPcLocked === null || isPcOnline === false;
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
                    const device = await window.WinKeyDevices.start(selectMobileDevice, updateMobilePresence);
                    selectMobileDevice(device);

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
                    isPcOnline = d.online !== false;
                    renderState();
                    badgeTextEl.textContent = isPcOnline ? 'Onlayn' : 'Oflayn';
                    badgeEl.className = isPcOnline ? 'badge badge-online' : 'badge badge-offline';
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
            if (isPcOnline === false) { statusBox.textContent = 'Kompüter oflayndır və ya mobil idarəetmə dayandırılıb.'; return; }
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
            try {
                const acctToken = localStorage.getItem('winkey_account_token');
                if (acctToken && revokedDevice) {
                    await request('/accounts/device-action', {
                        method: 'POST',
                        headers: {'Authorization': 'Bearer ' + acctToken, 'Content-Type': 'application/json'},
                        body: JSON.stringify({device_id: revokedDevice, action: 'delete'})
                    });
                } else if (authToken) {
                    await request('/mobile/revoke', {
                        method: 'POST',
                        headers: {'Authorization': 'Bearer ' + authToken}
                    });
                }
            } catch(e) {}
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
                    session_token: authToken,
                    device_id: targetDevice
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
                        isPcOnline = Boolean(msg.online);
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

        checkInstallButtonVisibility();
        init();
    </script>

</body>
</html>"""

def get_admin_html() -> str:
    return """<!DOCTYPE html>
<html lang="az">
<head>
    <meta charset="utf-8">
    <title>WinKey Pro — Şəxsi Sahib İdarəetmə Mərkəzi (Private Admin)</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        :root {
            --bg: #090d0b;
            --panel: #111613;
            --panel-border: #1a231e;
            --panel-sub: #161d19;
            --text: #e6ede8;
            --text-muted: #8e9e95;
            --text-faint: #5a6860;
            --green: #10b981;
            --green-glow: rgba(16, 185, 129, 0.15);
            --green-border: rgba(16, 185, 129, 0.3);
            --accent: #c8f279;
            --red: #ef4444;
            --red-glow: rgba(239, 68, 68, 0.15);
            --red-border: rgba(239, 68, 68, 0.3);
            --amber: #f59e0b;
            --radius-sm: 6px;
            --radius-md: 10px;
            --radius-lg: 14px;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; }
        
        /* Üst Zolaq (Navbar) */
        header.admin-nav {
            position: sticky; top: 0; z-index: 50;
            background: rgba(9, 13, 11, 0.92);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid var(--panel-border);
            padding: 12px 24px;
            display: flex; justify-content: space-between; align-items: center;
        }
        .nav-brand { display: flex; align-items: center; gap: 12px; }
        .nav-logo-pill {
            background: #13241b; color: var(--accent);
            border: 1px solid var(--green-border);
            padding: 4px 10px; border-radius: var(--radius-sm);
            font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
        }
        .nav-title { font-size: 1.15rem; font-weight: 700; color: #fff; letter-spacing: -0.3px; }
        .nav-right { display: flex; align-items: center; gap: 16px; font-size: 0.85rem; }
        .ws-badge {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 4px 10px; border-radius: var(--radius-sm); font-size: 0.75rem; font-weight: 600;
        }
        .ws-online { background: var(--green-glow); color: var(--green); border: 1px solid var(--green-border); }
        .ws-offline { background: var(--red-glow); color: var(--red); border: 1px solid var(--red-border); }
        .ws-dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }

        /* Əsas Sahə */
        main.admin-content { flex: 1; max-width: 1300px; width: 100%; margin: 0 auto; padding: 24px; display: flex; flex-direction: column; gap: 20px; }

        /* Giriş Qutusu (Login Screen) */
        .auth-card {
            max-width: 480px; width: 100%; margin: 80px auto;
            background: var(--panel); border: 1px solid var(--panel-border); border-radius: var(--radius-lg);
            padding: 32px; display: flex; flex-direction: column; gap: 18px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }
        .auth-title { font-size: 1.3rem; font-weight: 700; color: #fff; }
        .auth-desc { font-size: 0.85rem; color: var(--text-muted); line-height: 1.5; }

        /* Düymələr və Girişlər */
        input[type="text"], input[type="password"], select {
            width: 100%; padding: 10px 14px; background: var(--panel-sub);
            border: 1px solid var(--panel-border); border-radius: var(--radius-sm);
            color: #fff; font-size: 0.9rem; outline: none; transition: 0.15s;
        }
        input:focus, select:focus { border-color: var(--green); }
        .btn {
            display: inline-flex; align-items: center; justify-content: center; gap: 6px;
            padding: 9px 16px; border-radius: var(--radius-sm); font-size: 0.85rem; font-weight: 600;
            cursor: pointer; border: none; transition: 0.15s; white-space: nowrap; text-decoration: none;
        }
        .btn-primary { background: var(--accent); color: #090d0b; }
        .btn-primary:hover { opacity: 0.9; }
        .btn-secondary { background: var(--panel-sub); color: var(--text); border: 1px solid var(--panel-border); }
        .btn-secondary:hover { background: #1c2520; }
        .btn-danger { background: var(--red-glow); color: var(--red); border: 1px solid var(--red-border); }
        .btn-danger:hover { background: rgba(239, 68, 68, 0.25); }
        .btn-sm { padding: 5px 10px; font-size: 0.78rem; }

        /* Tab Menyu */
        .tab-bar {
            display: flex; gap: 6px; background: var(--panel); border: 1px solid var(--panel-border);
            padding: 4px; border-radius: var(--radius-md); overflow-x: auto;
        }
        .tab-btn {
            background: transparent; border: none; color: var(--text-muted);
            padding: 8px 16px; border-radius: var(--radius-sm); font-size: 0.85rem; font-weight: 600;
            cursor: pointer; transition: 0.15s; display: flex; align-items: center; gap: 8px;
        }
        .tab-btn:hover { color: #fff; }
        .tab-btn.active { background: var(--panel-sub); color: var(--accent); border: 1px solid var(--green-border); }

        /* Kartlar və Grid */
        .grid-overview { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }
        .metric-card {
            background: var(--panel); border: 1px solid var(--panel-border); border-radius: var(--radius-md);
            padding: 18px; display: flex; flex-direction: column; gap: 8px;
        }
        .metric-label { font-size: 0.75rem; text-transform: uppercase; font-weight: 600; color: var(--text-muted); letter-spacing: 0.5px; }
        .metric-value { font-size: 1.6rem; font-weight: 700; color: #fff; font-family: monospace; }
        .metric-sub { font-size: 0.78rem; color: var(--text-faint); }

        .card {
            background: var(--panel); border: 1px solid var(--panel-border); border-radius: var(--radius-md);
            padding: 20px; display: flex; flex-direction: column; gap: 16px;
        }
        .card-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
        .card-title { font-size: 1.05rem; font-weight: 700; color: #fff; }

        /* Cədvəllər */
        .table-responsive { width: 100%; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--panel-border); }
        th { color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.72rem; letter-spacing: 0.5px; }
        tr:hover td { background: rgba(255, 255, 255, 0.02); }
        code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.8rem; color: #a3e635; }

        /* Status Pilleri */
        .pill { display: inline-flex; align-items: center; gap: 5px; padding: 3px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 600; }
        .pill-active { background: var(--green-glow); color: var(--green); border: 1px solid var(--green-border); }
        .pill-revoked { background: var(--red-glow); color: var(--red); border: 1px solid var(--red-border); }
        .pill-online { background: #064e3b; color: #34d399; }
        .pill-offline { background: #262626; color: #a3a3a3; }
        .pill-info { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
        .pill-warn { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }

        /* Səhifələmə (Pagination) */
        .pagination-bar {
            display: flex; justify-content: space-between; align-items: center; padding-top: 12px;
            font-size: 0.85rem; color: var(--text-muted); flex-wrap: wrap; gap: 12px;
        }
        .pagination-controls { display: flex; align-items: center; gap: 8px; }

        /* Modal Dialog */
        .modal-overlay {
            position: fixed; inset: 0; background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(4px); z-index: 100;
            display: flex; justify-content: center; align-items: center; padding: 20px;
        }
        .modal-overlay[hidden] { display: none !important; }
        .modal-box {
            background: var(--panel); border: 1px solid var(--panel-border); border-radius: var(--radius-lg);
            max-width: 840px; width: 100%; max-height: 85vh; overflow-y: auto;
            padding: 24px; display: flex; flex-direction: column; gap: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.8);
        }

        /* Timeline addımları */
        .timeline { display: flex; flex-direction: column; gap: 12px; position: relative; padding-left: 20px; }
        .timeline::before {
            content: ''; position: absolute; left: 6px; top: 8px; bottom: 8px; width: 2px;
            background: var(--panel-border);
        }
        .timeline-item { position: relative; display: flex; flex-direction: column; gap: 4px; }
        .timeline-dot {
            position: absolute; left: -20px; top: 4px; width: 10px; height: 10px; border-radius: 50%;
            background: var(--green); border: 2px solid var(--bg);
        }
        .timeline-title { font-size: 0.85rem; font-weight: 600; color: #fff; }
        .timeline-meta { font-size: 0.75rem; color: var(--text-muted); display: flex; gap: 12px; }

        .filter-row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
        .filter-input { flex: 1; min-width: 180px; }

        .progress-bar-wrap { width: 100%; height: 6px; background: var(--panel-sub); border-radius: 3px; overflow: hidden; margin-top: 6px; }
        .progress-bar-fill { height: 100%; background: var(--green); transition: width 0.3s; }
        .err-msg { color: var(--red); font-size: 0.85rem; }
    </style>
</head>
<body>

    <!-- Üst Zolaq -->
    <header class="admin-nav">
        <div class="nav-brand">
            <span class="nav-logo-pill">Admin Center</span>
            <span class="nav-title">WinKey Pro — Şəxsi Sahib Paneli</span>
        </div>
        <div class="nav-right" id="nav-right-box" style="display:none;">
            <div id="wsStatusBadge" class="ws-badge ws-offline">
                <span class="ws-dot"></span> <span id="wsStatusText">Bağlantı kəsildi</span>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="refreshCurrentTab()" title="Yenilə">🔄 Yenilə</button>
            <button class="btn btn-danger btn-sm" onclick="logoutAdmin()">Çıxış</button>
        </div>
    </header>

    <main class="admin-content">

        <!-- Autentifikasiya Paneli -->
        <div class="auth-card" id="authBox">
            <div class="auth-title">Sahib Girişi</div>
            <div class="auth-desc">WinKey Pro serverini idarə etmək üçün təyin edilmiş <code>X-Owner-Admin-Secret</code> daxil edin.</div>
            <div style="display:flex; flex-direction:column; gap:10px;">
                <input type="password" id="inputAdminSecret" placeholder="X-Owner-Admin-Secret...">
                <button class="btn btn-primary" onclick="loginAdmin()">Daxil Ol</button>
            </div>
            <div id="authErrMsg" class="err-msg"></div>
        </div>

        <!-- Əsas Dashboard Panelləri (Girişdən sonra) -->
        <div id="dashboardContainer" style="display:none; flex-direction:column; gap:20px;">
            
            <!-- Tablar -->
            <div class="tab-bar">
                <button class="tab-btn active" id="tabBtn-overview" onclick="switchTab('overview')">📊 Ümumi Baxış</button>
                <button class="tab-btn" id="tabBtn-devices" onclick="switchTab('devices')">💻 PC Cihazları</button>
                <button class="tab-btn" id="tabBtn-updates" onclick="switchTab('updates')">⚡ OTA Yenilənmələr</button>
                <button class="tab-btn" id="tabBtn-telemetry" onclick="switchTab('telemetry')">📜 Hadisələr və Diaqnostika</button>
            </div>

            <!-- ==================== BÖLMƏ 1: ÜMUMİ BAXIŞ ==================== -->
            <div id="tabPanel-overview" style="display:flex; flex-direction:column; gap:20px;">
                <div class="grid-overview">
                    <div class="metric-card">
                        <div class="metric-label">Qeydiyyatlı Cihazlar</div>
                        <div class="metric-value" id="ovTotalDevices">—</div>
                        <div class="metric-sub" id="ovActiveRevoked">Aktiv: — | Ləğv: —</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Online Cihazlar (Fresh)</div>
                        <div class="metric-value" style="color:var(--green);" id="ovOnlineDevices">—</div>
                        <div class="metric-sub" id="ovOfflineDevices">Oflayn: —</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Son 24 Saat Xətaları</div>
                        <div class="metric-value" style="color:var(--amber);" id="ovError24h">—</div>
                        <div class="metric-sub">Kritik və ya xəta insidentləri</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Cari Server Buraxılışı</div>
                        <div class="metric-value" style="color:var(--accent);" id="ovReleaseVer">—</div>
                        <div class="metric-sub" id="ovReleaseId">ID: —</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">OTA Uğur Nisbəti</div>
                        <div class="metric-value" id="ovOtaCommitted">—</div>
                        <div class="metric-sub" id="ovOtaRollback">Rollback: — | Xəta: —</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Telemetriya Hadisələri</div>
                        <div class="metric-value" id="ovTotalTelemetry">—</div>
                        <div class="metric-sub">Qeydə alınmış bütün loqlar</div>
                    </div>
                </div>

                <!-- Server Sağlamlıq və Təhlükəsizlik Kartı -->
                <div class="card">
                    <div class="card-title">Mərkəzi Server Vəziyyəti</div>
                    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:16px; font-size:0.85rem;">
                        <div style="background:var(--panel-sub); padding:14px; border-radius:var(--radius-sm); border:1px solid var(--panel-border);">
                            <div style="color:var(--text-muted); font-size:0.75rem;">YENİLƏNMƏ ANBARI (REPOSITORY)</div>
                            <div style="font-weight:600; margin-top:4px;" id="repoStatusText">Yoxlanılır...</div>
                            <div style="color:var(--text-faint); margin-top:4px;" id="repoPathText">Yol: deploy/windows_release/WinKeyUpdate.zip</div>
                        </div>
                        <div style="background:var(--panel-sub); padding:14px; border-radius:var(--radius-sm); border:1px solid var(--panel-border);">
                            <div style="color:var(--text-muted); font-size:0.75rem;">MƏLUMAT BAZASI VƏ SESSİYALAR</div>
                            <div style="font-weight:600; margin-top:4px;">SQLite / PostgreSQL İkiqat Dəstək</div>
                            <div style="color:var(--text-faint); margin-top:4px;">Multi-Tenant & Session-Scoped Isolation</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ==================== BÖLMƏ 2: CİHAZLAR ==================== -->
            <div id="tabPanel-devices" style="display:none; flex-direction:column; gap:20px;">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">Qeydiyyatdan Keçmiş PC Cihazları</div>
                        <div class="filter-row">
                            <input type="text" id="devSearchInput" class="filter-input" placeholder="Kompüter adı və ya ID ilə axtar..." oninput="debouncedLoadDevices()">
                            <select id="devStatusFilter" onchange="loadDevices(1)" style="width:130px;">
                                <option value="">Bütün Statuslar</option>
                                <option value="ACTIVE">Aktiv (ACTIVE)</option>
                                <option value="REVOKED">Ləğv edilmiş (REVOKED)</option>
                            </select>
                            <select id="devOnlineFilter" onchange="loadDevices(1)" style="width:130px;">
                                <option value="">Bütün Əlaqələr</option>
                                <option value="true">Yalnız Online</option>
                                <option value="false">Yalnız Offline</option>
                            </select>
                            <select id="devSortFilter" onchange="loadDevices(1)" style="width:140px;">
                                <option value="last_seen_desc">Son Görülmə (Azalan)</option>
                                <option value="created_desc">Qeydiyyat (Yeni)</option>
                                <option value="created_asc">Qeydiyyat (Köhnə)</option>
                                <option value="name_asc">Ad (A-Z)</option>
                            </select>
                        </div>
                    </div>

                    <div class="table-responsive">
                        <table id="devicesTable">
                            <thead>
                                <tr>
                                    <th>Cihaz ID</th>
                                    <th>Kompüter Adı</th>
                                    <th>Əlaqə</th>
                                    <th>Qeydiyyat</th>
                                    <th>Worker Versiyası</th>
                                    <th>Serverdə Son</th>
                                    <th>Kilid</th>
                                    <th>PIN</th>
                                    <th>Son Görülmə</th>
                                    <th>Əməliyyatlar</th>
                                </tr>
                            </thead>
                            <tbody id="devicesTableBody">
                                <tr><td colspan="10" style="color:var(--text-muted); text-align:center;">Yüklənir...</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <div class="pagination-bar" id="devicesPagination">
                        <div id="devicesCountInfo">0 cihazdan 0 göstərilir</div>
                        <div class="pagination-controls">
                            <button class="btn btn-secondary btn-sm" id="btnDevPrev" onclick="changeDevPage(-1)">← Əvvəlki</button>
                            <span id="devPageIndicator">Səhifə 1 / 1</span>
                            <button class="btn btn-secondary btn-sm" id="btnDevNext" onclick="changeDevPage(1)">Növbəti →</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ==================== BÖLMƏ 3: OTA YENİLƏNMƏLƏR ==================== -->
            <div id="tabPanel-updates" style="display:none; flex-direction:column; gap:20px;">
                
                <!-- İmzalı Paket Yayımlama Bloku -->
                <div class="card">
                    <div class="card-title">İmzalı Release Paketini Yayımla (Publish Package)</div>
                    <div style="font-size:0.85rem; color:var(--text-muted);">
                        Serveri yenidən başlatmadan yeni imzalanmış <code>WinKeyUpdate-*.zip</code> paketini birbaşa mərkəzə yükləyin. 
                        Paket Ed25519 public key ilə təsdiqlənəcək və bütün aktiv cihazlara dərhal bildiriş göndəriləcək.
                    </div>
                    <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin-top:8px;">
                        <input type="file" id="packageFileInput" accept=".zip" style="max-width:320px; font-size:0.8rem;">
                        <button class="btn btn-primary" onclick="uploadPackage()">🚀 Paketi Yayımla</button>
                    </div>
                    <div id="uploadProgressWrap" style="display:none; flex-direction:column; gap:4px; margin-top:10px;">
                        <div style="display:flex; justify-content:space-between; font-size:0.75rem;">
                            <span id="uploadStatusLabel">Yüklənir...</span>
                            <span id="uploadPercentLabel">0%</span>
                        </div>
                        <div class="progress-bar-wrap"><div class="progress-bar-fill" id="uploadBarFill" style="width:0%;"></div></div>
                    </div>
                    <div id="uploadResultMsg" style="font-size:0.85rem; margin-top:6px;"></div>
                </div>

                <!-- Cihazların OTA Update Mərhələləri -->
                <div class="card">
                    <div class="card-title">Cihazların Update Mərhələləri və Keçid Tarixçəsi</div>
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>Cihaz ID</th>
                                    <th>Son Mərhələ</th>
                                    <th>Versiya</th>
                                    <th>Müddət (ms)</th>
                                    <th>Xəta Kodu</th>
                                    <th>Qeydə Alınma Vaxtı</th>
                                </tr>
                            </thead>
                            <tbody id="updateStagesTableBody">
                                <tr><td colspan="6" style="color:var(--text-muted); text-align:center;">Yüklənir...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- ==================== BÖLMƏ 4: TELEMETRİYA VƏ HADİSƏLƏR ==================== -->
            <div id="tabPanel-telemetry" style="display:none; flex-direction:column; gap:20px;">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">Hadisələr və Performans Diaqnostikası</div>
                        <div style="display:flex; gap:8px;">
                            <button class="btn btn-secondary btn-sm" onclick="exportTelemetry('json')">📥 JSON İxrac</button>
                            <button class="btn btn-secondary btn-sm" onclick="exportTelemetry('csv')">📥 CSV İxrac</button>
                        </div>
                    </div>

                    <!-- Filtrlər -->
                    <div class="filter-row">
                        <input type="text" id="telDevInput" class="filter-input" placeholder="Cihaz ID ilə filtr..." oninput="debouncedLoadTelemetry()">
                        <select id="telCompFilter" onchange="loadTelemetry(1)" style="width:130px;">
                            <option value="">Bütün Komponentlər</option>
                            <option value="agent">Agent / Worker</option>
                            <option value="mobile">Mobil PWA</option>
                            <option value="installer">Quraşdırıcı</option>
                            <option value="service">Windows Xidməti</option>
                        </select>
                        <select id="telSevFilter" onchange="loadTelemetry(1)" style="width:130px;">
                            <option value="">Bütün Dərəcələr</option>
                            <option value="INFO">INFO</option>
                            <option value="WARN">WARN</option>
                            <option value="ERROR">ERROR</option>
                            <option value="CRITICAL">CRITICAL</option>
                        </select>
                        <input type="text" id="telStageInput" class="filter-input" placeholder="Mərhələ (Stage) axtar..." oninput="debouncedLoadTelemetry()">
                    </div>

                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>Vaxt</th>
                                    <th>Cihaz</th>
                                    <th>Komponent</th>
                                    <th>Mərhələ / Əlaqə ID</th>
                                    <th>Hadisə</th>
                                    <th>Müddət</th>
                                    <th>Dərəcə</th>
                                    <th>Xəta / İzah</th>
                                </tr>
                            </thead>
                            <tbody id="telemetryTableBody">
                                <tr><td colspan="8" style="color:var(--text-muted); text-align:center;">Yüklənir...</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <div class="pagination-bar" id="telemetryPagination">
                        <div id="telemetryCountInfo">0 hadisədən 0 göstərilir</div>
                        <div class="pagination-controls">
                            <button class="btn btn-secondary btn-sm" id="btnTelPrev" onclick="changeTelPage(-1)">← Əvvəlki</button>
                            <span id="telPageIndicator">Səhifə 1 / 1</span>
                            <button class="btn btn-secondary btn-sm" id="btnTelNext" onclick="changeTelPage(1)">Növbəti →</button>
                        </div>
                    </div>
                </div>
            </div>

        </div>

    </main>

    <!-- ==================== CİHAZ DETAL MODALI ==================== -->
    <div id="deviceDetailModal" class="modal-overlay" hidden>
        <div class="modal-box">
            <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--panel-border); padding-bottom:12px;">
                <h3 style="font-size:1.15rem; font-weight:700;" id="modalDevTitle">Cihaz Detalları</h3>
                <button class="btn btn-secondary btn-sm" onclick="closeDeviceDetail()">✕ Bağla</button>
            </div>
            
            <!-- Metadata Grid -->
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:12px;" id="modalMetaGrid">
                <!-- Javascript tərəfindən doldurulur -->
            </div>

            <!-- Son Əmrlər Cədvəli -->
            <div>
                <h4 style="font-size:0.95rem; font-weight:600; margin-bottom:8px;">Son İcra Olunmuş Əmrlər</h4>
                <div class="table-responsive">
                    <table style="font-size:0.8rem;">
                        <thead>
                            <tr>
                                <th>Əmr ID</th>
                                <th>Əməliyyat</th>
                                <th>Status</th>
                                <th>Nəticə</th>
                                <th>Tarix</th>
                                <th>Timeline</th>
                            </tr>
                        </thead>
                        <tbody id="modalCommandsBody">
                            <tr><td colspan="6" style="color:var(--text-muted);">Əmr yoxdur.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Əmr Gecikməsi Timeline Bölməsi (Timeline Section) -->
            <div id="modalTimelineBox" style="display:none; background:var(--panel-sub); padding:16px; border-radius:var(--radius-sm); border:1px solid var(--panel-border);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <h4 style="font-size:0.9rem; font-weight:600; color:var(--accent);">Əmr İcra Mərhələləri (Latency Breakdown)</h4>
                    <button class="btn btn-secondary btn-sm" style="padding:2px 8px; font-size:0.75rem;" onclick="document.getElementById('modalTimelineBox').style.display='none'">Gizlət</button>
                </div>
                <div class="timeline" id="modalTimelineSteps">
                    <!-- Dinamik addımlar -->
                </div>
            </div>

            <!-- Cihazın Son Telemetriyası -->
            <div>
                <h4 style="font-size:0.95rem; font-weight:600; margin-bottom:8px;">Cihaza Aid Son Telemetriya</h4>
                <div class="table-responsive">
                    <table style="font-size:0.8rem;">
                        <thead>
                            <tr>
                                <th>Vaxt</th>
                                <th>Komponent</th>
                                <th>Mərhələ</th>
                                <th>Müddət</th>
                                <th>Dərəcə</th>
                                <th>Xəta</th>
                            </tr>
                        </thead>
                        <tbody id="modalTelemetryBody">
                            <tr><td colspan="6" style="color:var(--text-muted);">Telemetriya qeydi yoxdur.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- ==================== JAVASCRIPT MƏNTİQİ ==================== -->
    <script>
        // State
        let adminSecret = sessionStorage.getItem('winkey_admin_secret') || '';
        let currentTab = 'overview';
        let wsSocket = null;
        let wsReconnectTimer = null;
        let debTimerDev = null;
        let debTimerTel = null;

        let devPage = 1;
        let devTotalPages = 1;
        let telPage = 1;
        let telTotalPages = 1;

        // URL hash-dən dev-admin dəstəyi
        const localAccess = typeof location !== 'undefined' ? new URLSearchParams(location.hash.slice(1)).get('dev-admin') : null;
        if (localAccess) {
            sessionStorage.setItem('winkey_admin_secret', localAccess);
            adminSecret = localAccess;
            history.replaceState(null, '', location.pathname);
        }

        function escapeHtml(value) {
            return String(value ?? '').replace(/[&<>"']/g, ch => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            }[ch]));
        }

        function loginAdmin() {
            const val = document.getElementById('inputAdminSecret').value.trim();
            if (!val) return;
            adminSecret = val;
            sessionStorage.setItem('winkey_admin_secret', adminSecret);
            initDashboard();
        }

        function logoutAdmin() {
            sessionStorage.removeItem('winkey_admin_secret');
            adminSecret = '';
            if (wsSocket) {
                try { wsSocket.close(); } catch(e) {}
            }
            document.getElementById('dashboardContainer').style.display = 'none';
            document.getElementById('nav-right-box').style.display = 'none';
            document.getElementById('authBox').style.display = 'flex';
        }

        async function initDashboard() {
            document.getElementById('authErrMsg').textContent = '';
            // Test admin auth with overview
            try {
                const res = await fetch('/admin/overview', {
                    headers: { 'X-Owner-Admin-Secret': adminSecret }
                });
                if (res.status === 403 || res.status === 401) {
                    document.getElementById('authErrMsg').textContent = 'XƏTA: Admin Secret yanlışdır və ya icazəniz yoxdur.';
                    return;
                }
                const data = await res.json();
                document.getElementById('authBox').style.display = 'none';
                document.getElementById('nav-right-box').style.display = 'flex';
                document.getElementById('dashboardContainer').style.display = 'flex';
                
                renderOverview(data);
                connectWebSocket();
                switchTab('overview');
            } catch(e) {
                document.getElementById('authErrMsg').textContent = 'Şəbəkə xətası: ' + e.message;
            }
        }

        function switchTab(tabId) {
            currentTab = tabId;
            ['overview', 'devices', 'updates', 'telemetry'].forEach(t => {
                const p = document.getElementById('tabPanel-' + t);
                const b = document.getElementById('tabBtn-' + t);
                if (p) p.style.display = (t === tabId) ? 'flex' : 'none';
                if (b) b.classList.toggle('active', t === tabId);
            });
            if (tabId === 'overview') loadOverview();
            else if (tabId === 'devices') loadDevices(devPage);
            else if (tabId === 'updates') loadUpdates();
            else if (tabId === 'telemetry') loadTelemetry(telPage);
        }

        function refreshCurrentTab() {
            switchTab(currentTab);
        }

        // ================== WEBSOCKET ƏLAQƏSİ ==================
        function connectWebSocket() {
            if (!adminSecret) return;
            if (wsSocket && wsSocket.readyState <= 1) return;

            const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${proto}//${location.host}/ws`;

            try {
                wsSocket = new WebSocket(wsUrl);
                wsSocket.onopen = () => {
                    updateWsStatus(true);
                    wsSocket.send(JSON.stringify({
                        action: 'auth',
                        role: 'admin',
                        admin_secret: adminSecret
                    }));
                };
                wsSocket.onmessage = (event) => {
                    try {
                        const msg = JSON.parse(event.data);
                        // Cihaz və ya release yeniləndikdə cari tabı səssiz yeniləyirik
                        if (msg.event === 'device_status_update' || msg.event === 'release_published') {
                            refreshCurrentTab();
                        }
                    } catch(e) {}
                };
                wsSocket.onclose = () => {
                    updateWsStatus(false);
                    clearTimeout(wsReconnectTimer);
                    wsReconnectTimer = setTimeout(connectWebSocket, 5000);
                };
                wsSocket.onerror = () => {
                    updateWsStatus(false);
                };
            } catch(e) {
                updateWsStatus(false);
            }
        }

        function updateWsStatus(online) {
            const badge = document.getElementById('wsStatusBadge');
            const txt = document.getElementById('wsStatusText');
            if (online) {
                badge.className = 'ws-badge ws-online';
                txt.textContent = 'Canlı (WS)';
            } else {
                badge.className = 'ws-badge ws-offline';
                txt.textContent = 'Oflayn (HTTP Fallback)';
            }
        }

        // ================== 1. ÜMUMİ BAXIŞ ==================
        async function loadOverview() {
            try {
                const res = await fetch('/admin/overview', {
                    headers: { 'X-Owner-Admin-Secret': adminSecret }
                });
                if (res.status === 200) {
                    const data = await res.json();
                    renderOverview(data);
                }
            } catch(e) {}
        }

        function renderOverview(data) {
            document.getElementById('ovTotalDevices').textContent = data.total_devices ?? '0';
            document.getElementById('ovActiveRevoked').textContent = `Aktiv: ${data.active_devices ?? 0} | Ləğv: ${data.revoked_devices ?? 0}`;
            document.getElementById('ovOnlineDevices').textContent = data.online_devices ?? '0';
            document.getElementById('ovOfflineDevices').textContent = `Oflayn: ${data.offline_devices ?? 0}`;
            document.getElementById('ovError24h').textContent = data.error_count_24h ?? '0';
            
            const rel = data.current_release;
            if (rel && rel.version) {
                document.getElementById('ovReleaseVer').textContent = 'v' + rel.version;
                document.getElementById('ovReleaseId').textContent = 'ID: ' + rel.release_id.substring(0, 16) + '...';
                document.getElementById('repoStatusText').textContent = `Aktiv v${rel.version} (İmzalanmış)`;
            } else {
                document.getElementById('ovReleaseVer').textContent = 'Yoxdur';
                document.getElementById('ovReleaseId').textContent = 'Paket yayımlanmayıb';
                document.getElementById('repoStatusText').textContent = 'Paket tapılmadı';
            }

            const us = data.update_summary || {};
            document.getElementById('ovOtaCommitted').textContent = us.committed ?? '0';
            document.getElementById('ovOtaRollback').textContent = `Rollback: ${us.rollback ?? 0} | Xəta: ${us.error ?? 0}`;
            document.getElementById('ovTotalTelemetry').textContent = data.total_telemetry_events ?? '0';
        }

        // ================== 2. CİHAZLAR ==================
        function debouncedLoadDevices() {
            clearTimeout(debTimerDev);
            debTimerDev = setTimeout(() => loadDevices(1), 300);
        }

        async function loadDevices(page = 1) {
            devPage = page;
            const q = document.getElementById('devSearchInput').value.trim();
            const status = document.getElementById('devStatusFilter').value;
            const online = document.getElementById('devOnlineFilter').value;
            const sort = document.getElementById('devSortFilter').value;

            const url = new URL('/admin/devices', location.origin);
            if (q) url.searchParams.set('q', q);
            if (status) url.searchParams.set('status', status);
            if (online) url.searchParams.set('online', online);
            if (sort) url.searchParams.set('sort', sort);
            url.searchParams.set('page', page);
            url.searchParams.set('page_size', 15);

            try {
                const res = await fetch(url, { headers: { 'X-Owner-Admin-Secret': adminSecret } });
                if (res.status === 200) {
                    const data = await res.json();
                    renderDevices(data);
                }
            } catch(e) {}
        }

        function renderDevices(data) {
            const list = data.devices || [];
            devTotalPages = data.total_pages || 1;
            const tbody = document.getElementById('devicesTableBody');

            if (list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="10" style="color:var(--text-muted); text-align:center;">Cihaz tapılmadı.</td></tr>';
                document.getElementById('devicesCountInfo').textContent = 'Cəmi 0 cihaz';
                return;
            }

            let html = '';
            for (const d of list) {
                const stClass = d.status === 'ACTIVE' ? 'pill-active' : 'pill-revoked';
                const onClass = d.is_online ? 'pill-online' : 'pill-offline';
                const onText = d.is_online ? '🟢 Online' : '⚪ Offline';
                const pinText = d.pin_status === 'ready' ? '✅ Hazır' : (d.pin_status === 'not_ready' ? '⏳ Yoxdur' : '—');
                const lastSeen = d.last_seen_at ? new Date(d.last_seen_at * 1000).toLocaleString() : '—';

                html += `<tr>
                    <td><code>${escapeHtml(d.device_id.substring(0, 14))}...</code></td>
                    <td><strong>${escapeHtml(d.computer_name)}</strong></td>
                    <td><span class="pill ${onClass}">${onText}</span></td>
                    <td><span class="pill ${stClass}">${escapeHtml(d.status)}</span></td>
                    <td>${d.worker_version ? 'v' + escapeHtml(d.worker_version) : '<span style="color:var(--text-faint);">Bildirilməyib</span>'}</td>
                    <td>${d.latest_version ? 'v' + escapeHtml(d.latest_version) : '<span style="color:var(--text-faint);">Paket yoxdur</span>'}</td>
                    <td>${d.locked ? '🔒 Bəli' : '🔓 Xeyr'}</td>
                    <td>${pinText}</td>
                    <td><span style="font-size:0.75rem; color:var(--text-muted);">${lastSeen}</span></td>
                    <td>
                        <div style="display:flex; gap:6px;">
                            <button class="btn btn-secondary btn-sm" onclick="openDeviceDetail('${escapeHtml(d.device_id)}')">Detallar</button>
                            <button class="btn btn-danger btn-sm" onclick="toggleDeviceStatus('${escapeHtml(d.device_id)}', '${d.status === 'ACTIVE' ? 'revoke' : 'activate'}')">${d.status === 'ACTIVE' ? 'Ləğv' : 'Aktiv'}</button>
                            <button class="btn btn-danger btn-sm" style="background:#451212;" onclick="deleteDevice('${escapeHtml(d.device_id)}')">Sil</button>
                        </div>
                    </td>
                </tr>`;
            }
            tbody.innerHTML = html;

            document.getElementById('devicesCountInfo').textContent = `Cəmi ${data.total} cihazdan ${list.length} göstərilir`;
            document.getElementById('devPageIndicator').textContent = `Səhifə ${data.page} / ${data.total_pages}`;
            document.getElementById('btnDevPrev').disabled = (data.page <= 1);
            document.getElementById('btnDevNext').disabled = (data.page >= data.total_pages);
        }

        function changeDevPage(delta) {
            const next = devPage + delta;
            if (next >= 1 && next <= devTotalPages) {
                loadDevices(next);
            }
        }

        async function toggleDeviceStatus(devId, action) {
            const promptMsg = action === 'activate' ? 'Cihazı yenidən aktivləşdirmək istəyirsiniz?' : 'Cihazı ləğv etmək istəyirsiniz? Bütün mobil sessiyalar kəsiləcək.';
            if (!confirm(promptMsg)) return;
            try {
                await fetch(action === 'activate' ? '/admin/activate' : '/admin/revoke', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Owner-Admin-Secret': adminSecret },
                    body: JSON.stringify({ device_id: devId })
                });
                loadDevices(devPage);
            } catch(e) { alert('Xəta: ' + e); }
        }

        async function deleteDevice(devId) {
            if (!confirm('DİQQƏT: Cihaz tamamilə silinəcək və yeni kimi qeydiyyatdan keçməli olacaq. Əminsiniz?')) return;
            try {
                await fetch('/admin/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Owner-Admin-Secret': adminSecret },
                    body: JSON.stringify({ device_id: devId })
                });
                loadDevices(devPage);
            } catch(e) { alert('Silinmə xətası: ' + e); }
        }

        // ================== CİHAZ DETALLARI VƏ TİMELİNE MODALI ==================
        async function openDeviceDetail(devId) {
            const modal = document.getElementById('deviceDetailModal');
            modal.hidden = false;
            document.getElementById('modalDevTitle').textContent = 'Cihaz Detalları: ' + devId;
            document.getElementById('modalMetaGrid').innerHTML = '<div>Məlumatlar yüklənir...</div>';
            document.getElementById('modalTimelineBox').style.display = 'none';

            try {
                const res = await fetch(`/admin/devices/${encodeURIComponent(devId)}`, {
                    headers: { 'X-Owner-Admin-Secret': adminSecret }
                });
                if (res.status === 200) {
                    const data = await res.json();
                    renderModalDevice(data.device);
                } else {
                    document.getElementById('modalMetaGrid').innerHTML = '<div class="err-msg">Cihaz tapılmadı.</div>';
                }
            } catch(e) {
                document.getElementById('modalMetaGrid').innerHTML = '<div class="err-msg">Şəbəkə xətası: ' + e + '</div>';
            }
        }

        function closeDeviceDetail() {
            document.getElementById('deviceDetailModal').hidden = true;
        }

        function renderModalDevice(dev) {
            const pm = dev.pairing_metadata || {};
            const grid = document.getElementById('modalMetaGrid');
            grid.innerHTML = `
                <div style="background:var(--panel-sub); padding:10px; border-radius:6px; border:1px solid var(--panel-border);">
                    <div style="font-size:0.75rem; color:var(--text-muted);">KOMPÜTER ADI</div>
                    <div style="font-weight:700;">${escapeHtml(dev.computer_name)}</div>
                </div>
                <div style="background:var(--panel-sub); padding:10px; border-radius:6px; border:1px solid var(--panel-border);">
                    <div style="font-size:0.75rem; color:var(--text-muted);">STATUS / ƏLAQƏ</div>
                    <div><span class="pill ${dev.status === 'ACTIVE' ? 'pill-active' : 'pill-revoked'}">${escapeHtml(dev.status)}</span> 
                         <span class="pill ${dev.is_online ? 'pill-online' : 'pill-offline'}">${dev.is_online ? 'Online' : 'Offline'}</span></div>
                </div>
                <div style="background:var(--panel-sub); padding:10px; border-radius:6px; border:1px solid var(--panel-border);">
                    <div style="font-size:0.75rem; color:var(--text-muted);">WORKER / SERVER VERSİYA</div>
                    <div>${dev.worker_version ? 'v' + escapeHtml(dev.worker_version) : '—'} / ${dev.latest_version ? 'v' + escapeHtml(dev.latest_version) : '—'}</div>
                </div>
                <div style="background:var(--panel-sub); padding:10px; border-radius:6px; border:1px solid var(--panel-border);">
                    <div style="font-size:0.75rem; color:var(--text-muted);">AKTİV TELEFON SESSİYALARI</div>
                    <div>${pm.active_mobile_sessions ?? 0} ədəd</div>
                </div>
            `;

            // Commands
            const cbody = document.getElementById('modalCommandsBody');
            const cmds = dev.recent_commands || [];
            if (cmds.length === 0) {
                cbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted);">Əmr qeydə alınmayıb.</td></tr>';
            } else {
                let html = '';
                for (const c of cmds) {
                    html += `<tr>
                        <td><code>${escapeHtml(c.command_id.substring(0, 10))}...</code></td>
                        <td><strong>${escapeHtml(c.action)}</strong></td>
                        <td>${escapeHtml(c.status)}</td>
                        <td>${escapeHtml(c.result_status || '—')}</td>
                        <td>${c.created_at ? new Date(c.created_at * 1000).toLocaleTimeString() : '—'}</td>
                        <td><button class="btn btn-secondary btn-sm" onclick="loadCommandTimeline('${escapeHtml(c.command_id)}')">Timeline</button></td>
                    </tr>`;
                }
                cbody.innerHTML = html;
            }

            // Telemetry
            const tbody = document.getElementById('modalTelemetryBody');
            const tels = dev.recent_telemetry || [];
            if (tels.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted);">Telemetriya qeydi yoxdur.</td></tr>';
            } else {
                let html = '';
                for (const t of tels) {
                    html += `<tr>
                        <td>${t.received_at ? new Date(t.received_at * 1000).toLocaleTimeString() : '—'}</td>
                        <td>${escapeHtml(t.component)}</td>
                        <td>${escapeHtml(t.stage)}</td>
                        <td>${t.duration_ms != null ? t.duration_ms + ' ms' : '—'}</td>
                        <td><span class="pill ${t.severity === 'ERROR' ? 'pill-revoked' : 'pill-info'}">${escapeHtml(t.severity)}</span></td>
                        <td>${escapeHtml(t.error_code || '—')}</td>
                    </tr>`;
                }
                tbody.innerHTML = html;
            }
        }

        async function loadCommandTimeline(corrId) {
            const box = document.getElementById('modalTimelineBox');
            const stepsCont = document.getElementById('modalTimelineSteps');
            box.style.display = 'block';
            stepsCont.innerHTML = '<div>Mərhələlər yüklənir...</div>';

            try {
                const res = await fetch(`/admin/telemetry/timeline/${encodeURIComponent(corrId)}`, {
                    headers: { 'X-Owner-Admin-Secret': adminSecret }
                });
                if (res.status === 200) {
                    const data = await res.json();
                    const steps = data.steps || [];
                    if (steps.length === 0) {
                        stepsCont.innerHTML = `<div style="color:var(--text-muted);">Bu ID (${escapeHtml(corrId)}) üzrə mərhələ qeydi tapılmadı.</div>`;
                        return;
                    }
                    let html = '';
                    for (const s of steps) {
                        const tStr = s.received_at ? new Date(s.received_at * 1000).toLocaleTimeString() : '';
                        const dur = s.duration_ms != null ? `(${s.duration_ms} ms)` : '';
                        html += `
                            <div class="timeline-item">
                                <div class="timeline-dot"></div>
                                <div class="timeline-title">${escapeHtml(s.stage || s.event_type)} ${dur}</div>
                                <div class="timeline-meta">
                                    <span>Vaxt: ${tStr}</span>
                                    <span>Komponent: ${escapeHtml(s.component)}</span>
                                    <span>Nəticə/Xəta: ${escapeHtml(s.error_code || 'Uğurlu')}</span>
                                </div>
                            </div>
                        `;
                    }
                    stepsCont.innerHTML = html;
                }
            } catch(e) {
                stepsCont.innerHTML = '<div class="err-msg">Timeline xətası: ' + e + '</div>';
            }
        }

        // ================== 3. OTA YENİLƏNMƏLƏR VƏ PAKET YAYIMI ==================
        async function loadUpdates() {
            try {
                const res = await fetch('/admin/overview', { headers: { 'X-Owner-Admin-Secret': adminSecret } });
                if (res.status === 200) {
                    const data = await res.json();
                    renderOverview(data);
                }
                const resTel = await fetch('/admin/telemetry?stage=UPDATE_&page_size=20', {
                    headers: { 'X-Owner-Admin-Secret': adminSecret }
                });
                if (resTel.status === 200) {
                    const telData = await resTel.json();
                    renderUpdateStages(telData.telemetry || []);
                }
            } catch(e) {}
        }

        function renderUpdateStages(list) {
            const tbody = document.getElementById('updateStagesTableBody');
            if (list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted); text-align:center;">OTA hadisəsi qeydə alınmayıb.</td></tr>';
                return;
            }
            let html = '';
            for (const item of list) {
                const isCommitted = item.stage.includes('COMMIT');
                const isErr = item.stage.includes('ERROR') || item.stage.includes('ROLLBACK');
                const badgeClass = isCommitted ? 'pill-active' : (isErr ? 'pill-revoked' : 'pill-info');
                const tStr = item.received_at ? new Date(item.received_at * 1000).toLocaleString() : '—';
                html += `<tr>
                    <td><code>${escapeHtml(item.device_id || '—')}</code></td>
                    <td><span class="pill ${badgeClass}">${escapeHtml(item.stage)}</span></td>
                    <td>v${escapeHtml(item.version || '—')}</td>
                    <td>${item.duration_ms != null ? item.duration_ms + ' ms' : '—'}</td>
                    <td>${escapeHtml(item.error_code || '—')}</td>
                    <td><span style="font-size:0.75rem; color:var(--text-muted);">${tStr}</span></td>
                </tr>`;
            }
            tbody.innerHTML = html;
        }

        async function uploadPackage() {
            const fileInput = document.getElementById('packageFileInput');
            if (!fileInput.files || fileInput.files.length === 0) {
                alert('Zəhmət olmasa imzalanmış WinKeyUpdate-*.zip faylını seçin.');
                return;
            }
            const file = fileInput.files[0];
            const pWrap = document.getElementById('uploadProgressWrap');
            const pFill = document.getElementById('uploadBarFill');
            const pLabel = document.getElementById('uploadPercentLabel');
            const resMsg = document.getElementById('uploadResultMsg');

            pWrap.style.display = 'flex';
            pFill.style.width = '0%';
            pLabel.textContent = '0%';
            resMsg.textContent = '';

            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/admin/updates/publish');
            xhr.setRequestHeader('Authorization', 'Bearer ' + adminSecret);
            xhr.setRequestHeader('X-Owner-Admin-Secret', adminSecret);
            xhr.setRequestHeader('Content-Type', 'application/zip');

            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    pFill.style.width = percent + '%';
                    pLabel.textContent = percent + '%';
                }
            };

            xhr.onload = () => {
                if (xhr.status === 200) {
                    try {
                        const resp = JSON.parse(xhr.responseText);
                        resMsg.style.color = 'var(--green)';
                        resMsg.textContent = `✅ UĞURLU: Paket qəbul edildi və yayımlandı! Versiya: v${resp.version}`;
                        fileInput.value = '';
                        loadUpdates();
                    } catch(e) {
                        resMsg.textContent = 'Yayım təsdiqləndi.';
                    }
                } else {
                    resMsg.style.color = 'var(--red)';
                    resMsg.textContent = `❌ Xəta (${xhr.status}): Paket imzası və ya formatı rədd edildi.`;
                }
            };

            xhr.onerror = () => {
                resMsg.style.color = 'var(--red)';
                resMsg.textContent = 'Şəbəkə xətası baş verdi.';
            };

            xhr.send(file);
        }

        // ================== 4. TELEMETRİYA ==================
        function debouncedLoadTelemetry() {
            clearTimeout(debTimerTel);
            debTimerTel = setTimeout(() => loadTelemetry(1), 300);
        }

        async function loadTelemetry(page = 1) {
            telPage = page;
            const devId = document.getElementById('telDevInput').value.trim();
            const comp = document.getElementById('telCompFilter').value;
            const sev = document.getElementById('telSevFilter').value;
            const stage = document.getElementById('telStageInput').value.trim();

            const url = new URL('/admin/telemetry', location.origin);
            if (devId) url.searchParams.set('device_id', devId);
            if (comp) url.searchParams.set('component', comp);
            if (sev) url.searchParams.set('severity', sev);
            if (stage) url.searchParams.set('stage', stage);
            url.searchParams.set('page', page);
            url.searchParams.set('page_size', 25);

            try {
                const res = await fetch(url, { headers: { 'X-Owner-Admin-Secret': adminSecret } });
                if (res.status === 200) {
                    const data = await res.json();
                    renderTelemetry(data);
                }
            } catch(e) {}
        }

        function renderTelemetry(data) {
            const list = data.telemetry || [];
            telTotalPages = data.total_pages || 1;
            const tbody = document.getElementById('telemetryTableBody');

            if (list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="color:var(--text-muted); text-align:center;">Hadisə qeydə alınmayıb.</td></tr>';
                document.getElementById('telemetryCountInfo').textContent = 'Cəmi 0 hadisə';
                return;
            }

            let html = '';
            for (const ev of list) {
                const tStr = ev.received_at ? new Date(ev.received_at * 1000).toLocaleTimeString() : '—';
                const sevClass = ev.severity === 'ERROR' || ev.severity === 'CRITICAL' ? 'pill-revoked' : (ev.severity === 'WARN' ? 'pill-warn' : 'pill-info');
                html += `<tr>
                    <td><span style="font-size:0.75rem; color:var(--text-muted);">${tStr}</span></td>
                    <td><code>${escapeHtml(ev.device_id ? ev.device_id.substring(0, 10) + '...' : '—')}</code></td>
                    <td><span class="pill pill-info">${escapeHtml(ev.component)}</span></td>
                    <td><strong>${escapeHtml(ev.stage || '—')}</strong></td>
                    <td>${escapeHtml(ev.event_type)}</td>
                    <td>${ev.duration_ms != null ? ev.duration_ms + ' ms' : '—'}</td>
                    <td><span class="pill ${sevClass}">${escapeHtml(ev.severity)}</span></td>
                    <td>${escapeHtml(ev.error_code || '—')}</td>
                </tr>`;
            }
            tbody.innerHTML = html;

            document.getElementById('telemetryCountInfo').textContent = `Cəmi ${data.total} hadisədən ${list.length} göstərilir`;
            document.getElementById('telPageIndicator').textContent = `Səhifə ${data.page} / ${data.total_pages}`;
            document.getElementById('btnTelPrev').disabled = (data.page <= 1);
            document.getElementById('btnTelNext').disabled = (data.page >= data.total_pages);
        }

        function changeTelPage(delta) {
            const next = telPage + delta;
            if (next >= 1 && next <= telTotalPages) {
                loadTelemetry(next);
            }
        }

        function exportTelemetry(fmt) {
            const devId = document.getElementById('telDevInput').value.trim();
            const sev = document.getElementById('telSevFilter').value;
            const url = new URL('/admin/export/telemetry', location.origin);
            url.searchParams.set('format', fmt);
            if (devId) url.searchParams.set('device_id', devId);
            if (sev) url.searchParams.set('severity', sev);
            url.searchParams.set('limit', 1000);

            // Fetch with admin secret and trigger download
            fetch(url, { headers: { 'X-Owner-Admin-Secret': adminSecret } })
                .then(r => r.blob())
                .then(blob => {
                    const blobUrl = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = blobUrl;
                    a.download = `winkey_telemetry_${Date.now()}.${fmt}`;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                })
                .catch(e => alert('İxrac xətası: ' + e));
        }

        // Başlanğıc yoxlaması
        if (adminSecret) {
            initDashboard();
        }
    </script>
</body>
</html>
"""


class GatewayHandler(BaseHTTPRequestHandler):
    @classmethod
    def _verify_device_token(cls, conn, device_id, token):
        if not token or not device_id:
            return False
        import hashlib, time
        sess = conn.execute(
            "SELECT device_id FROM mobile_sessions WHERE session_token = ? AND (expires_at = 0 OR expires_at > ?)",
            (token, time.time())
        ).fetchone()
        if sess and sess["device_id"] == device_id:
            return True
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        acct = conn.execute(
            "SELECT account_id FROM account_sessions WHERE token_hash = ? AND expires_at > ?",
            (token_hash, time.time())
        ).fetchone()
        if acct:
            owner = conn.execute(
                "SELECT 1 FROM account_devices WHERE account_id = ? AND device_id = ?",
                (acct['account_id'], device_id)
            ).fetchone()
            if owner:
                return True
        return False

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
        if path == '/mobile-sw.js':
            from pathlib import Path
            content=(Path(__file__).parent/'static'/'mobile-sw.js').read_bytes()
            self.send_response(200)
            self._set_security_headers('application/javascript')
            self.send_header('Service-Worker-Allowed','/')
            self.send_header('Content-Length',str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        if path.startswith('/mobile-assets/'):
            from pathlib import Path
            from deploy.mobile_install import manifest
            asset = path.rsplit('/', 1)[1]
            if asset == 'manifest.webmanifest':
                ticket = parse_qs(url.query).get('install', [''])[0]
                payload = json.dumps(manifest(ticket)).encode('utf-8')
                self.send_response(200)
                self._set_security_headers('application/manifest+json; charset=utf-8')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if asset in ('devices.js','install.js','jsQR.js','icon.png','icon-192.png','icon-512.png','apple-touch-icon.png'):
                content = (Path(__file__).parent / 'static' / asset).read_bytes()
                self.send_response(200)
                self._set_security_headers('image/png' if asset.endswith('.png') else 'application/javascript')
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

        # 2a. Owner-Only Admin Overview
        if path == "/admin/overview":
            admin_sec = self.headers.get("X-Owner-Admin-Secret")
            service = GatewayService(self.db, get_admin_secret)
            status, data = service.admin_get_overview(admin_sec)
            self._send_json(status, data)
            return

        # 2b. Owner-Only Admin Devices (Pagination & Search)
        if path == "/admin/devices":
            admin_sec = self.headers.get("X-Owner-Admin-Secret")
            service = GatewayService(self.db, get_admin_secret)
            qs = parse_qs(url.query)
            q = qs.get("q", [None])[0]
            dev_status = qs.get("status", [None])[0]
            online = qs.get("online", [None])[0]
            version = qs.get("version", [None])[0]
            page = int(qs.get("page", ["1"])[0])
            page_size = int(qs.get("page_size", ["15"])[0])
            sort = qs.get("sort", ["created_desc"])[0]
            status, data = service.admin_get_devices(admin_sec, q, dev_status, online, version, page, page_size, sort)
            self._send_json(status, data)
            return

        # 2c. Owner-Only Admin Device Detail
        if path.startswith("/admin/devices/"):
            device_id = path[len("/admin/devices/"):]
            admin_sec = self.headers.get("X-Owner-Admin-Secret")
            service = GatewayService(self.db, get_admin_secret)
            status, data = service.admin_get_device_detail(device_id, admin_sec)
            self._send_json(status, data)
            return

        # 3a. Owner-Only Admin Telemetry (Pagination & Filters)
        if path == "/admin/telemetry":
            admin_sec = self.headers.get("X-Owner-Admin-Secret")
            service = GatewayService(self.db, get_admin_secret)
            qs = parse_qs(url.query)
            device_id = qs.get("device_id", [None])[0]
            component = qs.get("component", [None])[0]
            severity = qs.get("severity", [None])[0]
            stage = qs.get("stage", [None])[0]
            error_code = qs.get("error_code", [None])[0]
            page = int(qs.get("page", ["1"])[0])
            page_size = int(qs.get("page_size", ["30"])[0])
            from_ts = float(qs.get("from_ts", ["0"])[0]) if qs.get("from_ts") else None
            to_ts = float(qs.get("to_ts", ["0"])[0]) if qs.get("to_ts") else None
            status, data = service.admin_get_telemetry(admin_sec, device_id, component, severity, stage, error_code, page, page_size, from_ts, to_ts)
            self._send_json(status, data)
            return

        # 3b. Owner-Only Admin Timeline
        if path.startswith("/admin/telemetry/timeline/"):
            corr_id = path[len("/admin/telemetry/timeline/"):]
            admin_sec = self.headers.get("X-Owner-Admin-Secret")
            service = GatewayService(self.db, get_admin_secret)
            status, data = service.admin_get_timeline(corr_id, admin_sec)
            self._send_json(status, data)
            return

        # 3c. Owner-Only Admin Telemetry Export
        if path == "/admin/export/telemetry":
            admin_sec = self.headers.get("X-Owner-Admin-Secret")
            service = GatewayService(self.db, get_admin_secret)
            qs = parse_qs(url.query)
            fmt = qs.get("format", ["json"])[0]
            device_id = qs.get("device_id", [None])[0]
            severity = qs.get("severity", [None])[0]
            limit = int(qs.get("limit", ["500"])[0])
            status, data, media_type = service.admin_export_telemetry(admin_sec, fmt, device_id, severity, limit)
            if status != 200:
                self._send_json(status, data)
                return
            if fmt.lower() == "csv":
                self.send_response(200)
                self.send_header("Content-Type", media_type)
                self.send_header("Content-Disposition", 'attachment; filename="winkey_telemetry.csv"')
                self.end_headers()
                self.wfile.write(data.encode("utf-8"))
                return
            self._send_json(200, data)
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
                if not self._verify_device_token(conn, req_device_id, token):
                    self._send_json(403, {"error": "E_TENANT_IDOR_FORBIDDEN", "message": "Bu cihazın statusuna baxmaq icazəniz yoxdur"})
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
                    cmd = conn.execute("SELECT command_id, device_id, action, status, result_status AS result, created_at, completed_at AS executed_at FROM commands WHERE command_id = ?", (cmd_id,)).fetchone()
                    if not cmd:
                        self._send_json(404, {"error": "E_COMMAND_NOT_FOUND"})
                        return

                    # Multi-Tenant guard (mobile session or account session)
                    if not self._verify_device_token(conn, cmd["device_id"], token):
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

        if path.startswith('/accounts/') or path in ('/pair', '/mobile/install', '/mobile/restore', '/mobile/pair', '/mobile/devices'):
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
                if not self._verify_device_token(conn, req_device_id, token):
                    self._send_json(403, {"error": "E_TENANT_IDOR_FORBIDDEN", "message": "Bu cihaza komanda göndərmək icazəniz yoxdur və ya sessiya bitib."})
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
        # 8.9. Owner-Only Admin Update Publish (/admin/updates/publish)
        if path == "/admin/updates/publish":
            admin_sec = self.headers.get("X-Owner-Admin-Secret") or self._get_bearer_token()
            if not admin_sec or admin_sec != get_admin_secret():
                self._send_json(403, {"error": "E_ADMIN_UNAUTHORIZED", "message": "Yalnız sahib admin icazəlidir"})
                return
            try:
                from deploy.update_repository import UpdateRepository
                repo = UpdateRepository()
                # Read raw package binary
                length = int(self.headers.get('Content-Length', '0'))
                raw_bytes = self.rfile.read(length) if length > 0 else b''
                release = repo.publish(raw_bytes)
                self._send_json(200, {"published": True, "version": release["version"], "release_id": release["release_id"]})
            except Exception as e:
                self._send_json(400, {"error": "E_SIGNED_RELEASE_REJECTED", "detail": str(e)})
            return

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
