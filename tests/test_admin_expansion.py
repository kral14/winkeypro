import unittest
import time
import os
import io
import json
import secrets
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deploy.gateway_production_server import ProductionDatabase as Database
from deploy.gateway_service import GatewayService

class TestAdminExpansion(unittest.TestCase):
    def setUp(self):
        # Təcrid olunmuş müvəqqəti in-memory SQLite bazası
        self.db_path = f"tmp_test_admin_{secrets.token_hex(6)}.db"
        self.db = Database(self.db_path)
        self.admin_sec = "test_owner_secret_12345"
        self.service = GatewayService(self.db, lambda: self.admin_sec)

        # Sintetik test məlumatları əlavə edirik
        with self.db.get_conn() as conn:
            # 1. Cihazlar: 1 online (fresh), 1 offline (köhnə last_seen), 1 revoked
            now = time.time()
            conn.execute("""
                INSERT INTO devices (device_id, computer_name, public_key_hex, device_secret_hash, status, created_at, last_seen_at, locked, pin_ready)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("dev_online_001", "Desktop-Alpha", "pub01", "hash01", "ACTIVE", now - 3600, now - 10, 0, 1))

            conn.execute("""
                INSERT INTO devices (device_id, computer_name, public_key_hex, device_secret_hash, status, created_at, last_seen_at, locked, pin_ready)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("dev_offline_002", "Laptop-Beta", "pub02", "hash02", "ACTIVE", now - 7200, now - 500, 1, 0))

            conn.execute("""
                INSERT INTO devices (device_id, computer_name, public_key_hex, device_secret_hash, status, created_at, last_seen_at, locked, pin_ready)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("dev_revoked_003", "Old-Workstation", "pub03", "hash03", "REVOKED", now - 86400, now - 70000, 0, 0))

            # Versiyalar
            conn.execute("INSERT INTO device_versions (device_id, worker_version, reported_at) VALUES (?, ?, ?)",
                         ("dev_online_001", "0.2.9", now - 10))
            conn.execute("INSERT INTO device_versions (device_id, worker_version, reported_at) VALUES (?, ?, ?)",
                         ("dev_offline_002", "0.1.15", now - 500))

            # Əmrlər
            conn.execute("""
                INSERT INTO commands (command_id, device_id, action, status, created_at, completed_at, result_status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ("cmd_001", "dev_online_001", "lock", "completed", now - 60, now - 58, "OK"))

            # Telemetriya hadisələri
            conn.execute("""
                INSERT INTO telemetry_events (event_id, install_run_id, device_id, component, version, stage, event_type, severity, error_code, duration_ms, local_time, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("ev_001", "run_cmd_001", "dev_online_001", "mobile", "0.2.9", "COMMAND_TAP", "tap", "INFO", None, None, now - 61, now - 60))

            conn.execute("""
                INSERT INTO telemetry_events (event_id, install_run_id, device_id, component, version, stage, event_type, severity, error_code, duration_ms, local_time, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("ev_002", "run_cmd_001", "dev_online_001", "agent", "0.2.9", "COMMAND_COMPLETED", "exec", "INFO", None, 120, now - 59, now - 58))

            # Xəta hadisəsi (formula injection sınağı üçün zərərli simvol ilə)
            conn.execute("""
                INSERT INTO telemetry_events (event_id, install_run_id, device_id, component, version, stage, event_type, severity, error_code, duration_ms, local_time, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("ev_003", "run_ota_err", "dev_offline_002", "service", "0.1.15", "UPDATE_DOWNLOAD_DONE", "update", "ERROR", "=cmd|' /C calc'!A0", 5400, now - 300, now - 300))

            conn.commit()

    def tearDown(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def test_01_unauthorized_access(self):
        """1. Qorunan admin API-ləri yanlış və ya boş secret ilə 403 qaytarmalıdır."""
        bad_sec = "wrong_secret"
        self.assertEqual(self.service.admin_get_overview(bad_sec)[0], 403)
        self.assertEqual(self.service.admin_get_overview(None)[0], 403)
        self.assertEqual(self.service.admin_get_devices(bad_sec)[0], 403)
        self.assertEqual(self.service.admin_get_device_detail("dev_online_001", bad_sec)[0], 403)
        self.assertEqual(self.service.admin_get_telemetry(bad_sec)[0], 403)
        self.assertEqual(self.service.admin_get_timeline("run_cmd_001", bad_sec)[0], 403)
        self.assertEqual(self.service.admin_export_telemetry(bad_sec)[0], 403)
        self.assertEqual(self.service.admin_set_device_status("dev_online_001", "REVOKED", bad_sec)[0], 403)
        self.assertEqual(self.service.admin_delete_device("dev_online_001", bad_sec)[0], 403)

    def test_02_overview_metrics(self):
        """2. Ümumi baxış metrikaları dəqiq hesablanmalıdır."""
        status, data = self.service.admin_get_overview(self.admin_sec)
        self.assertEqual(status, 200)
        self.assertEqual(data["total_devices"], 3)
        self.assertEqual(data["active_devices"], 2)
        self.assertEqual(data["revoked_devices"], 1)
        self.assertEqual(data["online_devices"], 1)  # yalnız dev_online_001 (son 10s)
        self.assertEqual(data["offline_devices"], 2)
        self.assertEqual(data["error_count_24h"], 1)
        self.assertEqual(data["total_telemetry_events"], 3)
        self.assertEqual(data["update_summary"]["download_done"], 1)

    def test_03_devices_search_and_pagination(self):
        """3. Cihaz axtarışı, filtrləmə və səhifələmə işləməlidir."""
        # Axtarış
        status, data = self.service.admin_get_devices(self.admin_sec, q="Beta")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["devices"]), 1)
        self.assertEqual(data["devices"][0]["computer_name"], "Laptop-Beta")

        # Filtr status=REVOKED
        status, data = self.service.admin_get_devices(self.admin_sec, status="REVOKED")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["devices"]), 1)
        self.assertEqual(data["devices"][0]["device_id"], "dev_revoked_003")

        # Filtr online=true
        status, data = self.service.admin_get_devices(self.admin_sec, online="true")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["devices"]), 1)
        self.assertEqual(data["devices"][0]["device_id"], "dev_online_001")

        # Səhifələmə
        status, data = self.service.admin_get_devices(self.admin_sec, page=1, page_size=2)
        self.assertEqual(status, 200)
        self.assertEqual(len(data["devices"]), 2)
        self.assertEqual(data["total"], 3)
        self.assertEqual(data["total_pages"], 2)

    def test_04_device_detail_security(self):
        """4. Cihaz detalında məxfi sirlər (token, private key, PIN) olmamalıdır."""
        status, data = self.service.admin_get_device_detail("dev_online_001", self.admin_sec)
        self.assertEqual(status, 200)
        dev = data["device"]
        self.assertEqual(dev["computer_name"], "Desktop-Alpha")
        self.assertEqual(dev["pin_status"], "ready")
        self.assertTrue(dev["is_online"])
        self.assertEqual(len(dev["recent_commands"]), 1)
        self.assertEqual(dev["recent_commands"][0]["action"], "lock")

        # Məxfilik yoxlanışı
        self.assertNotIn("device_secret_hash", dev)
        self.assertNotIn("public_key_hex", dev)
        self.assertNotIn("session_token", str(dev))

    def test_05_telemetry_filtering(self):
        """5. Telemetriya hadisələri dərəcə və komponentə görə süzülməlidir."""
        status, data = self.service.admin_get_telemetry(self.admin_sec, severity="ERROR")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["telemetry"]), 1)
        self.assertEqual(data["telemetry"][0]["event_id"], "ev_003")

        status, data = self.service.admin_get_telemetry(self.admin_sec, component="mobile")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["telemetry"]), 1)
        self.assertEqual(data["telemetry"][0]["component"], "mobile")

    def test_06_command_timeline(self):
        """6. Əlaqə ID (correlation/install_run_id) üzrə addım-addım timeline ardıcıllığı."""
        status, data = self.service.admin_get_timeline("run_cmd_001", self.admin_sec)
        self.assertEqual(status, 200)
        steps = data["steps"]
        self.assertEqual(len(steps), 2)
        self.assertEqual(steps[0]["stage"], "COMMAND_TAP")
        self.assertEqual(steps[1]["stage"], "COMMAND_COMPLETED")
        self.assertEqual(steps[1]["duration_ms"], 120)

    def test_07_csv_formula_injection_protection(self):
        """7. CSV ixracında Excel formula injection hücumundan müdafiə (' tək dırnaq əlavəsi)."""
        status, csv_data, media_type = self.service.admin_export_telemetry(self.admin_sec, format_type="csv")
        self.assertEqual(status, 200)
        self.assertIn("text/csv", media_type)
        # =cmd|... hücumu '=cmd|... olaraq süzülməlidir
        self.assertIn("'=cmd|' /C calc'!A0", csv_data)
        self.assertNotIn("\n=cmd|", csv_data)

    def test_08_device_lifecycle_actions(self):
        """8. Cihazın Revoke, Activate və Delete əməliyyatları."""
        # Revoke
        st, res = self.service.admin_set_device_status("dev_online_001", "REVOKED", self.admin_sec)
        self.assertEqual(st, 200)
        self.assertEqual(res["status"], "REVOKED")

        # Activate
        st, res = self.service.admin_set_device_status("dev_online_001", "ACTIVE", self.admin_sec)
        self.assertEqual(st, 200)
        self.assertEqual(res["status"], "ACTIVE")

        # Delete
        st, res = self.service.admin_delete_device("dev_revoked_003", self.admin_sec)
        self.assertEqual(st, 200)
        self.assertEqual(res["status"], "DELETED")

        # Yoxlayırıq ki, baza daxilindən silinib
        with self.db.get_conn() as conn:
            r = conn.execute("SELECT 1 FROM devices WHERE device_id = 'dev_revoked_003'").fetchone()
            self.assertIsNone(r)

if __name__ == "__main__":
    unittest.main()
