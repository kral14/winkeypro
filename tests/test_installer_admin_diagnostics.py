"""
WinKey Pro — Installer -> Admin Telemetry & Incident Diagnostics Sınağı
Spesifikasiya: plan/DIAGNOSTICS_SUPPORT.md & plan/GEMINI_PRODUCT_INTEGRATION_FINAL.md

Yoxlayır:
1. Installer Local Durable Outbox:
   - service_installer.ps1 işə düşdükdə və ya başa çatdıqda $DataDir/diagnostics_outbox.json faylına strukturlaşdırılmış telemetriya hadisəsi yazılır.
2. Installer-to-Gateway Direct Event Forwarding:
   - Installer -GatewayOrigin parametri ilə Gateway-in /agent/telemetry endpoint-inə hadisəni (POST) çatdırır.
3. Owner Admin Paneli və İnsident Timeline İnteqrasiyası:
   - Admin GET /admin/telemetry çağırdıqda service_installer komponentinin yaratdığı hadisələri (INSTALL_SUCCESS, INSTALL_ROLLBACK və s.) görür.
4. Rollback Incident Audit:
   - Rollback xətası baş verdikdə ERROR dərəcəli insident error_code ilə qeydə alınır.
"""

import os
import sys
import json
import time
import shutil
import tempfile
import threading
import subprocess
import urllib.request
import urllib.error
import unittest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "deploy"))
import gateway_production_server as gateway

class TestInstallerAdminDiagnostics(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="winkey_diag_test_")
        self.data_dir = os.path.join(self.tmp_dir, "WinKeyData")
        os.makedirs(self.data_dir, exist_ok=True)

        self.db_path = os.path.join(self.tmp_dir, "gw.db")
        self.port = 8193
        self.origin = f"http://127.0.0.1:{self.port}"
        self.admin_secret = "admin_sec_telemetry_test_123"
        os.environ["WINKEY_ADMIN_SECRET"] = self.admin_secret

        self.server = gateway.run_server(self.port, self.db_path)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        time.sleep(0.2)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_installer_outbox_and_admin_telemetry_integration(self):
        """Installer: Oflayn olduqda hadisələr outbox-da qalır, online olduqda server ACK ilə flush və dequeue edilir."""
        installer_ps1 = os.path.join(ROOT_DIR, "scripts", "service_installer.ps1")
        
        # 1. Gateway göstərilmədikdə (oflayn rejim) — hadisələr outbox-da saxlanmalıdır
        ps_offline = f"""
        . '{installer_ps1}'
        $DataDir = '{self.data_dir}'
        $GatewayOrigin = ''
        
        Write-WinKeyDiagnosticEvent -Stage "INSTALL_START" -EventType "start" -Severity "INFO"
        Write-WinKeyDiagnosticEvent -Stage "INSTALL_ROLLBACK" -EventType "error" -Severity "ERROR" -ErrorCode "E_TEST_MOCK_ROLLBACK"
        Write-WinKeyDiagnosticEvent -Stage "INSTALL_SUCCESS" -EventType "success" -Severity "INFO"
        """
        
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_offline],
            capture_output=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(res.returncode, 0)

        outbox_file = os.path.join(self.data_dir, "diagnostics_outbox.json")
        self.assertTrue(os.path.isfile(outbox_file), "Lokal outbox faylı yaradılmalıdır!")
        with open(outbox_file, "r", encoding="utf-8-sig") as f:
            local_events = json.load(f)
        self.assertEqual(len(local_events), 3, "Oflayn rejimdə 3 hadisə outbox-da qalmalıdır!")
        print("[PASS] Oflayn rejim: Hadisələr lokal durable outbox-da etibarlı şəkildə saxlanıldı.")

        # 2. İndi Gateway aktivdir — flush və ACK-based dequeue icra edilir
        ps_online = f"""
        . '{installer_ps1}'
        $DataDir = '{self.data_dir}'
        $GatewayOrigin = '{self.origin}'
        
        # Mövcud outbox-dakı hadisələri Gateway-ə flush edirik
        Write-WinKeyDiagnosticEvent -Stage "FLUSH_SYNC" -EventType "sync" -Severity "INFO"
        """
        res2 = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_online],
            capture_output=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(res2.returncode, 0)

        # Gateway-ə çatdırıldıqdan sonra ACK alınıb və outbox dequeue olunub (0 qalıb)
        with open(outbox_file, "r", encoding="utf-8-sig") as f:
            flushed_queue = json.load(f)
        self.assertEqual(len(flushed_queue), 0, "Server ACK-indən sonra bütün hadisələr dequeue edilməlidir!")
        print("[PASS] Online rejim: Outbox-dakı hadisələr Gateway-ə çatdırıldı və ACK ilə dequeue edildi.")

        # 3. Gateway Server və Admin Telemetry API yoxlanışı
        time.sleep(0.3)
        req = urllib.request.Request(
            f"{self.origin}/admin/telemetry",
            headers={"X-Owner-Admin-Secret": self.admin_secret}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            server_events = data.get("telemetry", [])

        self.assertGreaterEqual(len(server_events), 3)
        server_stages = [e["stage"] for e in server_events]
        self.assertIn("INSTALL_START", server_stages)
        self.assertIn("INSTALL_ROLLBACK", server_stages)
        self.assertIn("INSTALL_SUCCESS", server_stages)

        # Rollback xəta kodunun dəqiq qeyd olunması
        rollback_evt = next(e for e in server_events if e["stage"] == "INSTALL_ROLLBACK")
        self.assertEqual(rollback_evt["error_code"], "E_TEST_MOCK_ROLLBACK")
        self.assertEqual(rollback_evt["severity"], "ERROR")

        print("[PASS] Installer hadisələri Gateway-ə çatdırıldı və Owner Admin telemetriyasında təsdiqləndi.")

    def test_02_actual_installer_lifecycle_diagnostics(self):
        """Faktiki service_installer.ps1 skripti icra olunduqda INSTALL_START və ACL_APPLIED hadisələri yaranır."""
        installer_ps1 = os.path.join(ROOT_DIR, "scripts", "service_installer.ps1")
        test_dir = os.path.join(self.tmp_dir, "LifecycleData")

        res = subprocess.run(
            [
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", installer_ps1,
                "-DataDir", test_dir,
                "-GatewayOrigin", self.origin,
                "-ApplyAclOnly"
            ],
            capture_output=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(res.returncode, 0, f"Installer lifecycle xətası: {res.stderr}\nStdout: {res.stdout}")

        # Gateway-də INSTALL_START və ACL_APPLIED hadisələrinin olması
        time.sleep(0.3)
        req = urllib.request.Request(
            f"{self.origin}/admin/telemetry",
            headers={"X-Owner-Admin-Secret": self.admin_secret}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            stages = [e["stage"] for e in data.get("telemetry", [])]

        self.assertIn("INSTALL_START", stages)
        self.assertIn("ACL_APPLIED", stages)
        print("[PASS] Faktiki service_installer.ps1 lifecycle-i INSTALL_START və ACL_APPLIED hadisələrini uğurla qeyd etdi.")

    def test_03_installer_outbox_durable_before_send_and_quarantine(self):
        """Zədələnmiş outbox faylının karantinə alınması və ayrı replay sender funksiyasının sınağı."""
        installer_ps1 = os.path.join(ROOT_DIR, "scripts", "service_installer.ps1")
        test_dir = os.path.join(self.tmp_dir, "QuarantineData")
        os.makedirs(test_dir, exist_ok=True)
        outbox_file = os.path.join(test_dir, "diagnostics_outbox.json")

        # 1. Zədələnmiş fayl yaradırıq (qeyri-valid JSON)
        with open(outbox_file, "w", encoding="utf-8") as f:
            f.write("CORRUPTED_NON_JSON_DATA_!!!###")

        # PowerShell ilə yeni hadisə yazdırırıq
        ps_cmd = f"""
        . '{installer_ps1}'
        $DataDir = '{test_dir}'
        $GatewayOrigin = ''
        Write-WinKeyDiagnosticEvent -Stage "TEST_AFTER_CORRUPT" -EventType "test" -Severity "INFO"
        """
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(res.returncode, 0)

        # 2. Zədələnmiş faylın karantinə köçürüldüyünü yoxlayırıq
        quarantine_files = [f for f in os.listdir(test_dir) if "diagnostics_outbox.json.corrupt." in f]
        self.assertGreaterEqual(len(quarantine_files), 1, "Zədələnmiş outbox karantinə alınmalıdır!")

        # 3. Yeni outbox faylının sağlam şəkildə yaradıldığını yoxlayırıq
        with open(outbox_file, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["stage"], "TEST_AFTER_CORRUPT")
        print("[PASS] Zədələnmiş telemetriya faylı uğurla karantinə aparıldı və sağlam növbə bərpa olundu.")

        # 4. Ayrı Replay Sender sınağı (-ReplayTelemetry)
        ps_replay = f"""
        & '{installer_ps1}' -DataDir '{test_dir}' -GatewayOrigin '{self.origin}' -ReplayTelemetry
        """
        res_rep = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_replay],
            capture_output=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(res_rep.returncode, 0)

        # Server ACK alıb və növbə təmizlənib
        with open(outbox_file, "r", encoding="utf-8-sig") as f:
            flushed = json.load(f)
        self.assertEqual(len(flushed), 0, "Replay sender bütün hadisələri serverə çatdırıb outbox-u boşaltmalıdır!")
        print("[PASS] Ayrı Replay Sender hadisələri serverə çatdırdı və ACK ilə dequeue etdi.")

if __name__ == "__main__":
    unittest.main()
