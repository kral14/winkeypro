"""
WinKey Pro — Avtomatik İmzalı Yenilənmə və A/B Rollback Mühərriki
Spesifikasiya: plan/UPDATE_ROLLBACK.md

Xüsusiyyətlər:
1. Ed25519 Manifest İmzalama və Doğrulama
2. SHA-256 Tamper və Path Traversal (Zip-Slip) Qoruması
3. Atomik Journal + A/B Slot Switch
4. Real Child-Process Health Check & Startup Crash-Loop Aşkarlanması
5. Avtomatik Fail-Closed Rollback və Karantin (Quarantine) Sistemi
"""

import os
import sys
import json
import time
import shutil
import hashlib
import subprocess
from typing import Dict, Any, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519

class UpdateRollbackEngine:
    def __init__(self, base_dir: str, pinned_public_key_hex: str):
        self.base_dir = os.path.abspath(base_dir)
        self.versions_dir = os.path.join(self.base_dir, "versions")
        self.slot_a_dir = os.path.join(self.versions_dir, "slot_a")
        self.slot_b_dir = os.path.join(self.versions_dir, "slot_b")
        self.journal_file = os.path.join(self.base_dir, "update_journal.json")
        self.pinned_public_key_hex = pinned_public_key_hex

        os.makedirs(self.slot_a_dir, exist_ok=True)
        os.makedirs(self.slot_b_dir, exist_ok=True)
        self._init_journal_if_needed()

    def _init_journal_if_needed(self):
        if not os.path.exists(self.journal_file):
            initial_journal = {
                "schema_version": 1,
                "current_slot": "slot_a",
                "last_known_good_slot": "slot_a",
                "state": "IDLE", # IDLE, STAGING, PENDING_ACTIVATION, PROBATION, COMMITTED, ROLLED_BACK
                "active_version": "0.1.0",
                "candidate_version": None,
                "quarantined_versions": [],
                "crash_count": 0,
                "last_update_ts": time.time()
            }
            self._write_journal(initial_journal)

    def _read_journal(self) -> Dict[str, Any]:
        try:
            with open(self.journal_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            # Zədələnmiş faylı arxivləşdiririk (Audit / Forensic itkisinin qarşısını almaq üçün)
            if os.path.exists(self.journal_file):
                corrupt_backup = f"{self.journal_file}.corrupt.{int(time.time())}"
                try:
                    shutil.copy2(self.journal_file, corrupt_backup)
                except Exception:
                    pass

            # Kor-koranə slot_a deyil, faktiki hər iki slotun salamatlığı yoxlanılır:
            slot_a_valid = self._is_slot_valid("slot_a")
            slot_b_valid = self._is_slot_valid("slot_b")

            if slot_a_valid:
                chosen_slot = "slot_a"
            elif slot_b_valid:
                chosen_slot = "slot_b"
            else:
                chosen_slot = "NONE"

            recovered = {
                "schema_version": 1,
                "current_slot": chosen_slot,
                "last_known_good_slot": chosen_slot,
                "state": "CORRUPTED_RECOVERED" if chosen_slot != "NONE" else "FATAL_NO_VALID_SLOT",
                "active_version": "0.1.0" if chosen_slot != "NONE" else None,
                "candidate_version": None,
                "quarantined_versions": [],
                "crash_count": 0,
                "last_update_ts": time.time()
            }
            return recovered

    def _is_slot_valid(self, slot_name: str) -> bool:
        """
        Slotun həqiqi salamatlığını yoxlayır:
        Mütləq tələblər (Strict Cryptographic & Binary Verification):
        1. Qovluq mövcudluğu
        2. Mütləq manifest.json və manifest.sig mövcudluğu
        3. Pinned Ed25519 public key ilə manifest imzasının doğrulanması
        4. Manifestdəki hər bir faylın SHA-256 integrity hash yoxlanışı
        5. Reparse/path traversal qoruması (fayl yollarında '..' və ya mütləq yollar qadağandır)
        6. Əgər .exe binary varsa, PE binar header imzası (b'MZ') yoxlanışı
        İmzasız və ya manifestsiz slotlar QƏTİYYƏN QƏBUL EDİLMİR (Fail-Closed).
        """
        slot_dir = os.path.join(self.versions_dir, slot_name)
        if not os.path.isdir(slot_dir):
            return False

        manifest_file = os.path.join(slot_dir, "manifest.json")
        sig_file = os.path.join(slot_dir, "manifest.sig")
        if not os.path.isfile(manifest_file) or not os.path.isfile(sig_file):
            return False

        try:
            with open(manifest_file, "rb") as mf:
                m_bytes = mf.read()
            with open(sig_file, "rb") as sf:
                s_bytes = sf.read()

            # 1. Kriptoqrafik imzanın doğrulanması
            if not self.verify_manifest(m_bytes, s_bytes):
                return False

            manifest_obj = json.loads(m_bytes.decode("utf-8"))
            files_spec = manifest_obj.get("files", {})
            if not files_spec or not isinstance(files_spec, dict):
                return False

            # 2. Hər bir payload faylının bütövlüyü və təhlükəsizliyi
            for fname, exp_hash in files_spec.items():
                if ".." in fname or fname.startswith("/") or fname.startswith("\\") or ":" in fname:
                    return False

                fpath = os.path.join(slot_dir, fname)
                if not os.path.isfile(fpath):
                    return False

                with open(fpath, "rb") as tf:
                    fcontent = tf.read()

                act_hash = hashlib.sha256(fcontent).hexdigest()
                if act_hash.lower() != exp_hash.lower():
                    return False

                # 3. Əgər executable (.exe) fayldırsa, PE format yoxlanışı (b'MZ' magic)
                if fname.lower().endswith(".exe"):
                    if len(fcontent) < 64 or not fcontent.startswith(b"MZ"):
                        return False

            return True
        except Exception:
            return False

    def _write_journal(self, data: Dict[str, Any]):
        data["last_update_ts"] = time.time()
        temp_path = self.journal_file + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, self.journal_file)

    def verify_manifest(self, manifest_bytes: bytes, signature_bytes: bytes) -> bool:
        """Pinned Release Ed25519 Public Key ilə manifest imzasını doğrulayır."""
        try:
            vk_bytes = bytes.fromhex(self.pinned_public_key_hex)
            # Standart Ed25519 doğrulama
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            public_key = Ed25519PublicKey.from_public_bytes(vk_bytes)
            public_key.verify(signature_bytes, manifest_bytes)
            return True
        except Exception as e:
            print(f"[SECURITY_REJECT] Manifest imzası etibarsızdır: {e}")
            return False

    def stage_update_bundle(self, manifest: Dict[str, Any], file_payloads: Dict[str, bytes], signature_bytes: bytes) -> Tuple[bool, str]:
        """
        1. Manifest və imza yoxlanışı
        2. Karantin yoxlanışı
        3. Path traversal və hash yoxlanışı
        4. Inactive slot-a atomik kopyalama
        """
        version = manifest.get("version", "")
        journal = self._read_journal()

        if version in journal.get("quarantined_versions", []):
            return False, f"E_VERSION_QUARANTINED: Versiya {version} əvvəlki uğursuzluğa görə karantindədir."

        # İmza yoxlanışı (Həm canonical, həm də indent=2 formatını yoxlayırıq)
        manifest_canonical = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
        if not self.verify_manifest(manifest_canonical, signature_bytes):
            manifest_indent = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
            if not self.verify_manifest(manifest_indent, signature_bytes):
                return False, "E_INVALID_SIGNATURE: Manifest Ed25519 imzası təsdiqlənmədi."
            manifest_canonical = manifest_indent

        # Inactive slot müəyyən edilir
        current_slot = journal.get("current_slot", "slot_a")
        target_slot = "slot_b" if current_slot == "slot_a" else "slot_a"
        target_dir = os.path.join(self.versions_dir, target_slot)

        # Journal: STAGING
        journal["state"] = "STAGING"
        journal["candidate_version"] = version
        self._write_journal(journal)

        # Slotu təmizləyirik
        shutil.rmtree(target_dir, ignore_errors=True)
        os.makedirs(target_dir, exist_ok=True)

        # Faylların təhlükəsiz yerləşdirilməsi və SHA256 integrity yoxlanışı
        files_spec = manifest.get("files", {})
        if isinstance(files_spec, list):
            file_items = [(f.get("path"), f.get("sha256")) for f in files_spec if isinstance(f, dict)]
        elif isinstance(files_spec, dict):
            file_items = list(files_spec.items())
        else:
            file_items = []

        for filename, expected_hash in file_items:
            # Path Traversal (Zip-Slip) Guard
            if not filename or ".." in filename or filename.startswith("/") or filename.startswith("\\") or ":" in filename:
                shutil.rmtree(target_dir, ignore_errors=True)
                return False, f"E_SECURITY_PATH_TRAVERSAL: Qadağan olunmuş fayl yolu: {filename}"

            if filename not in file_payloads:
                shutil.rmtree(target_dir, ignore_errors=True)
                return False, f"E_MISSING_PAYLOAD: Fayl çatışmır: {filename}"

            content = file_payloads[filename]
            calc_hash = hashlib.sha256(content).hexdigest()
            if calc_hash.lower() != expected_hash.lower():
                shutil.rmtree(target_dir, ignore_errors=True)
                return False, f"E_INTEGRITY_HASH_MISMATCH: {filename} hash uyğunsuzluğu ({calc_hash} != {expected_hash})"

            dest_path = os.path.join(target_dir, filename)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            with open(dest_path, "wb") as f:
                f.write(content)

        # Manifest və imza target slot qovluğuna qeyd edilir (gələcək recovery bütövlüyü üçün)
        with open(os.path.join(target_dir, "manifest.json"), "wb") as mf:
            mf.write(manifest_canonical)
        with open(os.path.join(target_dir, "manifest.sig"), "wb") as sf:
            sf.write(signature_bytes)

        # Journal: PENDING_ACTIVATION
        journal["state"] = "PENDING_ACTIVATION"
        self._write_journal(journal)
        return True, "STAGED_SUCCESSFULLY"

    def fetch_and_stage_update_from_gateway(self, gateway_origin: str) -> Tuple[bool, str]:
        """Gateway serverindən imzalı ən son versiyanı çəkir və qorunan A/B slotuna stage edir."""
        import urllib.request
        origin = gateway_origin.rstrip("/")
        latest_url = f"{origin}/updates/latest"

        try:
            req = urllib.request.Request(latest_url, headers={"User-Agent": "WinKey-Updater/0.1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    return False, f"E_GATEWAY_HTTP_{resp.status}"
                data = json.loads(resp.read().decode("utf-8"))

            manifest = data.get("manifest")
            sig_hex = data.get("manifest_sig_hex")
            dl_prefix = data.get("download_url_prefix", "/updates/download")

            if not manifest or not sig_hex:
                return False, "E_INVALID_UPDATE_METADATA"

            sig_bytes = bytes.fromhex(sig_hex)
            files_spec = manifest.get("files", {})
            if isinstance(files_spec, list):
                file_names = [f.get("path") for f in files_spec if isinstance(f, dict) and f.get("path")]
            elif isinstance(files_spec, dict):
                file_names = list(files_spec.keys())
            else:
                file_names = []

            file_payloads: Dict[str, bytes] = {}

            # Hər bir imzalı faylı endiririk
            for fname in file_names:
                dl_url = f"{origin}{dl_prefix}/{fname}"
                dl_req = urllib.request.Request(dl_url, headers={"User-Agent": "WinKey-Updater/0.1.0"})
                with urllib.request.urlopen(dl_req, timeout=10) as f_resp:
                    if f_resp.status != 200:
                        return False, f"E_DOWNLOAD_FAILED_{fname}"
                    file_payloads[fname] = f_resp.read()

            # Qorunan stage_update_bundle vasitəsilə təsdiqləyib slot-a yerləşdiririk
            return self.stage_update_bundle(manifest, file_payloads, sig_bytes)
        except Exception as e:
            return False, f"E_UPDATE_FETCH_EXCEPTION: {e}"

    def activate_candidate_and_monitor(self, timeout_sec: int = 5) -> Tuple[bool, str]:
        """
        1. Current slot -> Target slot dəyişdirilir (Atomik A/B Switch)
        2. Candidate prosesi işə salınır
        3. Real child-process crash-loop və ya uğursuzluq izlənir
        4. Crash olarsa -> Avtomatik ROLLBACK!
        """
        journal = self._read_journal()
        if journal.get("state") != "PENDING_ACTIVATION":
            return False, f"E_INVALID_STATE: Aktivasiya yalnız PENDING_ACTIVATION vəziyyətində mümkündür (cari: {journal.get('state')})"

        current_slot = journal.get("current_slot", "slot_a")
        target_slot = "slot_b" if current_slot == "slot_a" else "slot_a"
        candidate_version = journal.get("candidate_version", "unknown")

        print(f"[UPDATE_SUPERVISOR] A/B Keçidi başladılır: {current_slot} -> {target_slot} (v{candidate_version})")

        # Atomik Slot Switch
        journal["state"] = "PROBATION"
        journal["current_slot"] = target_slot
        self._write_journal(journal)

        target_dir = os.path.join(self.versions_dir, target_slot)
        runner_file = os.path.join(target_dir, "run.py")

        # Namizəd prosesin işə salınması
        if not os.path.exists(runner_file):
            print("[UPDATE_SUPERVISOR] Runner faylı tapılmadı -> Dərhal Rollback!")
            return self.trigger_rollback("E_MISSING_ENTRYPOINT")

        proc = subprocess.Popen([sys.executable, runner_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        start_t = time.time()
        crashed = False

        while time.time() - start_t < timeout_sec:
            poll_res = proc.poll()
            if poll_res is not None:
                # Proses tez çökdü (Crash-loop)
                crashed = True
                break
            time.sleep(0.2)

        if crashed:
            print(f"[UPDATE_SUPERVISOR] Namizəd proses çökmüşdür (Exit={proc.returncode})! Avtomatik Rollback icra olunur...")
            return self.trigger_rollback(f"E_CANDIDATE_CRASH_EXIT_{proc.returncode}")

        # Proses uğurla probation müddətini keçdi
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            proc.kill()

        journal["state"] = "COMMITTED"
        journal["last_known_good_slot"] = target_slot
        journal["active_version"] = candidate_version
        journal["candidate_version"] = None
        journal["crash_count"] = 0
        self._write_journal(journal)
        print(f"[UPDATE_SUPERVISOR] Yenilənmə uğurla COMMITTED oldu! Yeni LKG: {target_slot} (v{candidate_version})")
        return True, "UPDATE_COMMITTED"

    def trigger_rollback(self, reason: str) -> Tuple[bool, str]:
        """Köhnə last_known_good_slot-a təhlükəsiz qayıdış və namizədin karantinə alınması."""
        journal = self._read_journal()
        lkg_slot = journal.get("last_known_good_slot", "slot_a")
        bad_version = journal.get("candidate_version")

        print(f"[ROLLBACK] Səbəb: {reason}. Bərpa olunan etibarlı slot: {lkg_slot}")
        quarantined = journal.get("quarantined_versions", [])
        if bad_version and bad_version not in quarantined:
            quarantined.append(bad_version)

        journal["state"] = "ROLLED_BACK"
        journal["current_slot"] = lkg_slot
        journal["quarantined_versions"] = quarantined
        journal["candidate_version"] = None
        journal["crash_count"] = journal.get("crash_count", 0) + 1
        self._write_journal(journal)

        return False, f"ROLLED_BACK_TO_{lkg_slot}:{reason}"
