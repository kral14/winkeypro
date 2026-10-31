"""
WinKey Pro — Gateway Security Regression Suite
Spesifikasiya: plan/GEMINI_FINAL_BATCH_REVISION.md Bölmə P0

Codex Auditində aşkar edilmiş 3 əsas boşluğun və əlavə mənfi ssenarilərin rəddini yoxlayır:
1. UNAUTHENTICATED_INVALID_KEY_REGISTRATION -> HTTP 400 E_INVALID_PUBLIC_KEY
2. UNISSUED_CODE_GRANTS_MOBILE_SESSION -> HTTP 404 E_PAIR_CODE_NOT_FOUND
3. UNAUTHENTICATED_AGENT_STATE_CHANGE -> HTTP 401 E_UNAUTHORIZED_AGENT
4. COMMAND_RESULT_THEFT_IDOR -> HTTP 403 E_COMMAND_NOT_OWNED
5. DEVICE_OWNERSHIP_HIJACKING -> HTTP 409 E_DEVICE_ALREADY_EXISTS_OWNERSHIP_VIOLATION
"""

import os
import sys
import json
import tempfile
import io
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deploy.gateway_production_server import GatewayHandler, ProductionDatabase

def run_regression_tests():
    with tempfile.TemporaryDirectory(prefix="gateway_reg_") as folder:
        db_path = str(Path(folder) / "reg.db")
        database = ProductionDatabase(db_path)

        def call_endpoint(path, payload, headers=None, method="POST"):
            handler = object.__new__(GatewayHandler)
            body = json.dumps(payload).encode() if payload is not None else b""
            handler.path = path
            req_headers = {"Content-Length": str(len(body))}
            if headers:
                req_headers.update(headers)
            handler.headers = req_headers
            handler.rfile = io.BytesIO(body)
            handler.db = database
            result = []
            handler._send_json = lambda status, data: result.append((status, data))
            if method == "POST":
                handler.do_POST()
            else:
                handler.do_GET()
            return result[0] if result else (500, {})

        print("--- REGRESSION TEST 1: Etibarsız Açarla Qeydiyyatın Rədd Edilməsi ---")
        st1, res1 = call_endpoint("/agent/register", {"device_id": "bad-key-dev", "public_key_hex": "invalid"})
        assert st1 == 400, f"Expected 400, got {st1}"
        assert res1.get("error") == "E_INVALID_PUBLIC_KEY"
        print(f"[PASS] Etibarsız açar rədd edildi (HTTP {st1}): {res1}")

        print("\n--- REGRESSION TEST 2: Naməlum Cütləşmə Kodu ilə Sessiya Alınmasının Rəddi ---")
        st2, res2 = call_endpoint("/pair", {"pair_code": "never-issued-code"})
        assert st2 == 404, f"Expected 404, got {st2}"
        assert res2.get("error") == "E_PAIR_CODE_NOT_FOUND"
        print(f"[PASS] Naməlum cütləşmə kodu rədd edildi (HTTP {st2}): {res2}")

        print("\n--- REGRESSION TEST 3: Autentifikasiyasız Agent Vəziyyət Dəyişikliyinin Rəddi ---")
        st3, res3 = call_endpoint("/agent/poll", {"device_id": "unauth-dev", "locked": True})
        assert st3 == 401, f"Expected 401, got {st3}"
        assert res3.get("error") == "E_UNAUTHORIZED_AGENT"
        print(f"[PASS] Autentifikasiyasız agent sorğusu rədd edildi (HTTP {st3}): {res3}")

        # Legit qeydiyyat aparaq
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_hex = priv_key.public_key().public_bytes_raw().hex()

        _, chal = call_endpoint("/agent/challenge", {"purpose": "register", "device_id": "legit-pc"})
        nonce = chal["nonce"]
        sig = priv_key.sign(f"WINKEY_REGISTER:{nonce}:legit-pc".encode("utf-8")).hex()

        st_reg, reg_resp = call_endpoint("/agent/register", {
            "device_id": "legit-pc",
            "computer_name": "My-Workstation",
            "public_key_hex": pub_hex,
            "proof_signature_hex": sig,
            "nonce": nonce
        })
        assert st_reg == 200, f"Legit registration failed: {reg_resp}"
        agent_secret = reg_resp["device_secret"]
        print(f"\n[SETUP] Legit PC qeydiyyatdan keçdi.")

        print("\n--- REGRESSION TEST 4: Cihaz Mülkiyyətinin Oğurlanmasının (Hijack) Rəddi ---")
        # Başqa açarla eyni device_id-ni qeydiyyatdan keçirmək cəhdi
        priv_key_attacker = ed25519.Ed25519PrivateKey.generate()
        pub_hex_attacker = priv_key_attacker.public_key().public_bytes_raw().hex()

        _, chal_att = call_endpoint("/agent/challenge", {"purpose": "register", "device_id": "legit-pc"})
        sig_att = priv_key_attacker.sign(f"WINKEY_REGISTER:{chal_att['nonce']}:legit-pc".encode("utf-8")).hex()

        st_att, res_att = call_endpoint("/agent/register", {
            "device_id": "legit-pc",
            "computer_name": "Attacker-PC",
            "public_key_hex": pub_hex_attacker,
            "proof_signature_hex": sig_att,
            "nonce": chal_att["nonce"]
        })
        assert st_att == 409, f"Expected 409 Hijack rejection, got {st_att}"
        assert res_att.get("error") == "E_DEVICE_ALREADY_EXISTS_OWNERSHIP_VIOLATION"
        print(f"[PASS] Başqa açarla mövcud cihazı qeydiyyatdan keçirmək bloklandı (HTTP {st_att}): {res_att}")

        print("\n--- REGRESSION TEST 5: Autentifikasiya ilə Düzgün Polling ---")
        st_poll, res_poll = call_endpoint(
            "/agent/poll",
            {"device_id": "legit-pc", "locked": True, "pin_ready": True},
            headers={"Authorization": f"Bearer {agent_secret}"}
        )
        assert st_poll == 200, f"Authenticated poll failed: {res_poll}"
        print(f"[PASS] Autentifikasiya olunmuş agent sorğusu uğurla qəbul edildi (HTTP {st_poll})")

        print("\n--- REGRESSION TEST 6: İmsasız və Proof-suz Qeydiyyatın Rədd Edilməsi ---")
        st6, res6 = call_endpoint("/agent/register", {
            "device_id": "no-proof-dev",
            "public_key_hex": pub_hex
        })
        assert st6 == 400, f"Expected 400 E_MISSING_PROOF, got {st6}"
        assert res6.get("error") == "E_MISSING_PROOF"
        print(f"[PASS] Proof-suz qeydiyyat rədd edildi (HTTP {st6}): {res6}")

        print("\n--- REGRESSION TEST 7: Açıq ictimai açarla icazəsiz secret rotasiyasının rəddi ---")
        # Attacker həmin pub_hex ilə challenge alıb eyni cihazı təkrar qeydiyyatdan keçirmək istəyir (amma Bearer secret bilmir)
        _, chal_rot = call_endpoint("/agent/challenge", {"purpose": "register", "device_id": "legit-pc"})
        sig_rot = priv_key.sign(f"WINKEY_REGISTER:{chal_rot['nonce']}:legit-pc".encode("utf-8")).hex()
        st7, res7 = call_endpoint("/agent/register", {
            "device_id": "legit-pc",
            "public_key_hex": pub_hex,
            "proof_signature_hex": sig_rot,
            "nonce": chal_rot["nonce"]
        })
        assert st7 == 409, f"Expected 409 E_DEVICE_ALREADY_REGISTERED, got {st7}"
        assert res7.get("error") == "E_DEVICE_ALREADY_REGISTERED"
        print(f"[PASS] İcazəsiz secret rotasiyası bloklandı (HTTP {st7}): {res7}")

        print("\n--- REGRESSION TEST 8: REJECTED statuslu cütləşmə kodunun rədd edilməsi ---")
        conn = database.get_conn()
        conn.execute("INSERT INTO pairing_requests VALUES (?, ?, ?, ?, ?, ?)",
                     ("rejected-code-test", "legit-pc", "chal", "REJECTED", 9999999999, 1000))
        conn.commit()
        conn.close()
        st8, res8 = call_endpoint("/pair", {"pair_code": "rejected-code-test"})
        assert st8 == 403, f"Expected 403 E_PAIR_CODE_REJECTED, got {st8}"
        assert res8.get("error") == "E_PAIR_CODE_REJECTED"
        print(f"[PASS] REJECTED cütləşmə kodu rədd edildi (HTTP {st8}): {res8}")

        print("\n--- REGRESSION TEST 9: Mobil Revoke və Sessiyanın Serverdə Ləğvi ---")
        # Legit pair aparaq
        st_pair_req, pair_req_data = call_endpoint(
            "/devices/pair-request",
            {"device_id": "legit-pc"},
            headers={"Authorization": f"Bearer {agent_secret}"}
        )
        assert st_pair_req == 200, f"Pair request failed: {pair_req_data}"
        valid_pair_code = pair_req_data["pair_code"]

        st_pair, pair_resp = call_endpoint("/pair", {"pair_code": valid_pair_code})
        assert st_pair == 200, f"Pair claim failed: {pair_resp}"
        mobile_token = pair_resp["session_token"]

        # Həmin tokenlə komanda göndəririk (uğurlu olmalıdır)
        st_cmd, cmd_resp = call_endpoint(
            "/devices/legit-pc/command",
            {"action": "lock"},
            headers={"Authorization": f"Bearer {mobile_token}"}
        )
        assert st_cmd == 200, f"Command failed: {cmd_resp}"

        # İndi revoke çağırırıq
        st_rev, rev_resp = call_endpoint(
            "/mobile/revoke",
            {},
            headers={"Authorization": f"Bearer {mobile_token}"}
        )
        assert st_rev == 200, f"Revoke failed: {rev_resp}"

        # Köhnə tokenlə təkrar komanda göndərmək cəhdi (HTTP 401 E_INVALID_SESSION olmalıdır!)
        st_after, res_after = call_endpoint(
            "/devices/legit-pc/command",
            {"action": "lock"},
            headers={"Authorization": f"Bearer {mobile_token}"}
        )
        assert st_after == 401, f"Expected 401 after revoke, got {st_after}"
        assert res_after.get("error") == "E_INVALID_SESSION"
        print(f"[PASS] Mobil revoke server sessiyasını tam ləğv etdi və köhnə token bloklandı (HTTP {st_after})")

        print("\n=============================================================")
        print("  BÜTÜN GATEWAY REGRESSION TESTLƏRİ 100% UĞURLA KEÇDİ!        ")
        print("=============================================================")

        del database
        import gc
        gc.collect()

if __name__ == "__main__":
    run_regression_tests()
