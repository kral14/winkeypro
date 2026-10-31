from pathlib import Path
p=Path('tests/test_e2e_full_chain.py')
s=p.read_text(encoding='utf-8')
s=s.replace('import sys\n','import sys\nimport argparse\n',1)
s=s.replace('def run_e2e():','def run_e2e(allow_real_input=False):',1)
s=s.replace('        st_cmd, res_cmd = http_req("commands", "POST", {"device_id": device_id, "action": "lock"}, headers=owner_headers)', '        action = "lock" if allow_real_input else "mock"\n        st_cmd, res_cmd = http_req("commands", "POST", {"device_id": device_id, "action": action}, headers=owner_headers)',1)
s=s.replace('        assert cmd_finished is True, "Service failed to execute and report command within window!"','        assert cmd_finished is True, "Service failed to execute and report command within window!"\n        assert final_state == "success", f"Command failed: {final_result}"\n        expected = "SUCCESS_LOCKED" if allow_real_input else "DEMO_MOCK_ACTION"\n        assert expected in str(final_result), f"Unexpected command result: {final_result}"',1)
s=s.replace('        for attempt in range(12):\n            time.sleep(0.8)\n            st_chk, res_chk = http_req("history", "GET", headers=owner_headers)\n            if st_chk == 200:\n                matching = [c for c in res_chk.get("commands", []) if c["id"] == unlock_cmd_id]', '        missing_vault_finished = False\n        for attempt in range(12):\n            time.sleep(0.8)\n            st_chk, res_chk = http_req("history", "GET", headers=owner_headers)\n            if st_chk == 200:\n                matching = [c for c in res_chk.get("commands", []) if c["id"] == unlock_cmd_id]',1)
s=s.replace('                    log("[PASS] Strict Audit Verified: Network payload has zero credential; missing local vault returned E_NO_LOCAL_CREDENTIAL")','                    missing_vault_finished = True\n                    log("[PASS][SECURITY_BOUNDARY] Missing credential rejected; this is NOT an unlock success")',1)
s=s.replace('        # 7b. Provision Local PIN','        assert missing_vault_finished, "Missing-vault command never completed"\n\n        # 7b. Provision Local PIN',1)
a=s.index('        # 7c. Trigger unlock with Local PIN')
b=s.index('        # 10. Device Revoke Lifecycle',a)
block=s[a:b]
block=block.replace('        for attempt in range(12):','        functional_unlock_finished = False\n        for attempt in range(12):',1)
x=block.index('                    assert "SUCCESS_UNLOCKED" not in')
y=block.index('                    break',x)
block=block[:x]+'''                    assert matching[0]["state"] == "success", f"FUNCTIONAL_UNLOCK_FAILED: {matching[0]['result']}"
                    assert "SUCCESS_UNLOCKED" in str(matching[0]["result"]), "No verified unlock result"
                    functional_unlock_finished = True
                    log("[PASS][FUNCTIONAL_UNLOCK] Verified service unlock result")
'''+block[y:]
block+='        assert functional_unlock_finished, "Functional unlock command never completed"\n'
s=s[:a]+'        if allow_real_input:\n'+''.join('    '+line if line.strip() else line for line in block.splitlines(True))+'        else:\n            log("[NOT_TESTED][PHYSICAL_UNLOCK] Skipped: --allow-real-input not supplied. No credential input sent.")\n\n'+s[b:]
s=s.replace('  ALL END-TO-END FULL CHAIN INTEGRATION TESTS PASSED (9/9 PASS)  ','  NONPHYSICAL INTEGRATION COMPLETED; PHYSICAL UNLOCK REQUIRES OPT-IN  ')
s=s.replace('    run_e2e()','    parser = argparse.ArgumentParser()\n    parser.add_argument("--allow-real-input", action="store_true", help="Explicit operator opt-in: real screen lock and credential input")\n    run_e2e(allow_real_input=parser.parse_args().allow_real_input)',1)
p.write_text(s,encoding='utf-8')
