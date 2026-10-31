import importlib.util, tempfile, pathlib, shutil, json, traceback, subprocess, atexit
tracked=[]
original_popen=subprocess.Popen
def tracked_popen(*a,**kw):
    proc=original_popen(*a,**kw)
    tracked.append(proc)
    return proc
def cleanup():
    for proc in tracked:
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
atexit.register(cleanup)
subprocess.Popen=tracked_popen
root=pathlib.Path(__file__).resolve().parents[1]
src=(root/'tests/test_e2e_full_chain.py').read_text(encoding='utf-8')
# Keep native registration/login/approval/service polling. Replace actual LOCK with a mock action.
needle='st_cmd, res_cmd = http_req("commands", "POST", {"device_id": device_id, "action": "lock"}, headers=owner_headers)'
assert src.count(needle)==1
src=src.replace(needle,needle.replace('"action": "lock"','"action": "mock"'))
a=src.index('        # 7b. Provision Local PIN')
b=src.index('        # 10. Device Revoke Lifecycle',a)
src=src[:a]+'''        # Independent functional assertion: an unlock is only successful when success is actually reported.
        assert matching and matching[0]['state'] == 'success' and 'SUCCESS_UNLOCKED' in str(matching[0]['result']), "CODEX_FUNCTIONAL_UNLOCK_FAILED: native service did not unlock; original suite labels this failure PASS"
'''+src[b:]
tempfile.tempdir=str(root/'plan/reports/codex')
with tempfile.TemporaryDirectory(prefix='winkey_codex_audit_', dir=root/'plan/reports/codex') as td:
    gateway=pathlib.Path(td)/'gateway_server.py'
    shutil.copy2(root/'tests/gateway_http_suite/gateway_server.py',gateway)
    ns={'__name__':'codex_audit','__file__':str(root/'tests/test_e2e_full_chain.py')}
    exec(compile(src,'audited_e2e_no_input.py','exec'),ns)
    ns['PORT']=18789
    ns['BASE_URL']='http://127.0.0.1:18789'
    ns['GATEWAY_SCRIPT']=str(gateway)
    ns['REPORT_LOG']=str(root/'plan/reports/codex/unlock_functional_audit.log')
    try:
        ns['run_e2e']()
    except AssertionError as e:
        print('CODEX_RESULT:',str(e))
        raise SystemExit(1)


