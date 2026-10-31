import pathlib,tempfile,shutil,subprocess,atexit
root=pathlib.Path(__file__).resolve().parents[1]
tracked=[]
original=subprocess.Popen
def popen(*a,**kw):
    p=original(*a,**kw);tracked.append(p);return p
def cleanup():
    for p in tracked:
        if p.poll() is None:
            p.terminate()
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait()
atexit.register(cleanup)
subprocess.Popen=popen
tempfile.tempdir=str(root/'plan/reports/codex')
with tempfile.TemporaryDirectory(prefix='nonphysical_') as td:
    gw=pathlib.Path(td)/'gateway_server.py'
    shutil.copy2(root/'tests/gateway_http_suite/gateway_server.py',gw)
    ns={'__name__':'codex_nonphysical','__file__':str(root/'tests/test_e2e_full_chain.py')}
    exec(compile((root/'tests/test_e2e_full_chain.py').read_text(encoding='utf-8'),'test_e2e_full_chain.py','exec'),ns)
    ns.update(PORT=18791,BASE_URL='http://127.0.0.1:18791',GATEWAY_SCRIPT=str(gw),REPORT_LOG=str(root/'plan/reports/codex/nonphysical_e2e.log'))
    try:ns['run_e2e'](allow_real_input=False)
    finally:cleanup()
