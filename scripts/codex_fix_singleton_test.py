from pathlib import Path
p=Path('scripts/test_desktop_tray_singleton.py');s=p.read_text(encoding='utf-8')
s=s.replace("if proc.info['name'] and 'winkey_desktop' in proc.info['name'].lower():", "if proc.info['exe'] and os.path.normcase(os.path.realpath(proc.info['exe'])) == os.path.normcase(os.path.realpath(DESKTOP_EXE)):")
a=s.index('    # Cleanup any stale instances');b=s.index('    # 1. Launch Primary Instance',a)
s=s[:a]+'''    # Never terminate a user's existing app. Test only a process created here.
    stale = get_winkey_desktop_pids()
    if stale:
        print("[NOT_TESTED] Existing desktop instance is open; left untouched. Close it via tray Exit before rerunning.")
        return

'''+s[b:]
s=s.replace('5 rapid','8 rapid').replace('range(5)','range(8)').replace('after 5 rapid','after 8 rapid')
s=s.replace('ALL DESKTOP SINGLETON & MUTEX TESTS PASSED (100% PASS)','SINGLETON PROCESS TEST PASSED; TRAY CLICK/EXIT STILL REQUIRE UI TEST')
s=s.replace('without leaking a second process or tray icon!','without leaking a second process (tray icon count not measured)!')
s=s.replace('(Zero tray duplication).','(one process; tray icon count not measured).')
p.write_text(s,encoding='utf-8')
