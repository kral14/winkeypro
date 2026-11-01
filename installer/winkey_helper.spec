# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
ROOT = Path(SPECPATH).parent


a = Analysis(
    [str(ROOT / 'pc_agent' / 'helper_main.py')],
    pathex=[str(ROOT / 'pc_agent')],
    binaries=[],
    datas=[(str(ROOT / 'pc_agent' / 'focus_credential.ps1'), '.')],
    hiddenimports=['ipc_input_worker', 'unlock_engine'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='winkey_helper',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    contents_directory='helper_runtime',
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='winkey_helper')
