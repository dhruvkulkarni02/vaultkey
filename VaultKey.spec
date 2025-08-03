# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files

datas = []
datas += collect_data_files('vaultkey')


a = Analysis(
    ['run_vaultkey.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=['vaultkey.manager', 'vaultkey.generator', 'vaultkey.strength', 'vaultkey.breach', 'vaultkey.portability', 'vaultkey.crypto', 'vaultkey.storage'],
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
    a.binaries,
    a.datas,
    [],
    name='VaultKey',
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
)
