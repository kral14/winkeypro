"""Execute only the cleanup function from the installer on disposable files."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class RuntimeCleanupTest(unittest.TestCase):
    def test_removes_stale_dlls_preserves_signed_files_and_siblings(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            fixture=Path(temporary); install=fixture/'WinKey'; runtime=install/'helper_runtime'
            runtime.mkdir(parents=True)
            (runtime/'python313.dll').write_bytes(b'SYNTHETIC_SIGNED_RUNTIME')
            (runtime/'old-runtime.dll').write_bytes(b'STALE_UNSIGNED_RUNTIME')
            (runtime/'nested').mkdir();(runtime/'nested/old.dll').write_bytes(b'STALE')
            (install/'outside-runtime.txt').write_bytes(b'KEEP_SIBLING')
            manifest=fixture/'manifest.json'
            manifest.write_text(json.dumps({'files':[{'path':'helper_runtime/python313.dll'}]}))
            runner=fixture/'runner.ps1'
            runner.write_text('''param($Source,$RootDir,$Manifest)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if ($errors.Count) {throw 'E_INSTALLER_PARSE'}
$fn=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Remove-UnlistedHelperRuntime'},$true)
if (-not $fn) {throw 'E_CLEANUP_FUNCTION_MISSING'}
. ([scriptblock]::Create($fn.Extent.Text))
Remove-UnlistedHelperRuntime -RootDir $RootDir -Manifest (Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json)
''',encoding='utf-8-sig')
            result=subprocess.run(['powershell','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(runner),
                '-Source',str(ROOT/'scripts/service_installer.ps1'),'-RootDir',str(install),'-Manifest',str(manifest)],
                capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=15)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual((runtime/'python313.dll').read_bytes(),b'SYNTHETIC_SIGNED_RUNTIME')
            self.assertEqual((install/'outside-runtime.txt').read_bytes(),b'KEEP_SIBLING')
            self.assertFalse((runtime/'old-runtime.dll').exists())
            self.assertFalse((runtime/'nested/old.dll').exists())


if __name__=='__main__':unittest.main()
