"""Actual clean-layout/identity probes, no credentials and no OS input."""
from pathlib import Path
import json
import shutil
import statistics
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / 'apps/winkey_service/target/release'


def run(exe, *args):
    return subprocess.run([str(exe), *map(str, args)], capture_output=True, text=True, timeout=20)


def main():
    with tempfile.TemporaryDirectory(prefix='helper-delivery-', dir=ROOT / 'build') as tmp:
        slot = Path(tmp)
        manifest = ROOT / 'deploy/pre_signed_slot_a'
        data = json.loads((manifest / 'manifest.json').read_text())
        for entry in data['files']:
            dest = slot / entry['path']
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(RELEASE / entry['path'], dest)
        for name in ('manifest.json', 'manifest.sig'):
            shutil.copy2(manifest / name, slot / name)
        svc, helper = slot / 'winkey_service.exe', slot / 'winkey_helper.exe'
        for args in [('--validate-slot', slot), ('--probe-helper-peer', '--helper-path', helper)]:
            result = run(svc, *args)
            assert result.returncode == 0, result.stdout + result.stderr
        for flag in ('--check-focus-resource', '--check-input-abi'):
            assert run(helper, flag).returncode == 0
        dll = slot / 'helper_runtime/python313.dll'
        original = dll.read_bytes()
        dll.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        assert run(svc, '--validate-slot', slot).returncode != 0
        assert run(svc, '--probe-helper-peer', '--helper-path', helper).returncode != 0
        dll.write_bytes(original)
        print('PASS clean layout, signed dependencies, actual PID checks, corrupt runtime rejected')
        measurements = {}
        for name, exe in [('onefile', ROOT / 'build/helper_baseline/winkey_helper.exe'), ('onedir', helper)]:
            samples = []
            for _ in range(7):
                start = time.perf_counter()
                result = run(exe, '--check-input-abi')
                assert result.returncode == 0, result.stderr
                samples.append(round((time.perf_counter() - start) * 1000, 1))
            measurements[name] = {'samples_ms': samples, 'median_ms': statistics.median(samples)}
        out = ROOT / 'plan/reports/codex/helper_startup_measurements.json'
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(measurements, indent=2), encoding='utf-8')
        print(json.dumps(measurements))


if __name__ == '__main__':
    main()
