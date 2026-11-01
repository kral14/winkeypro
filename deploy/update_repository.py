"""Immutable signed Windows releases; atomic current pointer, no private keys."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PINNED_PUBLIC_KEY = bytes.fromhex('4c7fa3c7a37b79b840e939741138f0748087ae0f06fa94e728557ec2a558fc54')
MAX_PACKAGE = 256 * 1024 * 1024


class UpdateRepository:
    def __init__(self, root=None, public_key=PINNED_PUBLIC_KEY):
        self.root = Path(root or os.environ.get('WINKEY_UPDATES_DIR', '/updates'))
        self.public_key = public_key

    def current(self):
        try:
            release = (self.root / 'current').read_text(encoding='ascii').strip()
            if not re.fullmatch('[0-9a-f]{64}', release): return None
            directory = self.root / 'releases' / release
            raw = (directory / 'manifest.json').read_bytes()
            signature = (directory / 'manifest.sig').read_bytes()
            Ed25519PublicKey.from_public_bytes(self.public_key).verify(signature, raw)
            if hashlib.sha256(raw).hexdigest() != release: return None
            manifest = json.loads(raw)
            return {'release_id': release, 'version': manifest['version'], 'manifest': manifest,
                    'manifest_raw': raw.decode('utf-8'), 'manifest_sig_hex': signature.hex(),
                    'download_url_prefix': '/updates/download/' + release}
        except (OSError, ValueError, KeyError, TypeError):
            return None
        except Exception:
            return None

    def publish(self, archive):
        if len(archive) > MAX_PACKAGE: raise ValueError('E_PACKAGE_TOO_LARGE')
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            members = package.infolist()
            names = [m.filename for m in members]
            if len(names) != len(set(names)) or len(names) > 4096:
                raise ValueError('E_PACKAGE_DUPLICATES_OR_COUNT')
            if sum(m.file_size for m in members) > MAX_PACKAGE:
                raise ValueError('E_PACKAGE_EXPANSION_LIMIT')
            raw = package.read('manifest.json')
            signature = package.read('manifest.sig')
            Ed25519PublicKey.from_public_bytes(self.public_key).verify(signature, raw)
            manifest = json.loads(raw)
            if not re.fullmatch(r'\d+\.\d+\.\d+', manifest['version']):
                raise ValueError('E_VERSION_FORMAT')
            listed = [f['path'] for f in manifest['files']]
            if len(listed) != len(set(listed)) or set(names) != set(listed) | {'manifest.json', 'manifest.sig'}:
                raise ValueError('E_PACKAGE_FILE_SET')
            if not {'winkey_service.exe', 'winkey_helper.exe'}.issubset(listed):
                raise ValueError('E_REQUIRED_PAYLOAD')
            for name in listed:
                path = PurePosixPath(name)
                if path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name or str(path) != name:
                    raise ValueError('E_PACKAGE_PATH')
                if name not in ('winkey_service.exe', 'winkey_helper.exe', 'winkey_desktop.exe') and not name.startswith('helper_runtime/'):
                    raise ValueError('E_PACKAGE_UNEXPECTED_FILE')
            old = self.current()
            release = hashlib.sha256(raw).hexdigest()
            if old and old['release_id'] == release: return old
            if old and tuple(map(int,manifest['version'].split('.'))) <= tuple(map(int,old['version'].split('.'))):
                raise ValueError('E_RELEASE_NOT_NEWER')
            releases = self.root / 'releases'
            releases.mkdir(parents=True, exist_ok=True)
            staging = Path(tempfile.mkdtemp(prefix='.staging-', dir=releases))
            try:
                for entry in manifest['files']:
                    data = package.read(entry['path'])
                    if len(data) != entry['size'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
                        raise ValueError('E_PAYLOAD_HASH')
                    target = staging / entry['path']
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open('wb') as output:
                        output.write(data); output.flush(); os.fsync(output.fileno())
                for name, data in [('manifest.json',raw),('manifest.sig',signature)]:
                    with (staging / name).open('wb') as output:
                        output.write(data); output.flush(); os.fsync(output.fileno())
                destination = releases / release
                if not destination.exists(): os.replace(staging,destination)
                pointer = self.root / ('current.' + os.urandom(8).hex() + '.tmp')
                with pointer.open('w',encoding='ascii') as output:
                    output.write(release); output.flush(); os.fsync(output.fileno())
                os.replace(pointer,self.root / 'current')
                if os.name != 'nt':
                    descriptor=os.open(self.root,os.O_RDONLY)
                    try: os.fsync(descriptor)
                    finally: os.close(descriptor)
            finally:
                if staging.exists(): shutil.rmtree(staging)
        return self.current()

    def download(self, release, name):
        if not re.fullmatch('[0-9a-f]{64}', release): return None
        base = self.root / 'releases' / release
        try:
            raw = (base / 'manifest.json').read_bytes()
            Ed25519PublicKey.from_public_bytes(self.public_key).verify((base / 'manifest.sig').read_bytes(), raw)
            if hashlib.sha256(raw).hexdigest() != release: return None
            manifest = json.loads(raw)
            if name not in {f['path'] for f in manifest['files']}: return None
            path = (base / name).resolve()
            if not path.is_relative_to(base.resolve()) or not path.is_file(): return None
            return path
        except Exception:
            return None
