"""Build release → sanitized source snapshot + signed ZIP → Git push.

Only the dedicated signed update ZIP is a release binary in Git. Runtime data,
private keys, local credentials, caches and build directories are never exported.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

REMOTE = 'https://github.com/kral14/winkeypro.git'
PACKAGE_PATH = Path('deploy/windows_release/WinKeyUpdate.zip')
DIRECTORIES = {'.github','apps','deploy','installer','pc_agent','scripts','tests','docs','plan','legacy','experiments'}
SKIP_DIRS = {'.git','.github-publish','.agents','.codex','.aws','.openai','keys','secrets','target','dist','build',
    'node_modules','__pycache__','backups','reports','diagnostic_logs','.next','.wrangler','.vinext',
    '.sites-runtime','.sites-checkout','pre_signed_slot_a','windows_release','rustdesk','release','release2','release3'}
EXTENSIONS = {'.py','.rs','.ts','.tsx','.js','.mjs','.cjs','.html','.css','.json','.toml','.lock','.sql','.md',
    '.ps1','.bat','.vbs','.nsi','.svg','.png','.ico','.yml','.yaml','.spec','.nsh'}
ROOT_FILES = {'build.py','run.py','Dockerfile','compose.yaml','README.md','.gitignore','.gitattributes','.dockerignore','manifest.json','requirements-dev.txt'}
SKIP_FILES = {'config.json','package-credential.json','desktop_err.txt','desktop_out.txt'}


def git(repo, *args):
    result = subprocess.run(['git',*args],cwd=repo,capture_output=True,text=True,encoding='utf-8',errors='replace')
    if result.returncode:
        detail=result.stderr.strip()
        detail=re.sub(r'(https?://)[^\s/@]+(?::[^\s/@]*)?@',r'\1[REDACTED]@',detail)
        detail=re.sub(r'\b(?:ghp_|github_pat_)[A-Za-z0-9_]+','[REDACTED]',detail)
        detail=re.sub(r'(?i)(bearer\s+)\S+',r'\1[REDACTED]',detail)
        raise RuntimeError('Git '+args[0]+f' alınmadı (exit={result.returncode}): '+detail[:2000])
    return result.stdout.strip()


def checkout_for(root):
    root=Path(root)
    if (root/'.git').exists(): return root
    checkout=root/'.github-publish'
    if (checkout/'.git').exists(): return checkout
    raise RuntimeError('Git checkout tapılmadı. Layihə Git clone-dan və ya mövcud .github-publish ilə işlədilməlidir.')


def preflight_git(root, fetch=True, allow_pending=False):
    if not shutil.which('git'): raise RuntimeError('Git quraşdırılmayıb.')
    checkout=checkout_for(root)
    remote=git(checkout,'remote','get-url','origin')
    if remote.rstrip('/') not in (REMOTE,REMOTE.removesuffix('.git'),'git@github.com:kral14/winkeypro.git'):
        raise RuntimeError('Origin gözlənilən kral14/winkeypro repozitoriyası deyil; push dayandırıldı.')
    if git(checkout,'branch','--show-current') != 'main':
        raise RuntimeError('Avtomatik release yalnız main branch-dədir.')
    if not allow_pending and checkout.resolve()!=Path(root).resolve() and git(checkout,'status','--porcelain'):
        raise RuntimeError('Əvvəlki Git mərhələsi yarımçıqdır. Hazır paketi yenidən build etmədən göndərin: python build.py --push-only')
    if fetch:
        git(checkout,'fetch','origin','main')
        if git(checkout,'rev-list','--count','HEAD..origin/main')!='0':
            raise RuntimeError('GitHub-da daha yeni kod var. Əvvəl onu alın, sonra build edin; force push edilmir.')
    return checkout


def allowed(relative):
    relative=Path(relative)
    if any(p in SKIP_DIRS or p.startswith(('tmp','.test','.dev-runtime')) for p in relative.parts):return False
    if relative.name.startswith('.env') or relative.name in SKIP_FILES:return False
    if len(relative.parts)==1:return relative.name in ROOT_FILES
    if relative.parts[0] not in DIRECTORIES:return False
    return relative.suffix.lower() in EXTENSIONS or relative.name in {'requirements.txt','CMakeLists.txt','Caddyfile','.gitignore','.npmrc','jsQR-LICENSE.txt'}


def check_source(path):
    if path.suffix.lower() in {'.png','.ico'}:return
    text=path.read_text(encoding='utf-8-sig')
    if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/]{30}',text):
        raise RuntimeError('Məxfi açar aşkarlanıb; Git export dayandırıldı: '+path.name)
    for match in re.finditer(r'postgres(?:ql)?://[^\s/:]+:[^\s@]+@([^\s/:]+)',text):
        if match.group(1).lower() not in {'localhost','127.0.0.1','pg','test-pg','host','your-host','example.com'}:
            raise RuntimeError('Şifrəli DB URL aşkarlanıb; Git export dayandırıldı: '+path.name)
    if re.search(r'\b(?:ghp_|github_pat_)[A-Za-z0-9_]{30,}',text):
        raise RuntimeError('GitHub token aşkarlanıb; Git export dayandırıldı: '+path.name)


def source_files(root):
    root=Path(root).resolve()
    for parent,dirs,files in os.walk(root,followlinks=False):
        directory=Path(parent)
        dirs[:]=[d for d in dirs if d not in SKIP_DIRS and not d.startswith(('tmp','.test','.dev-runtime'))
            and (directory!=root or d in DIRECTORIES)
            and not (directory/d).is_symlink() and not getattr(directory/d,'is_junction',lambda:False)()]
        for name in files:
            path=directory/name
            relative=path.relative_to(root)
            if allowed(relative) and not path.is_symlink():
                check_source(path)
                yield relative


def verify_package(package):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from deploy.update_repository import PINNED_PUBLIC_KEY
    with zipfile.ZipFile(package) as archive:
        raw=archive.read('manifest.json')
        Ed25519PublicKey.from_public_bytes(PINNED_PUBLIC_KEY).verify(archive.read('manifest.sig'),raw)
        manifest=json.loads(raw)
        names={f['path'] for f in manifest['files']}
        if set(archive.namelist())!=names|{'manifest.json','manifest.sig'}:
            raise RuntimeError('Release ZIP-də manifestdən kənar fayl var.')
        for entry in manifest['files']:
            payload=archive.read(entry['path'])
            if len(payload)!=entry['size'] or hashlib.sha256(payload).hexdigest()!=entry['sha256']:
                raise RuntimeError('Release ZIP bütövlüyü pozulub.')
    if Path(package).stat().st_size > 90*1024*1024:
        raise RuntimeError('Release ZIP Git üçün 90 MiB limitindən böyükdür.')
    return manifest['version']


def prepare_snapshot(root, checkout, package):
    root=Path(root).resolve(); checkout=Path(checkout).resolve()
    candidates=list(source_files(root))  # Validate EVERYTHING before copying/staging.
    for relative in candidates:
        target=checkout/relative
        if root!=checkout:
            if not target.resolve().is_relative_to(checkout) or target.is_symlink():
                raise RuntimeError('Export yolu checkout xaricinə çıxır: '+str(relative))
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(root/relative,target)
    tracked=git(checkout,'ls-files').splitlines()
    removed=[name for name in tracked if allowed(Path(name)) and not (root/name).exists()]
    if removed: git(checkout,'rm','--',*removed)
    local_package=root/PACKAGE_PATH
    local_package.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(package,local_package)
    target=checkout/PACKAGE_PATH
    target.parent.mkdir(parents=True,exist_ok=True)
    if target!=local_package:shutil.copy2(package,target)
    # The only binary exception; never use `git add -f .`.
    ignored=subprocess.run(['git','check-ignore','--stdin','-z'],cwd=checkout,
        input=b'\0'.join(p.as_posix().encode('utf-8') for p in candidates)+b'\0',capture_output=True)
    if ignored.returncode not in (0,1):
        raise RuntimeError('Git ignore qaydaları yoxlanmadı; staging dayandırıldı.')
    ignored_paths={name.decode('utf-8') for name in ignored.stdout.split(b'\0') if name}
    to_add=[p.as_posix() for p in candidates if p.as_posix() not in ignored_paths]
    if ignored_paths:
        print(f'[GIT_IGNORE] {len(ignored_paths)} generated/local file skipped',flush=True)
    if to_add:
        git(checkout,'add','--',*to_add)
        # copy2 may preserve identical coarse Windows mtime/size for changed
        # files. Force content re-reading rather than trusting index stat cache.
        git(checkout,'add','--renormalize','--',*to_add)
    git(checkout,'add','-f','--',PACKAGE_PATH.as_posix())
    staged=git(checkout,'diff','--cached','--name-only').splitlines()
    for name in staged:
        if Path(name)!=PACKAGE_PATH and not allowed(Path(name)):
            raise RuntimeError('Gözlənilməz staged fayl; commit dayandırıldı: '+name)
    whitespace=subprocess.run(['git','diff','--cached','--check'],cwd=checkout,capture_output=True)
    if whitespace.returncode:
        print('[QEYD] Bəzi mənbə fayllarında boşluq formatı qeydləri var; mənbə məzmunu dəyişdirilmədi.',flush=True)
    return staged


def push_release(root, package, resume=False):
    version=verify_package(package)
    checkout=preflight_git(root,allow_pending=resume)
    staged=prepare_snapshot(root,checkout,package)
    if staged:git(checkout,'commit','-m',f'Release WinKey Pro {version}')
    git(checkout,'push','origin','main')
    commit=git(checkout,'rev-parse','--short','HEAD')
    print(f'[GIT_PUSH_OK] main {commit}; Windows release {version}',flush=True)
    print('[VM] Git auto-deploy menbeni ve imzali Windows paketini birlikde goturecek.',flush=True)
    return commit
