"""Local bare Git only; never pushes to GitHub or deploys a real VM."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import release_pipeline as pipeline


def command(where,*args):
    result=subprocess.run(['git',*args],cwd=where,check=True,capture_output=True,text=True,encoding='utf-8',errors='replace')
    return result.stdout.strip()


class PipelineTest(unittest.TestCase):
    def test_build_snapshot_pushes_source_and_only_dedicated_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary); remote=base/'remote.git'; seed=base/'seed'; root=base/'project'
            remote.mkdir(); seed.mkdir(); root.mkdir()
            command(remote,'init','--bare','--initial-branch=main')
            command(seed,'init','--initial-branch=main')
            command(seed,'config','user.email','local-test@example.invalid')
            command(seed,'config','user.name','Local Release Test')
            (seed/'README.md').write_text('old\n')
            (seed/'.gitignore').write_text('apps/generated.ts\n*.zip\n')
            (seed/'apps').mkdir(); (seed/'apps/deleted.rs').write_text('// old\n')
            command(seed,'add','.'); command(seed,'commit','-m','baseline')
            command(seed,'remote','add','origin',str(remote)); command(seed,'push','origin','main')
            checkout=root/'.github-publish'
            command(base,'clone',str(remote),str(checkout))
            command(checkout,'config','user.email','local-test@example.invalid')
            command(checkout,'config','user.name','Local Release Test')
            (root/'README.md').write_text('new\n')
            (root/'.gitignore').write_text('apps/generated.ts\n*.zip\n')
            (root/'apps').mkdir(); (root/'apps/new.rs').write_text('// new source\n')
            (root/'apps/generated.ts').write_text('// generated file ignored by Git\n')
            (root/'deploy/keys').mkdir(parents=True)
            (root/'deploy/keys/private.bin').write_bytes(b'FAKE_PRIVATE_CANARY')
            (root/'deploy/vm/secrets').mkdir(parents=True)
            (root/'deploy/vm/secrets/admin_key').write_text('FAKE_CANARY')
            (root/'.env').write_text('FAKE_CANARY=1')
            (root/'apps/config.json').write_text('{"pin":"FAKE_CANARY"}')
            (root/'dist').mkdir(); package=root/'dist/update.zip'; package.write_bytes(b'SYNTHETIC_ZIP_FOR_GIT_TRANSPORT')
            # Signature validation is separately exercised against the real signed
            # local build; this test isolates Git transport using a harmless fixture.
            with patch.object(pipeline,'REMOTE',str(remote)),patch.object(pipeline,'verify_package',return_value='9.0.1'):
                commit=pipeline.push_release(root,package)
            files=command(remote,'ls-tree','-r','--name-only','main').splitlines()
            self.assertEqual(set(files),{'.gitignore','README.md','apps/new.rs',pipeline.PACKAGE_PATH.as_posix()})
            self.assertTrue(commit)
            self.assertIn('Release WinKey Pro 9.0.1',command(remote,'log','-1','--format=%s','main'))
            self.assertEqual(command(remote,'show','main:README.md'),'new')

    def test_secret_dsn_stops_source_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); (root/'deploy').mkdir()
            fake_url='postgresql://' + 'sample:FAKE_PASSWORD@invalid.example/db'
            (root/'deploy/example.py').write_text('url="'+fake_url+'"')
            with self.assertRaisesRegex(RuntimeError,'DB URL'):
                list(pipeline.source_files(root))


if __name__=='__main__':unittest.main()
