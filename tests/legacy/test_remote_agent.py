import unittest, tempfile, time
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from legacy.remote_agent import app

class RemoteAgentTests(unittest.TestCase):
 def test_consumed_command_cannot_run_twice(self):
  with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as folder, patch.object(app,'DATA',Path(folder)):
   self.assertTrue(app.consume_command({'id':'one'}))
   self.assertFalse(app.consume_command({'id':'one'}))
 def test_expired_command_does_not_execute(self):
  with patch.object(app,'consume_command') as consume:
   self.assertEqual(app.execute({'id':'old','action':'unlock','expires':0},'example')['status'],'EXPIRED')
   consume.assert_not_called()
 def test_remote_shell_is_rejected(self):
  with patch.object(app,'consume_command') as consume:
   self.assertEqual(app.execute({'id':'bad','action':'shell','expires':time.time()*1000+5000},'example')['status'],'INVALID_ACTION')
   consume.assert_not_called()
 def test_plain_http_endpoint_rejected(self):
  with self.assertRaises(ValueError):app.valid_url('http://example.com')
 def test_credentials_in_url_rejected(self):
  with self.assertRaises(ValueError):app.valid_url('https://user:password@example.com')

class ConfigurationTests(unittest.TestCase):
 def test_explicit_test_directory_is_preserved(self):
  with patch.dict(app.os.environ, {'WINKEY_REMOTE_DATA':str(Path(__file__).resolve().parent / 'test-data')}):
   self.assertEqual(app.user_data_directory(),Path(__file__).resolve().parent / 'test-data')
 def test_windows_known_folder_wins_over_launcher_environment(self):
  def known_folder(window,kind,token,flags,buffer):
   buffer.value=r'C:\Users\Expected\AppData\Local'
   return 0
  with patch.dict(app.os.environ, {'LOCALAPPDATA':r'C:\WrongLauncher'},clear=True), patch.object(app.ctypes.windll.shell32,'SHGetFolderPathW',side_effect=known_folder):
   self.assertEqual(str(app.user_data_directory()),r'C:\Users\Expected\AppData\Local\WinKeyRemote')

class PortableConfigurationTests(unittest.TestCase):
 def test_packaged_app_uses_encrypted_file_beside_exe(self):
  with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
   base=Path(directory)
   (base/'connection.dpapi').write_bytes(b'encrypted-test-placeholder')
   with patch.object(app.sys,'frozen',True,create=True),patch.object(app.sys,'executable',str(base/'WinKeyRemote.exe')):
    self.assertEqual(app.config_path(),base/'connection.dpapi')
 def test_missing_portable_file_falls_back_to_user_settings(self):
  with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
   with patch.object(app.sys,'frozen',True,create=True),patch.object(app.sys,'executable',str(Path(directory)/'WinKeyRemote.exe')):
    self.assertEqual(app.config_path(),app.CONFIG)

class MobileLinkTests(unittest.TestCase):
 def test_pairing_qr_contains_only_device_and_temporary_code(self):
  config={'device_id':'pc-id','pair_code':'ABCDEFGHJKLM','pair_created':time.time(),'paired':False,'pin':'secret-pin','service_key':'service-secret','secret':'device-secret'}
  url=app.mobile_link(config)
  self.assertIn('/mobile?device=pc-id&code=ABCDEFGHJKLM',url)
  for secret in ('secret-pin','service-secret','device-secret'):self.assertNotIn(secret,url)
 def test_paired_qr_omits_pair_code(self):
  url=app.mobile_link({'device_id':'pc-id','paired':True,'pair_code':'ABCDEFGHJKLM','pair_created':time.time()})
  self.assertNotIn('code=',url)
 def test_expired_pair_code_is_not_put_in_qr(self):
  url=app.mobile_link({'device_id':'pc-id','paired':False,'pair_code':'ABCDEFGHJKLM','pair_created':time.time()-601})
  self.assertNotIn('code=',url)
 def test_no_qr_before_registration(self):
  self.assertEqual(app.mobile_link({}),'')

if __name__=='__main__':unittest.main()
