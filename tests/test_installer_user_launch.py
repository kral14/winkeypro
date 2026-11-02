"""Guard the setup/UI privilege boundary without installing the service."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallerUserLaunchTests(unittest.TestCase):
    def test_desktop_shortcut_is_user_selected(self):
        source = (ROOT / 'installer/WinKeySetup.nsi').read_text(encoding='utf-8')
        self.assertIn('Page custom ShortcutOptionsPage ShortcutOptionsLeave', source)
        self.assertIn('${NSD_GetState} $DesktopShortcutCheckbox $DesktopShortcutSelected', source)
        shortcut = source.index('CreateShortcut "$DESKTOP')
        self.assertIn('${If} $DesktopShortcutSelected == ${BST_CHECKED}', source[shortcut-100:shortcut])
    def test_finish_delegates_to_desktop_shell(self):
        source = (ROOT / 'installer/WinKeySetup.nsi').read_text(encoding='utf-8')
        launch = source.split('Function LaunchApp', 1)[1].split('FunctionEnd', 1)[0]
        self.assertNotIn('ExecShell "" "$INSTDIR', launch)
        self.assertIn('launch_desktop_user.ps1', launch)
        self.assertIn('RequestExecutionLevel admin', source)

    def test_launcher_uses_desktop_shell_and_fails_closed(self):
        script = (ROOT / 'scripts/launch_desktop_user.ps1').read_text(encoding='utf-8')
        self.assertIn('FindWindowSW', script)
        self.assertIn('.Document.Application', script)
        self.assertIn('.ShellExecute(', script)
        self.assertNotIn('Start-Process', script)
        self.assertIn('exit 1', script)


if __name__ == '__main__':
    unittest.main()
