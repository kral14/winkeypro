# Disposable fixture only; no services or real installation paths are changed.
$ErrorActionPreference = 'Stop'
$folder = Join-Path $PSScriptRoot ('..\plan\reports\codex\acl_fixture_' + [Guid]::NewGuid().ToString('N'))
$report = Join-Path $PSScriptRoot '..\plan\reports\codex\empty_slot_acl_test.txt'
New-Item -ItemType Directory -Path $folder | Out-Null
$file = Join-Path $folder 'fixture.txt'
try {
    [IO.File]::WriteAllText($file, 'original')
    $acl = Get-Acl -LiteralPath $file
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetSecurityDescriptorSddlForm('D:P',[Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $file -AclObject $acl
    $denied = $false
    try { [IO.File]::WriteAllText($file, 'unexpected') } catch { $denied = $true }
    if (-not $denied) { throw 'Fixture did not reproduce empty-DACL write denial' }
    & icacls.exe $file /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'File ACL repair failed' }
    [IO.File]::WriteAllText($file, 'repaired')
    if ([IO.File]::ReadAllText($file) -ne 'repaired') { throw 'Write verification failed' }
    [IO.File]::WriteAllText($report, 'PASS: Empty DACL reproduced; explicit SYSTEM/Admin file ACL restored; actual file overwrite succeeded. No installation/service changes.')
} catch {
    [IO.File]::WriteAllText($report, 'FAIL: ' + $_.Exception.Message)
    throw
} finally {
    # Restore access before removing the disposable fixture, confined to its known folder.
    if (Test-Path -LiteralPath $file) {
        & icacls.exe $file /grant:r '*S-1-5-32-544:F' | Out-Null
        Remove-Item -LiteralPath $file -Force
    }
    Remove-Item -LiteralPath $folder -Force
}
