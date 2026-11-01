$ErrorActionPreference = 'Continue'
$target = 'C:\ProgramData\WinKey\versions\slot_a\winkey_service.exe'
$report = Join-Path $PSScriptRoot '..\plan\reports\codex\slot_admin_diagnostic.txt'
$lines = @()
$lines += 'Elevated: ' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
try {
    $item = Get-Item -LiteralPath $target -Force -ErrorAction Stop
    $lines += 'File attributes: ' + $item.Attributes
    $acl = Get-Acl -LiteralPath $target -ErrorAction Stop
    $lines += 'Owner: ' + $acl.Owner
    $lines += 'SDDL: ' + $acl.Sddl
} catch { $lines += 'ACL error: ' + $_.Exception.Message }
$lines += 'Matching native processes:'
Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'winkey*' } | ForEach-Object {
    $lines += ('PID={0} Name={1} Path={2}' -f $_.ProcessId,$_.Name,$_.ExecutablePath)
}
try {
    # Open existing file without truncation or writes; distinguish ACL from a running image lock.
    $stream = [System.IO.File]::Open($target, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    $stream.Dispose()
    $lines += 'Write-open probe: OK (no bytes written)'
} catch { $lines += ('Write-open error: HResult=0x{0:X8} Message={1}' -f $_.Exception.HResult,$_.Exception.Message) }
[System.IO.File]::WriteAllLines($report,$lines,[System.Text.UTF8Encoding]::new($false))
