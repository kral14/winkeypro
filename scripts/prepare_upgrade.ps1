param(
    [Parameter(Mandatory=$true)][string]$InstallDir,
    [string]$DataDir = 'C:\ProgramData\WinKey',
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
try {
    $install = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\') + '\'
    $versions = [IO.Path]::GetFullPath((Join-Path $DataDir 'versions')).TrimEnd('\') + '\'
    if ($install -eq [IO.Path]::GetPathRoot($install) -or $versions -eq [IO.Path]::GetPathRoot($versions)) { throw 'E_UNSAFE_UPGRADE_PATH' }
    function Test-WinKeyBinaryPath([string]$Path) {
        if (-not $Path) { return $false }
        $full = [IO.Path]::GetFullPath($Path)
        return $full.StartsWith($install,[StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($versions,[StringComparison]::OrdinalIgnoreCase)
    }
    $names = @('winkey_desktop.exe','winkey_service.exe','winkey_helper.exe')
    if ($DryRun) {
        Write-Output 'DRY_RUN_UPGRADE_PREP: Stop WinKeyService; wait; close only verified installed/slot binary paths before extraction.'
        exit 0
    }
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'E_ADMIN_REQUIRED' }
    $service = Get-Service -Name WinKeyService -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        Write-Output '[UPGRADE] Stopping WinKeyService before replacing binaries...'
        & sc.exe stop WinKeyService | Out-Null
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(20))
    }
    # Never terminate by image name alone; preserve dev and unrelated copies.
    Get-CimInstance Win32_Process | Where-Object { $names -contains $_.Name.ToLowerInvariant() } | ForEach-Object {
        if (Test-WinKeyBinaryPath $_.ExecutablePath) {
            $process = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
            if ($process -and (Test-WinKeyBinaryPath $process.Path)) {
                Write-Output ('[UPGRADE] Closing installed process PID=' + $process.Id)
                $process.Kill()
                if (-not $process.WaitForExit(10000)) { throw 'E_UPGRADE_PROCESS_STOP_TIMEOUT' }
            }
        }
    }
    Write-Output '[UPGRADE] Installed binaries are stopped; extraction may proceed.'
    exit 0
} catch {
    Write-Output ('[UPGRADE_ERROR] ' + $_.Exception.Message)
    exit 1
}
