param(
    [Parameter(Mandatory=$true)][string]$InstallDir,
    [string]$DataDir = 'C:\ProgramData\WinKey',
    [switch]$DryRun,
    [switch]$UnicodeOutput
)

if ($UnicodeOutput) {
    [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
    $OutputEncoding = [System.Text.Encoding]::Unicode
} else {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
}
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
    if ($service) {
        Write-Output '[UPGRADE] SCM avtomatik bərpa parametrləri müvəqqəti dayandırılır...'
        & sc.exe failure WinKeyService reset= 0 actions= "" 2>$null | Out-Null
        if ($service.Status -ne 'Stopped') {
            Write-Output '[UPGRADE] Fayllar yenilənməzdən əvvəl WinKeyService dayandırılır...'
            & sc.exe stop WinKeyService | Out-Null
            try {
                $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15))
            } catch {}
        }
    }
    # Never terminate by image name alone; preserve dev and unrelated copies.
    Get-CimInstance Win32_Process | Where-Object { $names -contains $_.Name.ToLowerInvariant() } | ForEach-Object {
        $pPath = $_.ExecutablePath
        if ((-not $pPath) -or (Test-WinKeyBinaryPath $pPath)) {
            Write-Output ('[UPGRADE] Quraşdırılmış proses dayandırılır PID=' + $_.ProcessId)
            & taskkill.exe /F /PID $_.ProcessId 2>$null | Out-Null
        }
    }
    [System.Threading.Thread]::Sleep(500)
    Write-Output '[UPGRADE] Quraşdırılmış proseslər dayandırıldı; faylların çıxarılması davam edə bilər.'
    exit 0
} catch {
    Write-Output ('[UPGRADE_ERROR] ' + $_.Exception.Message)
    exit 1
}
