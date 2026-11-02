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
            } catch {
                Write-Output '[UPGRADE] SCM dayanma müddəti bitdi; yalnız təsdiqlənmiş WinKey prosesləri yoxlanılır.'
            }
        }
    }
    # Never terminate by image name alone; preserve dev and unrelated copies.
    Get-CimInstance Win32_Process | Where-Object { $names -contains $_.Name.ToLowerInvariant() } | ForEach-Object {
        $pPath = $_.ExecutablePath
        if ($pPath -and (Test-WinKeyBinaryPath $pPath)) {
            Write-Output ('[UPGRADE] Quraşdırılmış proses dayandırılır PID=' + $_.ProcessId)
            & taskkill.exe /F /PID $_.ProcessId 2>$null | Out-Null
            $killResult = $LASTEXITCODE
            $remaining = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
            if ($remaining) {
                if ($killResult -ne 0) { throw ('E_UPGRADE_PROCESS_STOP_FAILED: PID=' + $_.ProcessId) }
                $remaining.WaitForExit(5000) | Out-Null
                if (-not $remaining.HasExited) { throw ('E_UPGRADE_PROCESS_EXIT_TIMEOUT: PID=' + $_.ProcessId) }
            }
        }
    }
    # A successful taskkill/SCM request is not proof that the loader released
    # its image. Do not let NSIS overwrite anything until every image is writable.
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $blocked = @()
        foreach ($name in ($names + @('WebView2Loader.dll'))) {
            $file = Join-Path $InstallDir $name
            if (Test-Path -LiteralPath $file -PathType Leaf) {
                try {
                    $stream = [IO.File]::Open($file, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
                    $stream.Dispose()
                } catch { $blocked += $name }
            }
        }
        if ($blocked.Count -eq 0) { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw ('E_UPGRADE_FILES_LOCKED: ' + ($blocked -join ', ')) }
        [System.Threading.Thread]::Sleep(250)
    } while ($true)
    Write-Output '[UPGRADE] Quraşdırılmış proseslər dayandırıldı; faylların çıxarılması davam edə bilər.'
    exit 0
} catch {
    Write-Output ('[UPGRADE_ERROR] ' + $_.Exception.Message)
    exit 1
}
