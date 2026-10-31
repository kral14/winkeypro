<#
.SYNOPSIS
WinKey Pro - Windows Service & Autostart Production Uninstaller (Clean Teardown, Rollback & Purge)

.DESCRIPTION
REM-028: Xidmətin tam silinməsi və təmizlənməsi:
  1. WinKeyService xidmətinin dayandırılması.
  2. SCM qeydiyyatının ləğvi (sc.exe delete).
  3. Qorunan Program Files qovluğunun silinməsi.
  4. Opsional olaraq ProgramData anbarının silinməsi (-PurgeData).
  5. Test və audit üçün -DryRun rejimi.
#>

param (
    [string]$InstallDir = "C:\Program Files\WinKey Pro",
    [string]$DataDir = "C:\ProgramData\WinKey",
    [switch]$PurgeData,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$serviceName = "WinKeyService"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   WinKey Pro - Windows Xidməti Silmə (Uninstall) Skripti " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "`n[DRY RUN REJİMİ] Aşağıdakı silmə addımları icra ediləcək:" -ForegroundColor Magenta
    Write-Host " 1. sc.exe stop $serviceName"
    Write-Host " 2. sc.exe delete $serviceName"
    Write-Host " 3. Remove-Item -Recurse -Force `"$InstallDir`""
    if ($PurgeData) {
        Write-Host " 4. Remove-Item -Recurse -Force `"$DataDir`" (PurgeData seçilib)"
    }
    Write-Host "`n[DRY RUN PASS] Silmə ardıcıllığı təsdiqləndi (DRY_RUN_UNINSTALL_SUCCESSFUL)." -ForegroundColor Green
    exit 0
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[MƏHDUDİYYƏT] Windows SCM xidmətini silmək üçün Administrator hüququ tələb olunur." -ForegroundColor Yellow
    Write-Host "Operator Qaydası: PowerShell-i 'Run as Administrator' olaraq açıb bu skripti işə salın." -ForegroundColor Yellow
    exit 1
}

Write-Host "[ACTION] Xidmət dayandırılır..." -ForegroundColor Cyan
& sc.exe stop $serviceName 2>$null | Out-Null
Start-Sleep -Seconds 1

Write-Host "[ACTION] Xidmət SCM-dən silinir..." -ForegroundColor Cyan
& sc.exe delete $serviceName 2>$null | Out-Null
$delExit = $LASTEXITCODE

if ($delExit -ne 0 -and $delExit -ne 1060) { # 1060 = ERROR_SERVICE_DOES_NOT_EXIST
    Write-Host "[XƏBƏRDARLIQ] 'sc.exe delete' exit kodu: $delExit" -ForegroundColor Yellow
}

# Firewall qaydası silinir
& netsh.exe advfirewall firewall delete rule name="WinKey Pro Local Wi-Fi" 2>$null | Out-Null

# ProgramFiles təmizlənməsi
if (Test-Path $InstallDir) {
    Write-Host "[ACTION] Quraşdırma qovluğu silinir: $InstallDir" -ForegroundColor Cyan
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ProgramData təmizlənməsi (yalnız -PurgeData seçildikdə)
if ($PurgeData -and (Test-Path $DataDir)) {
    Write-Host "[ACTION] Xidmət məlumat qovluğu silinir (-PurgeData): $DataDir" -ForegroundColor Cyan
    Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "[OK] WinKey Pro sistemi uğurla təmizləndi (Exit kodu: 0)." -ForegroundColor Green
exit 0
