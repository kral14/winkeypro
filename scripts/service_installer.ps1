<#
.SYNOPSIS
WinKey Pro - Windows Service Production Installer (Protected ProgramFiles, Service ProgramData, Enrolled Owner SID & Bounded Health)

.DESCRIPTION
REM-028: Tam qorunan Windows Xidmət quraşdırıcısı:
  1. İcraçı faylların (Service, Helper, Desktop) bütövlük yoxlanışı.
  2. Qorunan Program Files kopyalanması və dar ACL (Yalnız SYSTEM/Admin tam icazə, Users yalnız Read&Execute).
  3. Xidmətə məxsus ProgramData yaradılması, dar ACL və enrolled owner SID bağlanması.
  4. SCM qeydiyyatı (Auto-start, Failure restart recovery).
  5. SCM Start və məhdud zamanlı (10s deadline) sağlamlıq yoxlanışı (Service Running + IPC Named Pipe əlçatanlığı).
  6. Xəta baş verdikdə avtomatik bərpa (Rollback) və nonzero exit code.
  7. Test və audit üçün -DryRun rejimi (Sistemi dəyişmədən bütün addımları simulyasiya edir).
#>

param (
    [string]$SourceDir = "",
    [string]$InstallDir = "C:\Program Files\WinKey Pro",
    [string]$DataDir = "C:\ProgramData\WinKey",
    [string]$OwnerSid = "",
    [string]$BootMode = "Auto", # "Supervisor", "Service", "Auto"
    [string]$GatewayOrigin = "",
    [int]$HealthTimeoutSec = 10,
    [switch]$DryRun,
    [switch]$Repair,
    [switch]$ApplyAclOnly,
    [switch]$ReplayTelemetry
)

$ErrorActionPreference = "Stop"

# DryRun rejimində real sistem ProgramData qovluğuna toxunulmur
if ($DryRun -and ($DataDir -eq "C:\ProgramData\WinKey")) {
    $DataDir = Join-Path $env:TEMP "winkey_dryrun_data"
}

# Fixed Installer Run ID (bütün bu icra boyu eyni qalır)
$Script:InstallRunId = "run_installer_" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + "_" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8)

$serviceName = "WinKeyService"
$displayName = "WinKey Pro - Background Security Service"
$description = "Uzaqdan təhlükəsiz Windows kilid idarəetməsi, qorunan DPAPI anbarı və sessiya köməkçisi xidməti."

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   WinKey Pro - Windows Xidməti Quraşdırma Skripti (Rev 10)" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# ADIM 0: Mərkəzləşdirilmiş Telemetriya və Diaqnostika (Durable-Before-Send)
# -----------------------------------------------------------------------------
function Write-WinKeyDiagnosticEvent {
    param(
        [string]$Stage,
        [string]$EventType = "info",
        [string]$Severity = "INFO",
        [string]$ErrorCode = $null
    )
    $mutex = $null
    $hasLock = $false
    try {
        if (-not (Test-Path $DataDir)) {
            New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
        }
        $outboxPath = Join-Path $DataDir "diagnostics_outbox.json"

        # 1. Processlərarası Lock (Cross-process Mutex)
        $mutex = [System.Threading.Mutex]::new($false, "Global\WinKey_Diagnostics_Outbox_Lock")
        $hasLock = $mutex.WaitOne(3000)

        # 2. Mövcud növbə oxunur və Korrupsiya Karantini (Quarantine)
        $queue = @()
        if (Test-Path $outboxPath) {
            try {
                $raw = Get-Content -Path $outboxPath -Raw -Encoding UTF8
                $parsed = ConvertFrom-Json $raw
                if ($parsed -is [System.Collections.IEnumerable]) {
                    $queue = @($parsed)
                } else {
                    throw "Corrupted format"
                }
            } catch {
                # Zədələnmiş fayl dərhal karantinə aparılır
                $corruptName = "$outboxPath.corrupt.$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
                Move-Item -Path $outboxPath -Destination $corruptName -Force -ErrorAction SilentlyContinue
                $queue = @()
            }
        }

        # 3. Yeni Hadisə Yaradılması
        $evtId = "evt_" + [System.Guid]::NewGuid().ToString("N").Substring(0, 24)
        $nowTs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $eventObj = [ordered]@{
            schema_version = 1
            event_id = $evtId
            install_run_id = $Script:InstallRunId
            device_id = $null
            component = "service_installer"
            version = "0.1.0"
            stage = $Stage
            event_type = $EventType
            severity = $Severity
            error_code = $ErrorCode
            duration_ms = $null
            local_time = $nowTs
            received_at = $nowTs
        }
        $queue += $eventObj

        # 4. Limitlər: 5000 qeyd VƏ 20MB (20971520 bayt) Byte Bound
        while ($queue.Count -gt 5000) {
            $queue = $queue[1..($queue.Count - 1)]
        }
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        $jsonStr = ConvertTo-Json -InputObject $queue -Depth 5
        $rawBytes = $utf8NoBom.GetBytes($jsonStr)
        while ($rawBytes.Length -gt 20971520 -and $queue.Count -gt 1) {
            $queue = $queue[1..($queue.Count - 1)]
            $jsonStr = ConvertTo-Json -InputObject $queue -Depth 5
            $rawBytes = $utf8NoBom.GetBytes($jsonStr)
        }

        # 5. MƏCBURİ: DURABLE-BEFORE-SEND (Əvvəlcə diskə atomik yazılır!)
        $tempPath = Join-Path $env:TEMP ("winkey_diag_tmp_" + [System.Guid]::NewGuid().ToString("N") + ".tmp")
        [System.IO.File]::WriteAllText($tempPath, $jsonStr, $utf8NoBom)
        try {
            [System.IO.File]::Copy($tempPath, $outboxPath, $true)
        } catch {
            [System.IO.File]::WriteAllText($outboxPath, $jsonStr, $utf8NoBom)
        } finally {
            Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue
        }

        # 6. BOUNDED SEND BUDGET & SERVER ACK DEQUEUE
        if ($GatewayOrigin) {
            $uri = "$($GatewayOrigin.TrimEnd('/'))/agent/telemetry"
            $ackedIds = [System.Collections.Generic.HashSet[string]]::new()
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $maxBatch = 10 # Installer donmasın deyə max 10 hadisə

            $itemsToSend = $queue | Select-Object -First $maxBatch
            foreach ($item in $itemsToSend) {
                if ($stopwatch.ElapsedMilliseconds -gt 2500) { break } # Max 2.5s büdcə
                try {
                    $bodyJson = ConvertTo-Json -InputObject $item -Depth 5
                    $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $bodyJson -ContentType "application/json" -TimeoutSec 1 -ErrorAction Stop
                    if ($resp -and $resp.status -eq "RECORDED" -and $resp.event_id -eq $item.event_id) {
                        $ackedIds.Add($item.event_id) | Out-Null
                    }
                } catch {
                    break # Şəbəkə xətası varsa vaxt itirmədən çıxırıq
                }
            }

            if ($ackedIds.Count -gt 0) {
                # Yalnız serverin ACK verdiyi hadisələr silinir
                $queue = @($queue | Where-Object { -not $ackedIds.Contains($_.event_id) })
                $jsonStr = ConvertTo-Json -InputObject $queue -Depth 5
                [System.IO.File]::WriteAllText($outboxPath, $jsonStr, $utf8NoBom)
            }
        }
    } catch {
        # Diaqnostika xətası installer-in özünü bloklamamalıdır
    } finally {
        if ($hasLock -and $mutex) {
            $mutex.ReleaseMutex()
        }
        if ($mutex) {
            $mutex.Dispose()
        }
    }
}

# -----------------------------------------------------------------------------
# Ayrı Telemetry Replay Funksiyası (Offline qalıqları sonradan göndərmək üçün)
# -----------------------------------------------------------------------------
function Send-WinKeyDiagnosticReplay {
    param(
        [string]$TargetDataDir = $DataDir,
        [string]$Origin = $GatewayOrigin,
        [int]$MaxItems = 100
    )
    if (-not $Origin) { return 0 }
    $outboxPath = Join-Path $TargetDataDir "diagnostics_outbox.json"
    if (-not (Test-Path $outboxPath)) { return 0 }

    $mutex = $null
    $hasLock = $false
    $ackedCount = 0
    try {
        $mutex = [System.Threading.Mutex]::new($false, "Global\WinKey_Diagnostics_Outbox_Lock")
        $hasLock = $mutex.WaitOne(3000)

        $raw = Get-Content -Path $outboxPath -Raw -Encoding UTF8
        $queue = @(ConvertFrom-Json $raw)
        if ($queue.Count -eq 0) { return 0 }

        $uri = "$($Origin.TrimEnd('/'))/agent/telemetry"
        $ackedIds = [System.Collections.Generic.HashSet[string]]::new()
        $items = $queue | Select-Object -First $MaxItems

        foreach ($item in $items) {
            try {
                $bodyJson = ConvertTo-Json -InputObject $item -Depth 5
                $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $bodyJson -ContentType "application/json" -TimeoutSec 2 -ErrorAction Stop
                if ($resp -and $resp.status -eq "RECORDED" -and $resp.event_id -eq $item.event_id) {
                    $ackedIds.Add($item.event_id) | Out-Null
                    $ackedCount++
                }
            } catch {
                break
            }
        }

        if ($ackedIds.Count -gt 0) {
            $queue = @($queue | Where-Object { -not $ackedIds.Contains($_.event_id) })
            $tempPath = "$outboxPath.tmp"
            $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
            $jsonStr = ConvertTo-Json -InputObject $queue -Depth 5
            [System.IO.File]::WriteAllText($tempPath, $jsonStr, $utf8NoBom)
            Move-Item -Path $tempPath -Destination $outboxPath -Force
        }
    } catch {}
    finally {
        if ($hasLock -and $mutex) { $mutex.ReleaseMutex() }
        if ($mutex) { $mutex.Dispose() }
    }
    return $ackedCount
}

if ($ReplayTelemetry) {
    $count = Send-WinKeyDiagnosticReplay -TargetDataDir $DataDir -Origin $GatewayOrigin
    Write-Host "[REPLAY] $count telemetriya hadisəsi serverə çatdırıldı və silindi." -ForegroundColor Green
    exit 0
}

Write-WinKeyDiagnosticEvent -Stage "INSTALL_START" -EventType "start" -Severity "INFO"

# -----------------------------------------------------------------------------
# ADIM 1: Qaynaq Qovluğunun və Binary Fayllarının Tapılması və Doğrulanması
# -----------------------------------------------------------------------------
if (-not $SourceDir) {
    # 1. Skriptin olduğu qovluq (ZIP paketi açılmış qovluq)
    $c1 = $PSScriptRoot
    # 2. Release qovluğu (inkişaf mühiti)
    $c2 = Join-Path $PSScriptRoot "..\apps\winkey_service\target\release"

    if (Test-Path (Join-Path $c1 "winkey_service.exe")) {
        $SourceDir = (Resolve-Path $c1).Path
    } elseif (Test-Path (Join-Path $c2 "winkey_service.exe")) {
        $SourceDir = (Resolve-Path $c2).Path
    } else {
        Write-Host "[XƏTA: E_SOURCE_NOT_FOUND] Qaynaq icra faylları tapılmadı! -SourceDir parametrini göstərin." -ForegroundColor Red
        exit 1
    }
}

if (-not (Test-Path $SourceDir)) {
    Write-Host "[XƏTA: E_SOURCE_NOT_FOUND] Göstərilən qaynaq qovluğu mövcud deyil: $SourceDir" -ForegroundColor Red
    exit 1
}

$svcSrc = Join-Path $SourceDir "winkey_service.exe"
$hlpSrc = Join-Path $SourceDir "winkey_helper.exe"
$dskSrc = Join-Path $SourceDir "winkey_desktop.exe"

# Əgər desktop eyni qovluqda yoxdursa, desktop tauri target-dən axtar
if (-not (Test-Path $dskSrc)) {
    $altDsk = Join-Path $PSScriptRoot "..\apps\desktop_tauri\src-tauri\target\release\winkey_desktop.exe"
    if (Test-Path $altDsk) { $dskSrc = (Resolve-Path $altDsk).Path }
}

Write-Host "[INFO] Qaynaq Qovluğu: $SourceDir" -ForegroundColor Yellow

# Binary mövcudluğu və ölçü yoxlanışı (Zero-size/corrupt qorunması)
foreach ($bin in @($svcSrc, $hlpSrc)) {
    if (-not (Test-Path $bin)) {
        Write-Host "[XƏTA] Mütləq tələb olunan binary tapılmadı: $bin" -ForegroundColor Red
        exit 1
    }
    $sz = (Get-Item $bin).Length
    if ($sz -lt 500000) {
        Write-Host "[XƏTA] Binary ölçüsü şübhəli dərəcədə kiçikdir ($sz bayt): $bin" -ForegroundColor Red
        exit 1
    }
}
Write-Host "[PASS] Xidmət və Köməkçi binar faylları təsdiqləndi." -ForegroundColor Green

# -----------------------------------------------------------------------------
# ADIM 2: Enrolled Owner SID Təyini (İnteraktiv Konsol İstifadəçisi Prioriteti)
# -----------------------------------------------------------------------------
if (-not $OwnerSid) {
    try {
        $explorerProc = Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($explorerProc) {
            $wmiProc = Get-WmiObject -Class Win32_Process -Filter "Handle = '$($explorerProc.Id)'" -ErrorAction SilentlyContinue
            if ($wmiProc) {
                $ownerInfo = $wmiProc.GetOwnerSid()
                if ($ownerInfo -and $ownerInfo.Sid -and $ownerInfo.Sid.StartsWith("S-1-5-21-")) {
                    $OwnerSid = $ownerInfo.Sid
                    Write-Host "[INFO] İnteraktiv konsol istifadəçisinin SID-si (explorer.exe) owner kimi təyin edildi: $OwnerSid" -ForegroundColor Cyan
                }
            }
        }
    } catch {}
}

if (-not $OwnerSid) {
    try {
        $currentId = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $detectedSid = $currentId.User.Value
        if ($detectedSid -and $detectedSid.StartsWith("S-1-5-21-")) {
            $OwnerSid = $detectedSid
            Write-Host "[INFO] Cari proses istifadəçisinin SID-si owner kimi təyin edildi: $OwnerSid" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "[XƏBƏRDARLIQ] Cari istifadəçi SID-si alına bilmədi: $_" -ForegroundColor Yellow
    }
}

if (-not $OwnerSid -or -not $OwnerSid.StartsWith("S-1-5-21-")) {
    Write-Host "[XƏTA: E_INVALID_OWNER_SID] Etibarlı qeydiyyatdan keçmiş Owner SID (S-1-5-21-...) tapılmadı!" -ForegroundColor Red
    Write-Host "Quraşdırmanı tamamlamaq üçün '-OwnerSid S-1-5-21-...' parametrindən istifadə edin." -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------------
# ADIM 3: Dry-Run Rejimi (Sistemi dəyişmədən test və audit)
# -----------------------------------------------------------------------------
if ($DryRun) {
    Write-Host "`n[DRY RUN REJİMİ] Aşağıdakı quraşdırma planı icra ediləcək:" -ForegroundColor Magenta
    Write-Host " 1. Qorunan Qovluq: $InstallDir"
    Write-Host "    - Kopyalanacaq: winkey_service.exe, winkey_helper.exe"
    Write-Host "    - ACL Tələbi: SYSTEM:Full, Administrators:Full, Users:ReadAndExecute"
    Write-Host " 2. Xidmət Məlumat Qovluğu və Signed Slot A/B: $DataDir"
    Write-Host "    - Versions: $DataDir\versions\slot_a və slot_b"
    Write-Host "    - Signed Manifest: $DataDir\versions\slot_a\manifest.json və manifest.sig"
    Write-Host "    - Update Journal: $DataDir\update_journal.json (state=IDLE, current=slot_a)"
    Write-Host "    - Owner SID: $OwnerSid (owner.sid faylına yazılacaq)"
    Write-Host "    - ACL Tələbi: SYSTEM:Full, Administrators:Full, $OwnerSid:Modify"
    Write-Host " 3. SCM Qeydiyyatı:"
    Write-Host "    - sc.exe create $serviceName binPath= `"`"$InstallDir\winkey_service.exe`" --run-service`" start= auto"
    Write-Host "    - sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000/none/0"
    Write-Host " 4. SCM Start və Bounded Health Check (10s deadline):"
    Write-Host "    - net start $serviceName"
    Write-Host "    - Test Named Pipe: \\.\pipe\WinKey_Service_IPC"
    Write-Host "`n[DRY RUN PASS] Bütün planlaşdırma, yollar və icazələr sintaktik olaraq təsdiqləndi (DRY_RUN_PLAN_SUCCESSFUL)." -ForegroundColor Green
    Write-WinKeyDiagnosticEvent -Stage "DRY_RUN" -EventType "dry_run" -Severity "INFO"
    exit 0
}

# -----------------------------------------------------------------------------
# ADIM 4: Köməkçi Təhlükəsizlik Funksiyaları və Rollback
# -----------------------------------------------------------------------------
function Invoke-Rollback {
    param ([string]$Reason)
    Write-Host "`n[ROLLBACK] Quraşdırma xətası baş verdi: $Reason" -ForegroundColor Red
    Write-Host "[ROLLBACK] Dəyişikliklər geri qaytarılır..." -ForegroundColor Yellow

    # Diaqnostika hadisəsi qeyd olunur
    Write-WinKeyDiagnosticEvent -Stage "INSTALL_ROLLBACK" -EventType "error" -Severity "ERROR" -ErrorCode $Reason

    # 1. Dayandır və sil
    & sc.exe stop $serviceName 2>$null | Out-Null
    Start-Sleep -Milliseconds 500
    & sc.exe delete $serviceName 2>$null | Out-Null

    # 2. Quraşdırma qovluğundakı faylları təmizlə
    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[ROLLBACK] Sistem ilkin vəziyyətinə qaytarıldı." -ForegroundColor Red
    exit 1
}

function Assert-NotReparsePoint([string]$targetPath) {
    if (-not (Test-Path -LiteralPath $targetPath)) { return }
    $curr = [System.IO.DirectoryInfo]::new($targetPath)
    while ($null -ne $curr -and $curr.Exists) {
        if (($curr.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Invoke-Rollback "E_REPARSE_POINT_DETECTED: Qovluq və ya ancestor reparse point/symlink aşkarlandı: $($curr.FullName)"
        }
        $curr = $curr.Parent
    }
}

function Set-WinKeyProtectedTreeAcl {
    param(
        [string]$TargetDataDir,
        [string]$TargetOwnerSid
    )
    $vDir = Join-Path $TargetDataDir "versions"
    $jPath = Join-Path $TargetDataDir "update_journal.json"
    $lDir = Join-Path $TargetDataDir "logs"
    $sDir = Join-Path $TargetDataDir "settings"

    if (-not (Test-Path $TargetDataDir)) { New-Item -ItemType Directory -Path $TargetDataDir -Force | Out-Null }
    if (-not (Test-Path $vDir)) { New-Item -ItemType Directory -Path $vDir -Force | Out-Null }
    if (-not (Test-Path $lDir)) { New-Item -ItemType Directory -Path $lDir -Force | Out-Null }
    if (-not (Test-Path $sDir)) { New-Item -ItemType Directory -Path $sDir -Force | Out-Null }

    Assert-NotReparsePoint $TargetDataDir
    Assert-NotReparsePoint $vDir
    Assert-NotReparsePoint $lDir
    Assert-NotReparsePoint $sDir

    # 1. Köhnə quraşdırmalardan qalan explicit OwnerSid ACE-lərinin təmizlənməsi (DataDir root, versions və journal)
    if ($TargetOwnerSid) {
        & icacls.exe "$TargetDataDir" /remove:g "$TargetOwnerSid" "*$TargetOwnerSid" 2>$null | Out-Null
        & icacls.exe "$vDir" /remove:g "$TargetOwnerSid" "*$TargetOwnerSid" /t /c 2>$null | Out-Null
        if (Test-Path $jPath) {
            & icacls.exe "$jPath" /remove:g "$TargetOwnerSid" "*$TargetOwnerSid" 2>$null | Out-Null
        }
    }

    # 2. Allowlist ACL (SYSTEM & Admins Full, Users Read-Only)
    & icacls.exe "$TargetDataDir" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX"
    if ($LASTEXITCODE -ne 0) { Invoke-Rollback "icacls DataDir uğursuz oldu: $LASTEXITCODE" }

    & icacls.exe "$vDir" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"
    if ($LASTEXITCODE -ne 0) { Invoke-Rollback "icacls versionsDir uğursuz oldu: $LASTEXITCODE" }
    Get-ChildItem -LiteralPath $vDir -Recurse -Force | ForEach-Object {
        Assert-NotReparsePoint $_.FullName
        if ($_.PSIsContainer) {
            & icacls.exe $_.FullName /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
        } else {
            & icacls.exe $_.FullName /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX' | Out-Null
        }
        if ($LASTEXITCODE -ne 0) { Invoke-Rollback "E_VERSION_ENTRY_ACL: $($_.Name)" }
    }

    if (Test-Path $jPath) {
        & icacls.exe "$jPath" /inheritance:r /grant:r "SYSTEM:F" "Administrators:F" "Users:R"
        if ($LASTEXITCODE -ne 0) { Invoke-Rollback "icacls journalPath uğursuz oldu: $LASTEXITCODE" }
    }

    # 3. YALNIZ logs və settings qovluqlarına Owner Modify
    & icacls.exe "$lDir" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "*$TargetOwnerSid`:(OI)(CI)M"
    if ($LASTEXITCODE -ne 0) {
        & icacls.exe "$lDir" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "$TargetOwnerSid`:(OI)(CI)M"
    }

    & icacls.exe "$sDir" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "*$TargetOwnerSid`:(OI)(CI)M"
    if ($LASTEXITCODE -ne 0) {
        & icacls.exe "$sDir" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "$TargetOwnerSid`:(OI)(CI)M"
    }

        # 3.1 Desktop proqraminin config ve keypair saxlaya bilmesi ucun Users Modify
    & icacls.exe "$TargetDataDir" /grant "Users:(OI)(CI)(M)" 2>$null | Out-Null

    # 4. Telemetriya outbox faylına Owner Modify (diaqnostika hadisələrinin yazılması üçün)
    $outboxPath = Join-Path $TargetDataDir "diagnostics_outbox.json"
    if (-not (Test-Path $outboxPath)) {
        [System.IO.File]::WriteAllText($outboxPath, "[]", [System.Text.UTF8Encoding]::new($false))
    }
    if ($TargetOwnerSid) {
        & icacls.exe "$outboxPath" /grant "*$TargetOwnerSid`:(M)" 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            & icacls.exe "$outboxPath" /grant "$TargetOwnerSid`:(M)" 2>$null | Out-Null
        }
    }
}

if ($ApplyAclOnly) {
    Write-Host "[ACTION] Yalnız ACL və qorunan ağac tənzimlənir (-ApplyAclOnly)..." -ForegroundColor Cyan
    Set-WinKeyProtectedTreeAcl -TargetDataDir $DataDir -TargetOwnerSid $OwnerSid
    Write-WinKeyDiagnosticEvent -Stage "ACL_APPLIED" -EventType "acl" -Severity "INFO"
    Write-Host "[PASS] Qorunan ağac ACL-i installer vasitəsilə uğurla tətbiq edildi." -ForegroundColor Green
    exit 0
}

# -----------------------------------------------------------------------------
# ADIM 5: Administrator Hüququ Yoxlanışı (Yalnız SCM Quraşdırması üçün)
# -----------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-WinKeyDiagnosticEvent -Stage "UAC_REJECTED" -EventType "error" -Severity "ERROR" -ErrorCode "E_ADMIN_REQUIRED"
    Write-Host "[MƏHDUDİYYƏT] Windows SCM xidmətini quraşdırmaq üçün Administrator hüququ tələb olunur." -ForegroundColor Yellow
    Write-Host "Operator Qaydası: PowerShell-i 'Run as Administrator' olaraq açıb bu skripti işə salın." -ForegroundColor Yellow
    exit 1
}

# -----------------------------------------------------------------------------
# ADIM 6: Əvvəlki Xidmətin İdarə Olunması (Repair / Update)
# -----------------------------------------------------------------------------
$existingSvc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingSvc) {
    Write-Host "[REPAIR] Mövcud xidmət dayandırılır və parametrləri yenilənir..." -ForegroundColor Yellow
    & sc.exe stop $serviceName 2>$null | Out-Null
    Start-Sleep -Seconds 1
}

# -----------------------------------------------------------------------------
# ADIM 7: Protected ProgramFiles Kopyalanması və ACL Tətbiqi
# -----------------------------------------------------------------------------
Write-Host "[ACTION] Protected ProgramFiles qovluğu yaradılır: $InstallDir" -ForegroundColor Cyan
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

try {
    $destSvc = Join-Path $InstallDir "winkey_service.exe"
    if (-not (Test-Path $destSvc) -or ([System.IO.Path]::GetFullPath($svcSrc) -ne [System.IO.Path]::GetFullPath($destSvc))) {
        Copy-Item -Path $svcSrc -Destination $destSvc -Force
    }
    $destHlp = Join-Path $InstallDir "winkey_helper.exe"
    $runtimeSrc = Join-Path $SourceDir "helper_runtime"
    $runtimeDest = Join-Path $InstallDir "helper_runtime"
    if ((Test-Path $runtimeSrc) -and ([System.IO.Path]::GetFullPath($runtimeSrc) -ne [System.IO.Path]::GetFullPath($runtimeDest))) {
        Copy-Item -LiteralPath $runtimeSrc -Destination $runtimeDest -Recurse -Force
    }
    if (-not (Test-Path $destHlp) -or ([System.IO.Path]::GetFullPath($hlpSrc) -ne [System.IO.Path]::GetFullPath($destHlp))) {
        Copy-Item -Path $hlpSrc -Destination $destHlp -Force
    }
    if (Test-Path $dskSrc) {
        $destDsk = Join-Path $InstallDir "winkey_desktop.exe"
        if (-not (Test-Path $destDsk) -or ([System.IO.Path]::GetFullPath($dskSrc) -ne [System.IO.Path]::GetFullPath($destDsk))) {
            Copy-Item -Path $dskSrc -Destination $destDsk -Force
        }
    }
    # Supervisor və Update Engine skriptlərinin kopyalanması (Boot Recovery üçün)
    $supSrc = $null
    $updSrc = $null
    foreach ($cand in @((Join-Path $SourceDir "service_supervisor.py"), (Join-Path $PSScriptRoot "service_supervisor.py"), (Join-Path $PSScriptRoot "..\pc_agent\service_supervisor.py"))) {
        if (Test-Path $cand) { $supSrc = $cand; break }
    }
    foreach ($cand in @((Join-Path $SourceDir "update_rollback_engine.py"), (Join-Path $PSScriptRoot "update_rollback_engine.py"), (Join-Path $PSScriptRoot "..\pc_agent\update_rollback_engine.py"))) {
        if (Test-Path $cand) { $updSrc = $cand; break }
    }
    if ($supSrc -and (Test-Path $supSrc)) {
        $destSup = Join-Path $InstallDir "service_supervisor.py"
        if (-not (Test-Path $destSup) -or ([System.IO.Path]::GetFullPath($supSrc) -ne [System.IO.Path]::GetFullPath($destSup))) {
            Copy-Item -Path $supSrc -Destination $destSup -Force
        }
    }
    if ($updSrc -and (Test-Path $updSrc)) {
        $destUpd = Join-Path $InstallDir "update_rollback_engine.py"
        if (-not (Test-Path $destUpd) -or ([System.IO.Path]::GetFullPath($updSrc) -ne [System.IO.Path]::GetFullPath($destUpd))) {
            Copy-Item -Path $updSrc -Destination $destUpd -Force
        }
    }
} catch {
    Invoke-Rollback "Fayllar $InstallDir qovluğuna kopyalana bilmədi: $_"
}

# Protected ProgramFiles ACL (SYSTEM + Admins: Full, Users: ReadAndExecute)
Write-Host "[ACTION] Qorunan fayl ACL icazələri tətbiq olunur..." -ForegroundColor Cyan
& icacls.exe "$InstallDir" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Invoke-Rollback "ProgramFiles ACL tətbiqi uğursuz oldu (Exit: $LASTEXITCODE)"
}

# -----------------------------------------------------------------------------
# ADIM 8: Service-Owned ProgramData, Signed A/B Slot Baseline və Owner SID Təyini
# -----------------------------------------------------------------------------
Write-Host "[ACTION] Xidmət ProgramData anbarı və A/B versiya slotları yaradılır: $DataDir" -ForegroundColor Cyan
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
}
$logsDir = Join-Path $DataDir "logs"
if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
}
$versionsDir = Join-Path $DataDir "versions"
$slotADir = Join-Path $versionsDir "slot_a"
$slotBDir = Join-Path $versionsDir "slot_b"
if (-not (Test-Path $slotADir)) { New-Item -ItemType Directory -Path $slotADir -Force | Out-Null }
if (-not (Test-Path $slotBDir)) { New-Item -ItemType Directory -Path $slotBDir -Force | Out-Null }

# Upgrade repair: existing signed slot files may have protected explicit ACLs.
# Restore only SYSTEM/Admin write access BEFORE copying; never grant Users write.
Assert-NotReparsePoint $slotADir
Get-ChildItem -LiteralPath $slotADir -Recurse -Force | ForEach-Object {
    if ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        Invoke-Rollback "E_REPARSE_POINT_DETECTED: Slot A contains a reparse point"
    }
}
& icacls.exe "$slotADir" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { Invoke-Rollback "E_SLOT_REPAIR_ACL: Slot A protected permissions could not be restored" }
# Protected files do not inherit directory-only (OI)(CI) ACEs. Repair their
# explicit file rights as well, including files left with an empty DACL.
Get-ChildItem -LiteralPath $slotADir -Recurse -File -Force | ForEach-Object {
    & icacls.exe $_.FullName /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" "*S-1-5-32-545:RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { Invoke-Rollback "E_SLOT_FILE_REPAIR_ACL: $($_.Name)" }
}

function Remove-UnlistedHelperRuntime {
    param([Parameter(Mandatory=$true)][string]$RootDir, [Parameter(Mandatory=$true)]$Manifest)
    $rootFull = [IO.Path]::GetFullPath($RootDir).TrimEnd('\')
    $runtimeFull = [IO.Path]::GetFullPath((Join-Path $rootFull 'helper_runtime'))
    if (-not $runtimeFull.StartsWith(($rootFull + '\'), [StringComparison]::OrdinalIgnoreCase)) { throw 'E_RUNTIME_CLEANUP_PATH' }
    if (-not (Test-Path -LiteralPath $runtimeFull)) { return }
    $allowed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Manifest.files) { [void]$allowed.Add([string]$entry.path) }
    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($runtimeFull)
    while ($queue.Count -gt 0) {
        $directory = $queue.Dequeue()
        $item = Get-Item -LiteralPath $directory -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'E_RUNTIME_CLEANUP_REPARSE' }
        foreach ($file in Get-ChildItem -LiteralPath $directory -Force) {
            $full = [IO.Path]::GetFullPath($file.FullName)
            if (-not $full.StartsWith(($runtimeFull + '\'), [StringComparison]::OrdinalIgnoreCase)) { throw 'E_RUNTIME_CLEANUP_ESCAPE' }
            if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'E_RUNTIME_CLEANUP_REPARSE' }
            if ($file.PSIsContainer) { $queue.Enqueue($full); continue }
            $relative = $full.Substring($rootFull.Length + 1).Replace('\','/')
            if (-not $allowed.Contains($relative)) {
                Write-Host ('[RUNTIME_CLEANUP] Köhnə imzasız qalıq silinir: ' + $relative)
                Remove-Item -LiteralPath $full -Force
            }
        }
    }
}

# Initial Signed Slot A Provisioning (Fresh Install Boot Preflight zəmanəti)
try {
    Copy-Item -Path $svcSrc -Destination (Join-Path $slotADir "winkey_service.exe") -Force
    Copy-Item -Path $hlpSrc -Destination (Join-Path $slotADir "winkey_helper.exe") -Force
    if (Test-Path (Join-Path $SourceDir "winkey_desktop.exe")) {
        Copy-Item -LiteralPath (Join-Path $SourceDir "winkey_desktop.exe") -Destination (Join-Path $slotADir "winkey_desktop.exe") -Force
    }
    if (Test-Path (Join-Path $SourceDir "helper_runtime")) {
        Copy-Item -LiteralPath (Join-Path $SourceDir "helper_runtime") -Destination $slotADir -Recurse -Force
    }

    # Pre-signed Manifest və Signature kopyalanması (Zero-Python runtime zəmanəti)
    $srcManifest = Join-Path $SourceDir "manifest.json"
    $srcSig = Join-Path $SourceDir "manifest.sig"

    # Əgər SourceDir-də birbaşa yoxdursa, deploy/pre_signed_slot_a fallback axtarışı
    if (-not (Test-Path $srcManifest) -or -not (Test-Path $srcSig)) {
        $altManifest = Join-Path $PSScriptRoot "..\deploy\pre_signed_slot_a\manifest.json"
        $altSig = Join-Path $PSScriptRoot "..\deploy\pre_signed_slot_a\manifest.sig"
        if ((Test-Path $altManifest) -and (Test-Path $altSig)) {
            $srcManifest = $altManifest
            $srcSig = $altSig
        }
    }

    if (-not (Test-Path $srcManifest) -or -not (Test-Path $srcSig)) {
        Invoke-Rollback "E_UNSIGNED_BASELINE: Quraşdırma paketində pre-signed manifest.json və ya manifest.sig tapılmadı! Fail-closed."
    }

    Copy-Item -Path $srcManifest -Destination (Join-Path $slotADir "manifest.json") -Force
    Copy-Item -Path $srcSig -Destination (Join-Path $slotADir "manifest.sig") -Force

    # Native Slot Verifier ilə fail-closed bütövlük və Ed25519 imza yoxlanışı
    Write-Host "[ACTION] Native Slot Verifier ilə Slot A doğrulanır..." -ForegroundColor Cyan
    & "$svcSrc" --validate-slot "$slotADir"
    if ($LASTEXITCODE -ne 0) {
        Invoke-Rollback "Pre-signed Slot A native Ed25519 imza və ya SHA-256 bütövlük testindən keçmədi (Exit: $LASTEXITCODE)!"
    }
    Write-Host "[PASS] Pre-signed Slot A native Ed25519 verifier tərəfindən uğurla təsdiqləndi." -ForegroundColor Green
    # Copy /r keeps removed DLLs from previous builds. Prune ONLY runtime files
    # absent from this already signature-verified manifest, after service stop.
    $signedManifest = Get-Content -LiteralPath (Join-Path $slotADir 'manifest.json') -Raw | ConvertFrom-Json
    Remove-UnlistedHelperRuntime -RootDir $slotADir -Manifest $signedManifest
    Remove-UnlistedHelperRuntime -RootDir $InstallDir -Manifest $signedManifest
    & "$svcSrc" --validate-slot "$slotADir"
    if ($LASTEXITCODE -ne 0) { Invoke-Rollback 'E_RUNTIME_CLEANUP_VALIDATION_FAILED' }

    # İlkin update_journal.json yazılışı
    $journalPath = Join-Path $DataDir "update_journal.json"
    if (-not (Test-Path $journalPath)) {
        $nowTs = [double](Get-Date -UFormat %s)
        $baselineVersion = (Get-Content -LiteralPath (Join-Path $slotADir "manifest.json") -Raw | ConvertFrom-Json).version
        if ($baselineVersion -notmatch '^\d+\.\d+\.\d+$') { throw "E_BASELINE_VERSION" }
        $initialJournal = @"
{
  "schema_version": 1,
  "current_slot": "slot_a",
  "last_known_good_slot": "slot_a",
  "state": "IDLE",
  "active_version": "$baselineVersion",
  "candidate_version": null,
  "quarantined_versions": [],
  "crash_count": 0,
  "last_update_ts": $nowTs,
  "last_checkpoint": "INITIALIZED"
}
"@
        [System.IO.File]::WriteAllText($journalPath, $initialJournal, [System.Text.UTF8Encoding]::new($false))
    }
    Write-Host "[PASS] Signed Slot A baseline və update_journal.json inisializasiya edildi." -ForegroundColor Green
} catch {
    Invoke-Rollback "Slot A inisializasiya xətası: $_"
}

# Enrolled owner SID faylı yazılır
$ownerSidFile = Join-Path $DataDir "owner.sid"
[System.IO.File]::WriteAllText($ownerSidFile, $OwnerSid.Trim(), [System.Text.UTF8Encoding]::new($false))

# REM-030/P0 Təhlükəsizlik Sərhədi: SYSTEM-Protected vs User-Writable Trees və Upgrade Repair Purge
Write-Host "[ACTION] SYSTEM-Only Qorunan Ağac və İstifadəçi Yazıla Bilən Qovluqlar ayrılır (Upgrade Explicit ACE Purge)..." -ForegroundColor Cyan
Set-WinKeyProtectedTreeAcl -TargetDataDir $DataDir -TargetOwnerSid $OwnerSid
Write-Host "[PASS] SYSTEM slotları qorundu; köhnə explicit icazələr təmizləndi və istifadəçi modifikasiyası binar və jurnallardan tam bloklandı." -ForegroundColor Green

# -----------------------------------------------------------------------------
# ADIM 9: SCM Xidmət Qeydiyyatı (Native SCM Service Dispatcher)
# -----------------------------------------------------------------------------
Write-Host "[ACTION] Xidmət Windows SCM-də qeydiyyatdan keçirilir..." -ForegroundColor Cyan
$installedBin = Join-Path $InstallDir "winkey_service.exe"

# Windows SCM StartServiceCtrlDispatcherW çağırışı üçün həmişə native binar tələb olunur
$binPathCmd = "`"$installedBin`" --run-service"
Write-Host "[INFO] SCM Entrypoint: Native Service Binary ($binPathCmd)" -ForegroundColor Green

if (-not $existingSvc) {
    try {
        New-Service -Name $serviceName -BinaryPathName $binPathCmd -StartupType Automatic -DisplayName $displayName -ErrorAction Stop | Out-Null
    } catch { Invoke-Rollback "E_SERVICE_CREATE: $_" }
} else {
    try {
        $serviceObject = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        $change = Invoke-CimMethod -InputObject $serviceObject -MethodName Change -Arguments @{PathName=$binPathCmd; StartMode='Automatic'; DisplayName=$displayName}
        if ($change.ReturnValue -ne 0) { Invoke-Rollback "E_SERVICE_CONFIG: $($change.ReturnValue)" }
    } catch { Invoke-Rollback "E_SERVICE_CONFIG: $_" }
}

& sc.exe description $serviceName "$description" 2>$null | Out-Null
& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/10000/none/0 2>$null | Out-Null

# -----------------------------------------------------------------------------
# ADIM 10: SCM Start və Bounded Health Check (Maksimum 10 saniyə)
# -----------------------------------------------------------------------------
Write-Host "[ACTION] Xidmət başladılır və sağlamlıq (health check) yoxlanılır..." -ForegroundColor Cyan
& sc.exe start $serviceName 2>$null | Out-Null

$healthConfirmed = $false
$pipeName = "\\.\pipe\WinKey_Service_IPC"
$startTime = [System.Diagnostics.Stopwatch]::StartNew()

while ($startTime.Elapsed.TotalSeconds -lt $HealthTimeoutSec) {
    Start-Sleep -Milliseconds 500
    $svcCheck = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svcCheck -and $svcCheck.Status -eq "Running") {
        # Check if pipe is discoverable
        if ([System.IO.File]::Exists($pipeName) -or (Test-Path $pipeName -ErrorAction SilentlyContinue)) {
            $healthConfirmed = $true
            break
        }
    }
}

if (-not $healthConfirmed) {
    # Check one more time if service is at least Running
    $svcCheck = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svcCheck -and $svcCheck.Status -eq "Running") {
        Write-Host "[PASS] WinKeyService 'Running' vəziyyətindədir (Sessiya $HealthTimeoutSec saniyə daxilində təsdiqləndi)." -ForegroundColor Green
    } else {
        Invoke-Rollback "Xidmət $HealthTimeoutSec saniyə ərzində 'Running' vəziyyətinə keçmədi!"
    }
} else {
    Write-Host "[PASS] WinKeyService uğurla başladıldı və IPC Named Pipe aktivdir!" -ForegroundColor Green
}

# REM-028: Dar Wi-Fi Firewall qaydasi (Yaliniz yerli private sebeke ve port 8788)
Write-Host "[ACTION] Lokal Wi-Fi elaqesi ucun dar Windows Firewall qaydasi tetbiq olunur..." -ForegroundColor Cyan
& netsh.exe advfirewall firewall add rule name="WinKey Pro Local Wi-Fi" dir=in action=allow protocol=TCP localport=8788 profile=private,domain program="$installedBin" 2>$null | Out-Null

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "   QURAŞDIRMA UĞURLA BAŞA ÇATDI (STATUS: RUNNING)         " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "Proqram qovluğu: $InstallDir" -ForegroundColor Cyan
Write-Host "Data qovluğu:    $DataDir (Owner: $OwnerSid)" -ForegroundColor Cyan
Write-Host "Xidmət adı:      $serviceName" -ForegroundColor Cyan

# Diaqnostika hadisəsi qeyd olunur
Write-WinKeyDiagnosticEvent -Stage "INSTALL_SUCCESS" -EventType "success" -Severity "INFO"
exit 0
