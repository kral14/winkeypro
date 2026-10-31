<#
.SYNOPSIS
WinKey Pro - One-Click Frontend Preview Launcher (Strict Process Ownership)
#>

param (
    [int]$Port = 5173,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"

$targetRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$workspaceDir = (Resolve-Path $targetRoot).Path
$webRemoteDir = Join-Path $workspaceDir "web_remote"
$desktopUrl = "http://127.0.0.1:$Port/desktop"
$metaFile = Join-Path $workspaceDir ".preview_server.json"
$logFile = Join-Path $workspaceDir ".preview_server.log"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   WinKey Pro - One-Click Frontend Preview Launcher        " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check existing listening process and verify exact workspace ownership:
$conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1

if ($conn) {
    $existingPid = $conn.OwningProcess
    $isOurWorkspace = $false

    try {
        $cimProc = Get-CimInstance Win32_Process -Filter "ProcessId = $existingPid" -ErrorAction SilentlyContinue
        $cmdLine = if ($cimProc) { $cimProc.CommandLine } else { "" }

        $parentCmdLine = ""
        if ($cimProc -and $cimProc.ParentProcessId) {
            $parentProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($cimProc.ParentProcessId)" -ErrorAction SilentlyContinue
            if ($parentProc) { $parentCmdLine = $parentProc.CommandLine }
        }

        # Exact resolved workspace verification
        if (($cmdLine -like "*$workspaceDir*") -or ($parentCmdLine -like "*$workspaceDir*")) {
            $isOurWorkspace = $true
        }
    } catch {
        $isOurWorkspace = $false
    }

    if (-not $isOurWorkspace) {
        Write-Host "[ERROR] Port $Port is in use by another process (PID: $existingPid)." -ForegroundColor Red
        Write-Host "Process does NOT belong to resolved workspace: $workspaceDir. Aborting." -ForegroundColor Red
        exit 1
    }

    # Verify /desktop health
    Write-Host "[INFO] Port $Port has verified workspace process (PID: $existingPid). Checking /desktop health..." -ForegroundColor Yellow
    try {
        $check = Invoke-WebRequest -Uri $desktopUrl -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        if ($check.StatusCode -eq 200) {
            Write-Host "[OK] Server is active and /desktop returns HTTP 200." -ForegroundColor Green
            Write-Host "[INFO] Preserving existing server (No duplicate process launched)." -ForegroundColor Green

            if (-not $NoBrowser) {
                Write-Host "[ACTION] Launching default browser: $desktopUrl" -ForegroundColor Cyan
                Start-Process $desktopUrl
            }
            exit 0
        }
    } catch {
        Write-Host "[WARN] Port is active but /desktop check failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# 2. Start server with explicit web_remote cwd:
Write-Host "[INFO] Starting server with explicit cwd in web_remote..." -ForegroundColor Yellow

if (-not (Test-Path $webRemoteDir)) {
    Write-Host "[ERROR] web_remote directory not found: $webRemoteDir" -ForegroundColor Red
    exit 1
}

$startArgs = "/c npm run dev > `"$logFile`" 2>&1"
$newProc = Start-Process -FilePath "cmd.exe" `
    -ArgumentList $startArgs `
    -WorkingDirectory $webRemoteDir `
    -WindowStyle Hidden `
    -PassThru

$startedPid = $newProc.Id
$creationTime = ""
try {
    $startedWmi = Get-CimInstance Win32_Process -Filter "ProcessId = $startedPid" -ErrorAction SilentlyContinue
    if ($startedWmi -and $startedWmi.CreationDate) {
        $creationTime = $startedWmi.CreationDate.ToString("o")
    }
} catch {}

# Register strict process metadata
$metaObj = [ordered]@{
    pid = $startedPid
    creationTime = $creationTime
    workspace = $workspaceDir
    webRemoteDir = $webRemoteDir
    port = $Port
    logFile = $logFile
    startedAt = (Get-Date).ToString("o")
}
$metaData = $metaObj | ConvertTo-Json -Compress
$metaData | Out-File -FilePath $metaFile -Encoding ascii -Force
$startedPid | Out-File -FilePath (Join-Path $workspaceDir ".preview_server.pid") -Encoding ascii -Force

Write-Host "[INFO] Server process created (PID: $startedPid). Awaiting /desktop endpoint..." -ForegroundColor Yellow

# 3. Await /desktop health endpoint (max 30 seconds):
$isHealthy = $false
$maxAttempts = 30
$attempt = 0

while ($attempt -lt $maxAttempts) {
    Start-Sleep -Milliseconds 1000
    $attempt++

    try {
        $resp = Invoke-WebRequest -Uri $desktopUrl -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            $isHealthy = $true
            Write-Host "`n[OK] Server is healthy and /desktop responded with HTTP 200!" -ForegroundColor Green
            break
        }
    } catch {
        Write-Host "." -NoNewline
    }
}

Write-Host ""

if (-not $isHealthy) {
    Write-Host "[ERROR] Server did not respond with HTTP 200 on /desktop within 30 seconds." -ForegroundColor Red
    Write-Host "Browser was NOT opened. Check log file: $logFile" -ForegroundColor Yellow
    exit 1
}

if (-not $NoBrowser) {
    Write-Host "[ACTION] Launching default browser: $desktopUrl" -ForegroundColor Cyan
    Start-Process $desktopUrl
}

Write-Host ""
Write-Host "Available Preview URLs:" -ForegroundColor White
Write-Host " - Desktop Shell:  http://127.0.0.1:$Port/desktop" -ForegroundColor Green
Write-Host " - Mobil PWA:      http://127.0.0.1:$Port/mobile" -ForegroundColor Green
Write-Host " - Sahib Admin:    http://127.0.0.1:$Port/admin" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
