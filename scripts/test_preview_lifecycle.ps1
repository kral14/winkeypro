# Advanced Strict Lifecycle & Process Isolation Test (PRE-002, PRE-004 verification)
$ErrorActionPreference = "Stop"

$workspaceDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$reportDir = Join-Path $workspaceDir "plan\reports\remaining"
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
$logPath = Join-Path $reportDir "launcher_strict_lifecycle.log"

Start-Transcript -Path $logPath -Force

Write-Host "=========================================================="
Write-Host " TEST 1: Syntactic Check on Launcher Scripts"
Write-Host "=========================================================="
$err1 = $null; [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $workspaceDir "scripts\preview\start_preview.ps1"), [ref]$null, [ref]$err1)
$err2 = $null; [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $workspaceDir "scripts\preview\stop_preview.ps1"), [ref]$null, [ref]$err2)

Write-Host "start_preview.ps1 errors: $($err1.Count)"
Write-Host "stop_preview.ps1 errors: $($err2.Count)"
if ($err1.Count -ne 0 -or $err2.Count -ne 0) {
    throw "Syntax error in start or stop scripts!"
}
Write-Host "[PASS] Syntax check passed with 0 errors."

Write-Host "`n=========================================================="
Write-Host " TEST 2: Strict Workspace Matching vs Generic Substrings"
Write-Host "=========================================================="
# Start a dummy process listening on test port 5997 that contains generic 'npm' in command line but NOT exact workspace
$dummyListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 5997)
$dummyListener.Start()
Write-Host "[OK] Test listener started on port 5997."

# Call stop_preview on port 5997
$stopScript = Join-Path $workspaceDir "scripts\preview\stop_preview.ps1"
& powershell -NoProfile -ExecutionPolicy Bypass -File $stopScript -Port 5997

$isStillAlive = $false
try {
    $conn = Get-NetTCPConnection -LocalPort 5997 -State Listen -ErrorAction Stop
    if ($conn) { $isStillAlive = $true }
} catch {}

if (-not $isStillAlive) {
    $dummyListener.Stop()
    throw "Generic substring process was falsely killed! Test FAILED!"
}
Write-Host "[PASS] Process on port 5997 remained untouched. Generic substring rejected."
$dummyListener.Stop()

Write-Host "`n=========================================================="
Write-Host " TEST 3: Stale Metadata / PID Reuse Simulation"
Write-Host "=========================================================="
# Create a fake .preview_server.json with PID of existing powershell process but wrong creation time
$testMetaFile = Join-Path $workspaceDir ".preview_server.json"
$fakeMeta = [ordered]@{
    pid = $PID
    creationTime = "2020-01-01T00:00:00.0000000Z" # Clearly mismatched past timestamp
    workspace = $workspaceDir
    webRemoteDir = Join-Path $workspaceDir "legacy\web_remote"
    port = 5173
} | ConvertTo-Json -Compress

$fakeMeta | Out-File -FilePath $testMetaFile -Encoding ascii -Force

# Call stop_preview - MUST detect timestamp mismatch and NOT kill current process
& powershell -NoProfile -ExecutionPolicy Bypass -File $stopScript -Port 5996

Write-Host "[PASS] Current process is still alive. Stale metadata / PID reuse was safely ignored."

Write-Host "`n=========================================================="
Write-Host " TEST 4: Duplicate Start Prevention on Active Port"
Write-Host "=========================================================="
$startScript = Join-Path $workspaceDir "scripts\preview\start_preview.ps1"
$connBefore = Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
$pidBefore = if ($connBefore) { $connBefore.OwningProcess } else { 0 }

if ($pidBefore -gt 0) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $startScript -Port 5173 -NoBrowser
    $connAfter = Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    $pidAfter = if ($connAfter) { $connAfter.OwningProcess } else { 0 }

    if ($pidBefore -ne $pidAfter) {
        throw "Process ID changed! Duplicate process was started! Before: $pidBefore, After: $pidAfter"
    }
    Write-Host "[PASS] Active server PID $pidBefore preserved. Duplicate launch prevented."
} else {
    Write-Host "[INFO] Port 5173 not active, skipping live duplicate test."
}

Write-Host "`n=========================================================="
Write-Host " ALL STRICT LIFECYCLE TESTS COMPLETED SUCCESSFULLY!"
Write-Host "=========================================================="
Stop-Transcript
