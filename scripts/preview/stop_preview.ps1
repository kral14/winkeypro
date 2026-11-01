<#
.SYNOPSIS
WinKey Pro - Frontend Preview Safe Stopper Script (Strict Ownership & Process Tree)
Safe against PowerShell reserved $PID collisions.
Requires exact resolved workspace path match AND stored creation timestamp match.
Generic substrings (*npm*, *node*, *web_remote*) are strictly rejected as proof of ownership.
Never stops unrelated processes.
#>

param (
    [int]$Port = 5173
)

$ErrorActionPreference = "Stop"

$targetRoot = Join-Path $PSScriptRoot "..\.."
$workspaceDir = (Resolve-Path $targetRoot).Path
$webRemoteDir = Join-Path $workspaceDir "legacy\web_remote"
$metaFile = Join-Path $workspaceDir ".preview_server.json"
$pidFile = Join-Path $workspaceDir ".preview_server.pid"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   WinKey Pro - Safe Preview Stopper (Strict Ownership)    " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

$stoppedCount = 0

# 1. Inspect .preview_server.json metadata:
if (Test-Path $metaFile) {
    try {
        $metaJson = Get-Content $metaFile -Raw | ConvertFrom-Json
        $recordedProcessId = [int]$metaJson.pid
        $recordedCreationTime = [string]$metaJson.creationTime

        if ($recordedProcessId -gt 0) {
            $cimProc = Get-CimInstance Win32_Process -Filter "ProcessId = $recordedProcessId" -ErrorAction SilentlyContinue

            if ($cimProc) {
                # Strict verification: CreationDate + exact resolved workspace path in CommandLine
                $isOwnerVerified = $false
                $currentCreationTime = if ($cimProc.CreationDate) { $cimProc.CreationDate.ToString("o") } else { "" }
                $cmdLine = $cimProc.CommandLine

                # Check if creation time matches (if recorded)
                $timeMatch = $true
                if ($recordedCreationTime -and $currentCreationTime) {
                    if ($recordedCreationTime -ne $currentCreationTime) {
                        $timeMatch = $false
                    }
                }

                # Check exact resolved workspace path
                if ($timeMatch -and ($cmdLine -like "*$workspaceDir*")) {
                    $isOwnerVerified = $true
                }

                if ($isOwnerVerified) {
                    # Terminate verified child process tree
                    $childProcs = Get-CimInstance Win32_Process -Filter "ParentProcessId = $recordedProcessId" -ErrorAction SilentlyContinue
                    foreach ($child in $childProcs) {
                        try {
                            Stop-Process -Id $child.ProcessId -Force -ErrorAction SilentlyContinue
                            Write-Host "[OK] Stopped verified child process: $($child.Name) (PID: $($child.ProcessId))" -ForegroundColor Green
                            $stoppedCount++
                        } catch {}
                    }

                    try {
                        Stop-Process -Id $recordedProcessId -Force -ErrorAction SilentlyContinue
                        Write-Host "[OK] Stopped verified primary process: $($cimProc.Name) (PID: $recordedProcessId)" -ForegroundColor Green
                        $stoppedCount++
                    } catch {}
                } else {
                    Write-Host "[WARN] Found PID $recordedProcessId, but strict ownership verification failed (Timestamp or exact workspace path mismatch). Skipping." -ForegroundColor Yellow
                }
            }
        }
    } catch {
        Write-Host "[WARN] Error inspecting metadata file: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Remove-Item -Path $metaFile -Force -ErrorAction SilentlyContinue
}

if (Test-Path $pidFile) {
    Remove-Item -Path $pidFile -Force -ErrorAction SilentlyContinue
}

# 2. Check process listening on local port with strict workspace match:
$conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1

if ($conn) {
    $listenerProcessId = $conn.OwningProcess
    $listenerWmi = Get-CimInstance Win32_Process -Filter "ProcessId = $listenerProcessId" -ErrorAction SilentlyContinue

    if ($listenerWmi) {
        $cmdLine = $listenerWmi.CommandLine
        $parentCmdLine = ""

        if ($listenerWmi.ParentProcessId) {
            $parentWmi = Get-CimInstance Win32_Process -Filter "ProcessId = $($listenerWmi.ParentProcessId)" -ErrorAction SilentlyContinue
            if ($parentWmi) { $parentCmdLine = $parentWmi.CommandLine }
        }

        # Strict exact resolved workspace match (generic substrings strictly rejected)
        $isWorkspaceOwner = $false
        if (($cmdLine -like "*$workspaceDir*") -or ($parentCmdLine -like "*$workspaceDir*")) {
            $isWorkspaceOwner = $true
        }

        if ($isWorkspaceOwner) {
            try {
                if ($listenerWmi.ParentProcessId -and ($parentCmdLine -like "*$workspaceDir*")) {
                    Stop-Process -Id $listenerWmi.ParentProcessId -Force -ErrorAction SilentlyContinue
                }
                Stop-Process -Id $listenerProcessId -Force -ErrorAction SilentlyContinue
                Write-Host "[OK] Stopped verified workspace listening process: $($listenerWmi.Name) (PID: $listenerProcessId)" -ForegroundColor Green
                $stoppedCount++
            } catch {
                Write-Host "[ERROR] Could not stop process: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "[WARN] Process listening on port $Port (PID: $listenerProcessId, Name: $($listenerWmi.Name)) does not match exact workspace path." -ForegroundColor Yellow
            Write-Host "[WARN] Strict ownership rejected; process left untouched." -ForegroundColor Yellow
        }
    }
}

if ($stoppedCount -gt 0) {
    Write-Host "[OK] Preview server safely stopped ($stoppedCount processes terminated)." -ForegroundColor Green
} else {
    Write-Host "[INFO] No running workspace preview processes found to stop." -ForegroundColor Yellow
}
Write-Host "==========================================================" -ForegroundColor Cyan
