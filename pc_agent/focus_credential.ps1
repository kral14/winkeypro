$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$clock = [Diagnostics.Stopwatch]::StartNew()
function Write-Stage([string]$message) { Write-Output ('t_ms=' + $clock.ElapsedMilliseconds + ' ' + $message) }
Write-Output ('UIA_BEGIN pid=' + $PID + ' session=' + (Get-Process -Id $PID).SessionId)
trap { Write-Output ('UIA_FATAL type=' + $_.Exception.GetType().FullName + ' hresult=' + $_.Exception.HResult); exit 3 }
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class LockScreenInput {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError=true)] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll", SetLastError=true)] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extra);
    public static string ClickCurtain(IntPtr hwnd) {
        RECT rect;
        if (!GetWindowRect(hwnd, out rect)) return "rect_error=" + Marshal.GetLastWin32Error();
        if (rect.Right <= rect.Left || rect.Bottom <= rect.Top) return "invalid_rect";
        int x = rect.Left + (rect.Right - rect.Left) / 2;
        int y = rect.Top + (rect.Bottom - rect.Top) / 3;
        if (!SetCursorPos(x, y)) return "cursor_error=" + Marshal.GetLastWin32Error();
        mouse_event(2, 0, 0, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(40);
        mouse_event(4, 0, 0, 0, UIntPtr.Zero);
        return "click_sent x=" + x + " y=" + y;
    }
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);
}
"@
Write-Stage 'UIA_READY'
$dismissCount = 0
$errorDismissed = $false
$editCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit)
for ($attempt = 0; $attempt -lt 12; $attempt++) {
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $edits = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $editCondition)
    Write-Stage ('UIA_SCAN attempt=' + $attempt + ' edit_count=' + $edits.Count)
    # LogonUI may expose a focused password edit behind the LockApp curtain.
    # Check the curtain before trusting that edit's HasKeyboardFocus property.
    $curtain = [IntPtr]::Zero
    $foreground = [LockScreenInput]::GetForegroundWindow()
    [uint32]$foregroundPid = 0
    [void][LockScreenInput]::GetWindowThreadProcessId($foreground, [ref]$foregroundPid)
    $foregroundName = 'unknown'
    try { $foregroundName = (Get-Process -Id $foregroundPid).ProcessName } catch {}
    if ($foregroundName -eq 'LockApp') { $curtain = $foreground }
    if ($curtain -eq [IntPtr]::Zero) {
        foreach ($window in $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)) {
            try {
                $windowProps = $window.Current
                if ($windowProps.IsOffscreen -or $windowProps.NativeWindowHandle -eq 0) { continue }
                $windowOwner = Get-Process -Id $windowProps.ProcessId -ErrorAction Stop
                if ($windowOwner.ProcessName -eq 'LockApp') {
                    $candidate = [IntPtr]([long]$windowProps.NativeWindowHandle)
                    if ([LockScreenInput]::IsWindowVisible($candidate)) { $curtain = $candidate; break }
                }
            } catch {}
        }
    }
    Write-Stage ('CURTAIN_CHECK foreground=' + $foregroundName + ' visible_lockapp=' + ($curtain -ne [IntPtr]::Zero) + ' edit_count=' + $edits.Count)
    if ($curtain -ne [IntPtr]::Zero -and $dismissCount -lt 2 -and ($dismissCount -eq 0 -or $attempt -ge 4)) {
        Write-Stage 'CURTAIN_CLICK_START owner=LockApp'
        $clickResult = [LockScreenInput]::ClickCurtain($curtain)
        Write-Stage ('CURTAIN_CLICK_END ' + $clickResult)
        $dismissCount++
        Start-Sleep -Milliseconds 180
        continue
    }
    if ($curtain -ne [IntPtr]::Zero) {
        Write-Stage 'CURTAIN_STILL_VISIBLE waiting; credential input blocked'
        Start-Sleep -Milliseconds 150
        continue
    }
    # A rejected password leaves a modal acknowledgement above the password edit.
    # Invoke only the visible, enabled acknowledgement owned by this session's LogonUI.
    if (-not $errorDismissed -and $foregroundName -eq 'LogonUI') {
        $buttonCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
        foreach ($button in $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $buttonCondition)) {
            try {
                $buttonProps = $button.Current
                if ($buttonProps.IsOffscreen -or -not $buttonProps.IsEnabled -or ($buttonProps.Name -replace '&', '').Trim() -notin @('Tamam', 'OK', 'Ok')) { continue }
                $buttonOwner = Get-Process -Id $buttonProps.ProcessId -ErrorAction Stop
                if ($buttonOwner.ProcessName -ne 'LogonUI' -or $buttonOwner.SessionId -ne (Get-Process -Id $PID).SessionId) { continue }
                Write-Stage 'LOGIN_ERROR_BUTTON_FOUND'
                $invoked = $false
                try {
                    $invoke = $button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
                    $invoke.Invoke()
                    $invoked = $true
                    Start-Sleep -Milliseconds 180
                } catch { Write-Stage 'LOGIN_ERROR_INVOKE_UNAVAILABLE' }
                # Some credential providers expose Invoke but leave the dialog open.
                $stillVisible = $false
                try { $stillVisible = -not $button.Current.IsOffscreen -and $button.Current.IsEnabled } catch {}
                if (-not $invoked -or $stillVisible) {
                    [uint32]$clickPid = 0
                    [void][LockScreenInput]::GetWindowThreadProcessId([LockScreenInput]::GetForegroundWindow(), [ref]$clickPid)
                    if ($clickPid -ne $buttonProps.ProcessId) { Write-Stage 'LOGIN_ERROR_FOREGROUND_CHANGED'; continue }
                    $point = New-Object System.Windows.Point
                    if (-not $button.TryGetClickablePoint([ref]$point)) { Write-Stage 'LOGIN_ERROR_NO_CLICKABLE_POINT'; continue }
                    # Check that the discovered point still belongs to this button.
                    $hit = [System.Windows.Automation.AutomationElement]::FromPoint($point)
                    if (-not [System.Windows.Automation.Automation]::Compare($hit, $button)) { Write-Stage 'LOGIN_ERROR_CLICK_TARGET_CHANGED'; continue }
                    if (-not [LockScreenInput]::SetCursorPos([int]$point.X, [int]$point.Y)) { continue }
                    [LockScreenInput]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)
                    [LockScreenInput]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
                    Write-Stage 'LOGIN_ERROR_BUTTON_CLICK_SENT'
                }
                $errorDismissed = $true
                Write-Stage 'LOGIN_ERROR_ACK_ATTEMPTED'
                Start-Sleep -Milliseconds 180
                break
            } catch { Write-Stage ('LOGIN_ERROR_DISMISS_FAILED type=' + $_.Exception.GetType().FullName + ' hresult=' + $_.Exception.HResult) }
        }
        if ($errorDismissed) { continue }
    }
    foreach ($edit in $edits) {
        try {
            $props = $edit.Current
            Write-Output ('UIA_EDIT process_id=' + $props.ProcessId + ' password=' + $props.IsPassword + ' enabled=' + $props.IsEnabled + ' offscreen=' + $props.IsOffscreen + ' focusable=' + $props.IsKeyboardFocusable + ' focused=' + $props.HasKeyboardFocus)
            if (-not $props.IsEnabled -or $props.IsOffscreen -or -not $props.IsKeyboardFocusable) { continue }
            $owner = Get-Process -Id $props.ProcessId -ErrorAction Stop
            if ($owner.ProcessName -ne 'LogonUI' -or -not $props.IsPassword) { continue }
            Write-Stage 'UIA_SETFOCUS_START'
            if (-not $props.HasKeyboardFocus) { $edit.SetFocus(); Start-Sleep -Milliseconds 60 }
            if ($edit.Current.HasKeyboardFocus) { Write-Stage 'FOCUSED'; exit 0 }
        } catch { Write-Output ('UIA_EDIT_ERROR type=' + $_.Exception.GetType().FullName + ' hresult=' + $_.Exception.HResult); continue }
    }
    # If no edit is exposed, allow a click only on the Windows sign-in window.
    if ($edits.Count -eq 0 -and $foregroundName -eq 'LogonUI' -and $dismissCount -lt 1) {
        Write-Stage 'CURTAIN_CLICK_START owner=LogonUI no_edit=True'
        Write-Stage ('CURTAIN_CLICK_END ' + [LockScreenInput]::ClickCurtain($foreground))
        $dismissCount++
    }
    Start-Sleep -Milliseconds 150
}
Write-Output 'PIN/parol xanasina fokus verile bilmedi; Windows giris usulunu yoxlayin.'
exit 2
