param(
    [Parameter(Mandatory = $true)][string]$Executable,
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
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        throw 'Masaüstü icra faylı tapılmadı.'
    }
    # Bind to the existing desktop Explorer, rather than launching from the
    # elevated installer token (which can belong to a different admin account).
    $shell = New-Object -ComObject Shell.Application
    $hwnd = 0
    # SWC_DESKTOP = 8, SWFO_NEEDDISPATCH = 1. This also works when no folder
    # windows are open. Never fall back to an elevated launch on failure.
    $desktop = $shell.Windows().FindWindowSW(0, 0, 8, [ref]$hwnd, 1)
    if ($null -eq $desktop) { throw 'İnteraktiv masaüstü qabığı (explorer) əlçatan deyil.' }
    $desktopShell = $desktop.Document.Application
    $desktopShell.ShellExecute($Executable, '', (Split-Path -Parent $Executable), 'open', 1)
    exit 0
} catch {
    Write-Error "WinKey masaüstü tətbiqi başladılmadı: $_" -ErrorAction Continue
    exit 1
}
