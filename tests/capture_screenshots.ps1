# Capture real console windows running the packaged CLI.
# Each shot runs the real rea.exe inside Windows Terminal, waits for a completion
# marker, then captures the window pixels with PrintWindow.
# Usage: powershell -ExecutionPolicy Bypass -File tests\capture_screenshots.ps1 [-Only 01-analyze]

param([string]$Only = "")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root "dist\rea.exe"
$shotsDir = Join-Path $root "assets\screenshots"
$work = Join-Path $root "out\shots"
New-Item -ItemType Directory -Force -Path $shotsDir, $work | Out-Null

if (-not (Test-Path $exe)) { throw "dist\rea.exe is missing; run build\build.ps1 first" }

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class ReaWin {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc p, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int ht, bool repaint);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
"@
[ReaWin]::SetProcessDPIAware() | Out-Null

function Find-ConsoleWindow([string]$title) {
    $script:wantTitle = $title
    $script:foundHandle = [IntPtr]::Zero
    $cb = [ReaWin+EnumProc]{ param($h, $l)
        if ([ReaWin]::IsWindowVisible($h)) {
            $sb = New-Object System.Text.StringBuilder 512
            [void][ReaWin]::GetWindowText($h, $sb, 512)
            if ($sb.ToString() -eq $script:wantTitle) {
                $script:foundHandle = $h
                return $false
            }
        }
        return $true
    }
    [ReaWin]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
    return $script:foundHandle
}

function Wait-Window([string]$title, [int]$seconds = 30) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        $handle = Find-ConsoleWindow $title
        if ($handle -ne [IntPtr]::Zero) { return $handle }
        Start-Sleep -Milliseconds 300
    }
    return [IntPtr]::Zero
}

function Wait-Marker([string]$path, [int]$seconds = 90) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $path) { return $true }
        Start-Sleep -Milliseconds 300
    }
    return $false
}

function Close-Matching([string]$title) {
    $script:stale = New-Object System.Collections.ArrayList
    $cb = [ReaWin+EnumProc]{ param($h, $l)
        if ([ReaWin]::IsWindowVisible($h)) {
            $sb = New-Object System.Text.StringBuilder 512
            [void][ReaWin]::GetWindowText($h, $sb, 512)
            if ($sb.ToString() -eq $script:staleTitle) { [void]$script:stale.Add($h) }
        }
        return $true
    }
    $script:staleTitle = $title
    [ReaWin]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null
    foreach ($h in $script:stale) {
        [ReaWin]::PostMessage($h, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    }
    if ($script:stale.Count -gt 0) { Start-Sleep -Milliseconds 700 }
}

function Close-Tab([IntPtr]$handle) {
    [ReaWin]::SetForegroundWindow($handle) | Out-Null
    Start-Sleep -Milliseconds 300
    if ([ReaWin]::GetForegroundWindow() -eq $handle) {
        [ReaWin]::keybd_event(0x11, 0, 0, [UIntPtr]::Zero)      # Ctrl down
        Start-Sleep -Milliseconds 50
        [ReaWin]::keybd_event(0x10, 0, 0, [UIntPtr]::Zero)      # Shift down
        Start-Sleep -Milliseconds 50
        [ReaWin]::keybd_event(0x57, 0, 0, [UIntPtr]::Zero)      # W down
        Start-Sleep -Milliseconds 50
        [ReaWin]::keybd_event(0x57, 0, 2, [UIntPtr]::Zero)      # W up
        Start-Sleep -Milliseconds 50
        [ReaWin]::keybd_event(0x10, 0, 2, [UIntPtr]::Zero)      # Shift up
        Start-Sleep -Milliseconds 50
        [ReaWin]::keybd_event(0x11, 0, 2, [UIntPtr]::Zero)      # Ctrl up
        return
    }
    [ReaWin]::PostMessage($handle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
}

function Scroll-ToTop([IntPtr]$handle) {
    if ([ReaWin]::GetForegroundWindow() -ne $handle) { return $false }
    [ReaWin]::keybd_event(0x11, 0, 0, [UIntPtr]::Zero)          # Ctrl down
    Start-Sleep -Milliseconds 60
    [ReaWin]::keybd_event(0x10, 0, 0, [UIntPtr]::Zero)          # Shift down
    Start-Sleep -Milliseconds 60
    [ReaWin]::keybd_event(0x24, 0, 0, [UIntPtr]::Zero)          # Home down
    Start-Sleep -Milliseconds 60
    [ReaWin]::keybd_event(0x24, 0, 2, [UIntPtr]::Zero)          # Home up
    Start-Sleep -Milliseconds 60
    [ReaWin]::keybd_event(0x10, 0, 2, [UIntPtr]::Zero)          # Shift up
    Start-Sleep -Milliseconds 60
    [ReaWin]::keybd_event(0x11, 0, 2, [UIntPtr]::Zero)          # Ctrl up
    Start-Sleep -Milliseconds 900
    return $true
}

function Save-Window([IntPtr]$handle, [string]$path, [bool]$scrollTop = $false) {
    [ReaWin]::ShowWindow($handle, 9) | Out-Null      # SW_RESTORE
    [ReaWin]::MoveWindow($handle, 70, 30, 1520, 980, $true) | Out-Null
    [ReaWin]::SetForegroundWindow($handle) | Out-Null
    Start-Sleep -Milliseconds 1200
    if ($scrollTop -and -not (Scroll-ToTop $handle)) {
        Write-Host "  note: could not focus the window for scrolling"
    }
    $rect = New-Object ReaWin+RECT
    [ReaWin]::GetWindowRect($handle, [ref]$rect) | Out-Null
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    if ($width -lt 400 -or $height -lt 300) { throw "window is too small ($width x $height)" }

    $bitmap = New-Object System.Drawing.Bitmap($width, $height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $hdc = $graphics.GetHdc()
    $printed = [ReaWin]::PrintWindow($handle, $hdc, 2)
    $graphics.ReleaseHdc($hdc)
    if (-not $printed) {
        $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size)
    }
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bitmap.Dispose()
    return "$width x $height"
}

$shots = @(
    @{
        Name = "01-analyze"
        Title = "REA CLI - analyze"
        Command = "`"$exe`" analyze fixtures\sample.apk --out `"$work\analyze`" --no-pause"
        Scroll = $true
    },
    @{
        Name = "02-source"
        Title = "REA CLI - Java sources"
        Command = "`"$exe`" source fixtures\sample.apk --out `"$work\source`" --no-pause"
        Scroll = $false
    },
    @{
        Name = "03-shell"
        Title = "REA CLI - shell"
        Command = "(echo source& echo quit) | `"$exe`" shell fixtures\sample.apk --out `"$work\shell`""
        Scroll = $false
    },
    @{
        Name = "04-strings"
        Title = "REA CLI - strings"
        Command = "`"$exe`" strings fixtures\sample.apk"
        Scroll = $true
    },
    @{
        Name = "05-compare"
        Title = "REA CLI - compare"
        Command = "`"$exe`" compare fixtures\sample.apk fixtures\sample.jar"
        Scroll = $true
    },
    @{
        Name = "06-pyc"
        Title = "REA CLI - Python source"
        Command = "`"$exe`" source fixtures\sample_module.pyc --out `"$work\pyc`" --no-pause"
        Scroll = $true
    },
    @{
        Name = "07-code"
        Title = "REA CLI - recovered code"
        Command = "type `"$work\source\dex\java\demo\Hello.java`""
        Scroll = $true
    },
    @{
        Name = "08-help"
        Title = "REA CLI - help"
        Command = "`"$exe`" --help"
        Scroll = $true
    }
)

foreach ($shot in $shots) {
    if ($Only -and $shot.Name -ne $Only) { continue }
    $marker = Join-Path $work ("{0}.done" -f $shot.Name)
    Remove-Item -LiteralPath $marker -ErrorAction SilentlyContinue
    $batchPath = Join-Path $work ("{0}.cmd" -f $shot.Name)
    $batch = @(
        "@echo off",
        "title $($shot.Title)",
        "mode con cols=130 lines=200 >nul",
        "cd /d `"$root`"",
        $shot.Command,
        "> `"$marker`" echo finished",
        "timeout /t 120 /nobreak >nul 2>&1"
    ) -join "`r`n"
    Set-Content -Path $batchPath -Value $batch -Encoding ASCII

    Write-Host "capturing $($shot.Name) ..."
    Close-Matching $shot.Title
    $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$batchPath`"" -PassThru -WindowStyle Normal
    $handle = Wait-Window $shot.Title 25
    if ($handle -eq [IntPtr]::Zero) {
        Write-Host "  window not found for $($shot.Name); skipping"
        try { $process.Kill() } catch { }
        continue
    }
    if (-not (Wait-Marker $marker 90)) {
        Write-Host "  command did not finish in time for $($shot.Name)"
    }
    Start-Sleep -Milliseconds 900
    $target = Join-Path $shotsDir ("{0}.png" -f $shot.Name)
    try {
        $size = Save-Window $handle $target $shot.Scroll
        Write-Host "  saved $target ($size)"
    }
    catch {
        Write-Host "  capture failed: $($_.Exception.Message)"
    }

    Close-Tab $handle
    Start-Sleep -Milliseconds 800
    try { $process.Kill() } catch { }
}

Write-Host "done"
