# End-to-end checks against the packaged executable.
# Usage: powershell -ExecutionPolicy Bypass -File tests\exe_smoke.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root "dist\rea.exe"
$out = Join-Path $root "out\exe"
New-Item -ItemType Directory -Force -Path $out | Out-Null

if (-not (Test-Path $exe)) { throw "dist\rea.exe is missing; run build\build.ps1 first" }

$targets = @(
    "fixtures\sample_module.wasm",
    "fixtures\sample_image.elf",
    "fixtures\sample_image.macho",
    "fixtures\Sample.class",
    "fixtures\sample.dex",
    "fixtures\AndroidManifest.bin",
    "fixtures\sample.asar",
    "fixtures\sample.jar",
    "fixtures\sample.apk",
    "fixtures\sample.db",
    "fixtures\sample.js",
    "fixtures\notes.txt",
    "fixtures\blob.bin",
    "fixtures\sample_module.pyc",
    "fixtures\jsapp"
)

$sourceExpectations = @{
    "Sample.class" = ".java"
    "sample.apk" = ".java"
    "sample.jar" = ".java"
    "sample.dex" = ".java"
    "sample_module.pyc" = ".py"
}

$failures = 0
foreach ($target in $targets) {
    $name = Split-Path -Leaf $target
    $log = Join-Path $out ("{0}.log" -f $name)
    $json = Join-Path $out ("{0}.json" -f $name)
    $work = Join-Path $out ("{0}.out" -f $name)
    Push-Location $root
    & $exe $target --json --no-pause --out $work | Out-File -Encoding utf8 $json
    $code = $LASTEXITCODE
    Pop-Location
    if ($code -ne 0) {
        Write-Host ("FAIL {0} exit={1}" -f $name, $code)
        $failures++
        continue
    }
    try {
        $parsed = Get-Content -Raw -Encoding utf8 $json | ConvertFrom-Json
    }
    catch {
        Write-Host ("FAIL {0} invalid JSON" -f $name)
        $failures++
        continue
    }
    Write-Host ("OK   {0,-24} format={1,-12} artifacts={2,-3} limitations={3}" -f `
        $name, $parsed.format, $parsed.artifacts.Count, $parsed.limitations.Count)
    $expected = $sourceExpectations[$name]
    if ($expected) {
        $source = @($parsed.artifacts | Where-Object { $_.path.EndsWith($expected) })
        if ($source.Count -eq 0) {
            Write-Host ("FAIL {0}: no {1} source artifact" -f $name, $expected)
            $failures++
        }
    }
}

$refusal = Join-Path $out "remote.log"
Push-Location $root
& $exe "https://example.com/sample.apk" --json --no-pause 2>&1 | Out-File -Encoding utf8 $refusal
$code = $LASTEXITCODE
Pop-Location
$text = Get-Content -Raw -Encoding utf8 $refusal
if ($code -eq 0 -or $text -notmatch "network_refused") {
    Write-Host "FAIL remote URL was not refused"
    $failures++
}
else {
    Write-Host "OK   remote URL refused"
}

Write-Host ""
Write-Host ("{0} failure(s)" -f $failures)
exit $failures
