# Set the app version everywhere it is written down (Windows twin of set-version.sh).
#   powershell -ExecutionPolicy Bypass -File scripts\set-version.ps1 2.0.6
#   set-version.bat 2.0.6            (same thing, from the repository root)
# With no version it prints the current one. See docs/DEVELOPMENT.md, "Version number".
param([string]$Version = "")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$utf8 = New-Object System.Text.UTF8Encoding $false

function Get-Current {
    $m = [regex]::Match([IO.File]::ReadAllText((Join-Path $root "Cargo.toml")), '(?m)^version = "([^"]*)"')
    return $m.Groups[1].Value
}

if ($Version -eq "") { Write-Host "Current version: $(Get-Current)"; exit 0 }
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
    Write-Error "Version must look like 2.0.6 (three numbers), got '$Version'."
    exit 1
}

$edits = @(
    @{ File = "Cargo.toml";                    Pattern = '(?m)^(\[package\]\r?\n(?:[^\[\n]*\n)*?version = ")[^"]*"'; Count = 1; First = $true },
    @{ File = "gui\src-tauri\Cargo.toml";      Pattern = '(?m)^(\[package\]\r?\n(?:[^\[\n]*\n)*?version = ")[^"]*"'; Count = 1; First = $true },
    @{ File = "gui\src-tauri\tauri.conf.json"; Pattern = '(?m)^(  "version": ")[^"]*"'; Count = 1; First = $true },
    @{ File = "gui\package.json";              Pattern = '(?m)^(  "version": ")[^"]*"'; Count = 1; First = $true },
    @{ File = "gui\package-lock.json";         Pattern = '("name": "gui",\r?\n\s*"version": ")[^"]*"'; Count = 2; First = $false },
    @{ File = "Cargo.lock";                    Pattern = '(name = "mabi-pack2-core"\r?\nversion = ")[^"]*"'; Count = 1; First = $false },
    @{ File = "gui\src-tauri\Cargo.lock";      Pattern = '(name = "(?:mabi-pack2-core|mabi-patcher)"\r?\nversion = ")[^"]*"'; Count = 2; First = $false }
)

# Check every file first so a failure leaves nothing half-changed.
foreach ($e in $edits) {
    $text = [IO.File]::ReadAllText((Join-Path $root $e.File))
    $n = [regex]::Matches($text, $e.Pattern).Count
    if ($e.First -and $n -gt 1) { $n = 1 }
    if ($n -ne $e.Count) { Write-Error "$($e.File): expected $($e.Count) version line(s), found $n"; exit 1 }
}

Write-Host "Setting version $(Get-Current) -> $Version"
foreach ($e in $edits) {
    $path = Join-Path $root $e.File
    $text = [IO.File]::ReadAllText($path)
    $re = New-Object System.Text.RegularExpressions.Regex $e.Pattern
    $limit = if ($e.First) { 1 } else { -1 }
    $text = $re.Replace($text, { param($m) $m.Groups[1].Value + $Version + '"' }, $limit)
    [IO.File]::WriteAllText($path, $text, $utf8)
    Write-Host "  $($e.File)"
}
Write-Host "Done. Rebuild to pick up the new version (build.bat)."
