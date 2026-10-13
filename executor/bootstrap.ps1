# ============================================================================
# bootstrap.ps1: prepares the executor environment (RF-10).
# Creates the .venv virtual environment, installs the run_diff.py dependencies and
# leaves a config.yaml ready to edit.
#
# Usage (PowerShell, from the extracted ZIP folder):
#   powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
# (If Windows blocks the script because it came from the Internet: Unblock-File .\bootstrap.ps1)
# ============================================================================

$ErrorActionPreference = "Stop"

Write-Host "[Thanos] Checking Python 3.10+..." -ForegroundColor Cyan
$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) { $python = "py"; $pyArgs = @("-3") } else {
    $python = "python"; $pyArgs = @()
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        throw "Python 3.10+ not found. Install it from python.org and try again."
    }
}

Write-Host "[Thanos] Creating virtual environment .venv..." -ForegroundColor Cyan
& $python @pyArgs -m venv .venv
$venvPython = ".\.venv\Scripts\python.exe"

Write-Host "[Thanos] Installing dependencies (pyyaml, rdflib)..." -ForegroundColor Cyan
& $venvPython -m pip install --upgrade pip | Out-Null
& $venvPython -m pip install "pyyaml>=6.0,<7.0" "rdflib>=7.1,<8.0"

if (-not (Test-Path config.yaml)) {
    if (Test-Path config.example.yaml) {
        Copy-Item config.example.yaml config.yaml
        Write-Host "[Thanos] Created config.yaml from config.example.yaml." -ForegroundColor Cyan
    }
}

Write-Host "[Thanos] Environment ready." -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Edit config.yaml and set ghidra_support_dir (Ghidra's 'support' folder; requires JDK 17+)."
Write-Host "  2. Copy the DLLs to input\before and input\after (same name in both folders)."
Write-Host "  3. Run:  .\.venv\Scripts\python.exe run_diff.py"
Write-Host "  4. Hand output\<run_id>.bundle.json to the coordinator or upload it to the panel."
