$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Port = if ($env:PORT) { $env:PORT } else { "8010" }
$Url = "http://127.0.0.1:$Port"

Set-Location $Root

Write-Host "NetWatch IDS startup"
Write-Host "Project: $Root"

$Python = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
  $Python = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
  $Python = "py"
}

if (-not $Python) {
  Write-Error "Python is required but was not found. Install Python 3 and re-run this script."
  exit 1
}

try {
  & $Python -c "import joblib, numpy, pandas, sklearn" | Out-Null
} catch {
  Write-Host "Installing Python ML dependencies from requirements.txt..."
  & $Python -m pip install -r requirements.txt
}

try {
  $health = Invoke-WebRequest -UseBasicParsing -Uri "$Url/api/health" -TimeoutSec 2
  if ($health.StatusCode -eq 200) {
    Write-Host "IDS is already running at $Url"
    Write-Host "Dashboard: $Url"
    exit 0
  }
} catch {
  # No running server detected on this port.
}

$listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($listener) {
  Write-Error "Port $Port is already in use. Run with another port, for example: `$env:PORT=8011; .\run.ps1"
  exit 1
}

if (-not $env:NPCAP_SDK) {
  $defaultNpcap = Join-Path $env:ProgramFiles "Npcap\SDK"
  if (Test-Path $defaultNpcap) {
    $env:NPCAP_SDK = $defaultNpcap
  }
}

if ($env:NPCAP_SDK) {
  Write-Host "Npcap SDK detected. The app will try to build the C++ packet collector automatically."
} else {
  Write-Host "Npcap SDK not detected. The Windows OS connection fallback will still run."
  Write-Host "Install Npcap + Npcap SDK for raw packet capture."
}

Write-Host "Starting IDS backend..."
Write-Host "Dashboard: $Url"
Write-Host "Press Ctrl+C to stop."
$env:PORT = $Port
& $Python app.py
