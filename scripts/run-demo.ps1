# Start a throw-away API instance, run the walkthrough, save the transcript.
#
#   powershell -ExecutionPolicy Bypass -File .\scripts\run-demo.ps1
param(
    [int]$Port = 3000,
    [string]$OutFile = 'docs/evidence/api-demo.txt'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$dataDir = Join-Path $root 'data'
$dbPath = Join-Path $dataDir 'demo.db'
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
Remove-Item -Force $dbPath, "$dbPath-wal", "$dbPath-shm" -ErrorAction SilentlyContinue

$env:PORT = "$Port"
$env:APP_ENV = 'development'
$env:DATABASE_PATH = $dbPath
$env:JWT_SECRET = 'demo-only-secret-demo-only-secret-demo-only'
$env:SEED_DEMO_USERS = 'true'

$serverLog = Join-Path $dataDir 'server.log'
$server = Start-Process -FilePath 'node' -ArgumentList 'src/server.js' -PassThru `
    -RedirectStandardOutput $serverLog -RedirectStandardError "$serverLog.err" -WindowStyle Hidden

try {
    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $null = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -UseBasicParsing -TimeoutSec 2
            $ready = $true
            break
        } catch { }
    }
    if (-not $ready) {
        Write-Host 'server did not start:' -ForegroundColor Red
        Get-Content $serverLog -ErrorAction SilentlyContinue
        exit 1
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutFile) | Out-Null
    node scripts/demo.mjs "http://127.0.0.1:$Port" 2>&1 | Tee-Object -FilePath $OutFile
    exit $LASTEXITCODE
}
finally {
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}
