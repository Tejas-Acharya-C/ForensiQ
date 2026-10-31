# =============================================================================
# ForensiQ — Standard Application Launcher
# =============================================================================
# Launches ForensiQ with isolated application-data storage outside the repository.
# Binds strictly to loopback interface 127.0.0.1:8000.
# =============================================================================

[CmdletBinding()]
param(
    [int]$Port = 8000,
    [string]$HostAddress = "127.0.0.1"
)

$ErrorActionPreference = "Stop"

# 1. Resolve and navigate to repository root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path "$ScriptDir\..").Path
Set-Location -Path $RepoRoot

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  ForensiQ — Digital Forensics Workstation Launcher" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "Repository Root: $RepoRoot" -ForegroundColor Gray

# 2. Check Python availability
try {
    $pythonVer = python --version 2>&1
    Write-Host "Python: $pythonVer" -ForegroundColor Gray
} catch {
    Write-Error "Python is not found in PATH. Please activate your virtual environment."
    exit 1
}

# 3. Verify Database Status
Write-Host "`nChecking database connectivity..." -ForegroundColor Yellow
python scripts/check_db.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "Database not yet initialized or unreachable. Initializing schema via Alembic..." -ForegroundColor Yellow
    alembic upgrade head
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to run Alembic migrations. Please check your database configuration."
        exit 1
    }
}

# 4. Launch ForensiQ
Write-Host "`nStarting ForensiQ on http://$HostAddress`:$Port/ ..." -ForegroundColor Green
Write-Host "Press Ctrl+C to terminate.`n" -ForegroundColor Gray

uvicorn app.main:app --app-dir backend --host $HostAddress --port $Port

