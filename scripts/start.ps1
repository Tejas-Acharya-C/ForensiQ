[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8000,
    [string]$HostAddress = "127.0.0.1",
    [switch]$InitializeDatabase
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$VenvScripts = Join-Path $RepoRoot ".venv\Scripts"
$Python = Join-Path $VenvScripts "python.exe"
$Uvicorn = Join-Path $VenvScripts "uvicorn.exe"
$Alembic = Join-Path $VenvScripts "alembic.exe"

foreach ($requiredFile in @($Python, $Uvicorn, $Alembic)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required project virtual-environment executable is missing: $requiredFile. Create .venv and install requirements.txt."
    }
}

if ([string]::IsNullOrWhiteSpace($HostAddress)) {
    throw "HostAddress must not be empty."
}

$locationPushed = $false
try {
    Push-Location -LiteralPath $RepoRoot
    $locationPushed = $true

    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  ForensiQ - Digital Forensics Workstation" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "Repository root: $RepoRoot" -ForegroundColor Gray

    $pythonVersion = & $Python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "The project virtual-environment Python could not be run."
    }
    Write-Host "Python: $pythonVersion" -ForegroundColor Gray

    & $Python (Join-Path $RepoRoot "scripts\check_environment.py")
    if ($LASTEXITCODE -ne 0) {
        throw "Dependency or configuration validation failed. Install the project requirements into .venv and correct the reported configuration."
    }

    Write-Host "`nChecking the configured database..." -ForegroundColor Yellow
    & $Python (Join-Path $RepoRoot "scripts\check_db.py")
    $databaseExitCode = $LASTEXITCODE

    if ($databaseExitCode -eq 2) {
        if (-not $InitializeDatabase) {
            throw "The configured SQLite database does not exist. No database was created. To explicitly initialize a new development database, run .\scripts\start.ps1 -InitializeDatabase."
        }

        & $Python (Join-Path $RepoRoot "scripts\check_environment.py") "--check-initialization"
        if ($LASTEXITCODE -ne 0) {
            throw "Explicit database initialization preflight failed. No migration was run."
        }

        Write-Host "Initializing the missing development database at the configured location..." -ForegroundColor Yellow
        & $Alembic heads
        if ($LASTEXITCODE -ne 0) {
            throw "Alembic migration configuration could not be validated. No database was initialized."
        }

        & $Alembic upgrade head
        if ($LASTEXITCODE -ne 0) {
            throw "Alembic failed to initialize the explicitly requested development database."
        }

        & $Python (Join-Path $RepoRoot "scripts\check_db.py")
        if ($LASTEXITCODE -ne 0) {
            throw "The initialized database did not pass the connectivity check."
        }
    }
    elseif ($databaseExitCode -ne 0) {
        throw "Database connectivity or configuration validation failed. Migrations were not run."
    }

    & $Python (Join-Path $RepoRoot "scripts\check_environment.py") "--check-migrations"
    if ($LASTEXITCODE -ne 0) {
        throw "Database migration state is not ready for startup. No automatic migration was applied; back up existing data and review pending migrations manually."
    }

    & $Python (Join-Path $RepoRoot "scripts\check_environment.py") "--import-app"
    if ($LASTEXITCODE -ne 0) {
        throw "FastAPI application import failed. Review the traceback above."
    }

    $applicationUrl = "http://{0}:{1}/" -f $HostAddress, $Port
    Write-Host "`nStarting ForensiQ at $applicationUrl" -ForegroundColor Green
    Write-Host "Press Ctrl+C to stop the server." -ForegroundColor Gray

    $uvicornArguments = @(
        "app.main:app",
        "--app-dir", "backend",
        "--host", $HostAddress,
        "--port", $Port.ToString()
    )
    & $Uvicorn @uvicornArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Uvicorn exited with code $LASTEXITCODE."
    }
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    if ($locationPushed) {
        Pop-Location
    }
}
