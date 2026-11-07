# ─────────────────────────────────────────────────────────────────────────────
# ZTSP One-Click Demo Runner (Windows PowerShell)
# AI-Augmented Zero Trust Security Orchestration Platform
# ─────────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  AI-Augmented Zero Trust Security Orchestration Platform " -ForegroundColor Cyan
Write-Host "  B.Tech Final Year Research Prototype - Turnkey Demo    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python
Write-Host "[1/6] Checking Python installation..." -ForegroundColor Yellow
try {
    $pyVer = python --version 2>&1
    Write-Host "  -> Found $pyVer" -ForegroundColor Green
} catch {
    Write-Host "[-] Python 3.11+ is required but not found in PATH." -ForegroundColor Red
    exit 1
}

# 2. Check Docker
Write-Host "[2/6] Checking Docker daemon status..." -ForegroundColor Yellow
try {
    $null = docker info 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Docker not running" }
    Write-Host "  -> Docker daemon is running." -ForegroundColor Green
} catch {
    Write-Host "[-] Docker Desktop is not running." -ForegroundColor Red
    Write-Host "    Please launch Docker Desktop from the Start Menu, wait until it is ready, and re-run." -ForegroundColor Red
    exit 1
}

# 3. Generate synthetic data if not present
Write-Host "[3/6] Checking synthetic telemetry dataset..." -ForegroundColor Yellow
if (-not (Test-Path "testbed\data\all_labelled.ndjson")) {
    Write-Host "  -> Generating synthetic dataset (10,000 normal + attacks)..." -ForegroundColor Cyan
    python testbed\generate_telemetry.py --seed 42 --normal 10000 --attacks 100
} else {
    Write-Host "  -> Dataset present in testbed\data." -ForegroundColor Green
}

# 4. Train M5 ML models if not present
Write-Host "[4/6] Checking M5 ML models..." -ForegroundColor Yellow
if (-not (Test-Path "m5_ml\models\isolation_forest.pkl")) {
    Write-Host "  -> Training Isolation Forest + Random Forest ensemble..." -ForegroundColor Cyan
    python m5_ml\trainer.py --data-dir testbed\data --seed 42
} else {
    Write-Host "  -> ML models present in m5_ml\models." -ForegroundColor Green
}

# 5. Build and launch all 8 microservices
Write-Host "[5/6] Building and starting all 8 microservices via Docker Compose..." -ForegroundColor Yellow
docker compose up --build -d

Write-Host "  -> Waiting 15 seconds for services to initialize and pass healthchecks..." -ForegroundColor Cyan
Start-Sleep -Seconds 15

# 6. Execute live attack scenarios
Write-Host "[6/6] Executing live attack scenarios (S1-S4) vs RBAC baseline..." -ForegroundColor Yellow
python testbed\scenarios\run_all.py

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  ZTSP PLATFORM DEMO COMPLETE & OPERATIONAL!              " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  Web Dashboard:      http://localhost:8080" -ForegroundColor Cyan
Write-Host "  Protected Resource: http://localhost:8090" -ForegroundColor Cyan
Write-Host "  M1 Identity API:    http://localhost:8001/docs" -ForegroundColor Cyan
Write-Host "  M2 Policy PDP/PEP:  http://localhost:8002/docs" -ForegroundColor Cyan
Write-Host "  M3 SOAR Response:   http://localhost:8003/docs" -ForegroundColor Cyan
Write-Host "  M4 Posture Engine:  http://localhost:8004/docs" -ForegroundColor Cyan
Write-Host "  M5 ML Risk Engine:  http://localhost:8005/docs" -ForegroundColor Cyan
Write-Host "  Mock SOC Webhook:   http://localhost:8099/alerts" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Opening Live Web Dashboard in your default browser..." -ForegroundColor Yellow
Start-Process "http://localhost:8080"

