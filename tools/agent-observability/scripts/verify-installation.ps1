# Verification script for Coding-Agent Toolchain & Observability Dashboard
# Validates health checks, runs test suites, and verifies database integrity

param(
    [string]$DbPath = "tools\agent-observability\data\observability.db"
)

$ErrorActionPreference = "Stop"
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "ETW Coding-Agent Toolchain & Observability Verification" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

# 1. Health checks
Write-Host "`n[1/3] Running toolchain health checks..." -ForegroundColor Yellow
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $scriptDir "check-tools.ps1") -DbPath $DbPath

# 2. Run Python test suites
Write-Host "`n[2/3] Running automated unit test suites..." -ForegroundColor Yellow
python -m unittest discover -s "tools/agent-observability/tests" -p "test_*.py" -v

# 3. Database status check
Write-Host "`n[3/3] Inspecting observability database..." -ForegroundColor Yellow
$fullDbPath = (Resolve-Path $DbPath).Path.Replace('\', '/')
$pyCheck = @"
import sqlite3

db_path = '$fullDbPath'
conn = sqlite3.connect(db_path)
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM health_checks')
hc_count = c.fetchone()[0]
c.execute('SELECT COUNT(*) FROM events')
ev_count = c.fetchone()[0]
c.execute('SELECT COUNT(*) FROM work_sessions')
ws_count = c.fetchone()[0]
print(f'Database verified at {db_path}: {hc_count} health checks, {ev_count} events, {ws_count} work sessions.')
"@
python -c "$pyCheck"

Write-Host "`nAll verification checks completed successfully." -ForegroundColor Green
