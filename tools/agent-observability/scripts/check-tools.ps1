# Health Check script for Coding-Agent Toolchain
# Executes fixed allowlist checks and updates local SQLite database

param(
    [string]$DbPath = "tools\agent-observability\data\observability.db",
    [string]$WorkspaceRoot = "."
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pyScript = Join-Path (Split-Path -Parent $scriptDir) "check_tools.py"

python $pyScript --db $DbPath --workspace $WorkspaceRoot
