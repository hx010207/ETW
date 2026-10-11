# Records a tool usage event into the local SQLite database

param(
    [Parameter(Mandatory=$true)]
    [string]$ToolId,

    [string]$EventType = "manual_usage_record",
    [ValidateSet("success", "failed", "pending")]
    [string]$Status = "success",
    [int]$DurationMs = 0,
    [string]$TaskId = "",
    [string]$PhaseId = "",
    [int]$ExitCode = 0,
    [string]$EvidenceSource = "manual_entry",
    [string]$Details = "",
    [string]$EventId = "",
    [string]$DbPath = "tools\agent-observability\data\observability.db"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pyScript = Join-Path (Split-Path -Parent $scriptDir) "record_event.py"

$argsList = @(
    "--tool-id", $ToolId,
    "--event-type", $EventType,
    "--status", $Status,
    "--exit-code", $ExitCode,
    "--evidence-source", $EvidenceSource,
    "--db", $DbPath
)

if ($DurationMs -gt 0) { $argsList += @("--duration-ms", $DurationMs) }
if ($TaskId) { $argsList += @("--task-id", $TaskId) }
if ($PhaseId) { $argsList += @("--phase-id", $PhaseId) }
if ($Details) { $argsList += @("--details", $Details) }
if ($EventId) { $argsList += @("--event-id", $EventId) }

python $pyScript @argsList
