# Agent Observability Tool

A lightweight, localhost-only dashboard and telemetry recorder for the Exposure Triage Workbench (ETW) coding-agent toolchain.

## Directory Layout

```
tools/agent-observability/
├── check_tools.py               # CLI toolchain health check runner
├── database.py                  # SQLite storage, sanitization & query layer
├── health_checker.py            # Fixed allowlist health inspection logic
├── hook_listener.py             # Antigravity PostToolUse hook listener
├── metrics.py                   # Productivity & financial value calculation engine
├── record_event.py              # Event recorder CLI
├── server.py                    # Localhost HTTP server (127.0.0.1:8765)
├── data/                        # Local SQLite database (Git-ignored)
│   └── observability.db
├── scripts/
│   ├── check-tools.ps1          # PowerShell health check runner
│   ├── record-event.ps1         # PowerShell event logger
│   └── verify-installation.ps1  # Full verification & test runner
├── static/
│   ├── app.js                   # Dashboard client logic
│   ├── index.html               # Minimal dashboard interface
│   └── styles.css               # Clean dashboard styles
└── tests/
    ├── test_metrics.py          # Unit tests for metric formulas
    └── test_server.py           # Acceptance tests for HTTP endpoints & security
```

## Quick Start

1. Start the server:
   ```powershell
   python tools/agent-observability/server.py --port 8765
   ```
2. Open in browser:
   `http://127.0.0.1:8765/`

3. Run full verification:
   ```powershell
   powershell -ExecutionPolicy Bypass -File tools/agent-observability/scripts/verify-installation.ps1
   ```
