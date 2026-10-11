"""
Unit and security tests for Model Context Protocol (MCP) static configuration analysis.

Guarantees Verified:
1. Pure AST / JSON reading: zero subprocess or shell executions.
2. Passive analysis only: zero socket or network calls.
3. Accurate detection of static indicators:
   - MCP-CFG-001 (Cleartext HTTP transport)
   - MCP-CFG-003 (Hardcoded credential literal)
   - MCP-CFG-007 (Dangerous root filesystem path)
4. Safe quarantine of malformed configuration files.
"""

import json
from pathlib import Path
from unittest.mock import patch
import pytest

from etw.ingest.mcp_config import ingest_mcp_config


SAMPLE_MCP_CONFIG = {
    "mcpServers": {
        "safe_local_server": {
            "command": "python",
            "args": ["-m", "safe_tool.server"],
            "env": {
                "SERVICE_PORT": "8080"
            }
        },
        "insecure_remote_http": {
            "command": "node",
            "args": ["http://insecure-remote.internal/sse"],
            "url": "http://api.internal:3000/mcp"
        },
        "dangerous_root_access": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
        },
        "hardcoded_credentials": {
            "command": "docker",
            "args": ["run", "-i", "my-server"],
            "env": {
                "AWS_ACCESS_KEY_ID": "AKIA1122334455667788",
                "GITHUB_TOKEN": "ghp_111122223333444455556666777788889999"
            }
        }
    }
}


@pytest.fixture
def sample_mcp_file(tmp_path: Path) -> Path:
    config_file = tmp_path / "claude_desktop_config.json"
    config_file.write_text(json.dumps(SAMPLE_MCP_CONFIG), encoding="utf-8")
    return config_file


def test_mcp_config_passive_indicators_detection(sample_mcp_file: Path):
    """Verify detection of MCP-CFG-001, MCP-CFG-003, and MCP-CFG-007 indicators."""
    res = ingest_mcp_config(sample_mcp_file)

    assert res.total_read == 4
    assert res.quarantined_count == 0
    assert len(res.observations) > 0

    rule_ids = {o.rule_id for o in res.observations}
    assert "MCP-CFG-001" in rule_ids  # Cleartext HTTP
    assert "MCP-CFG-003" in rule_ids  # Literal AWS / GitHub token
    assert "MCP-CFG-007" in rule_ids  # Dangerous root path

    # Check cleartext HTTP finding
    http_obs = [o for o in res.observations if o.rule_id == "MCP-CFG-001"]
    assert any("http" in o.redacted_match.lower() for o in http_obs)
    assert any("http://" in a.identifier for o in http_obs for a in o.extracted_assets)

    # Check root filesystem finding
    root_obs = [o for o in res.observations if o.rule_id == "MCP-CFG-007"]
    assert any(o.redacted_match == "/" for o in root_obs)

    # Check credential finding
    cred_obs = [o for o in res.observations if o.rule_id == "MCP-CFG-003"]
    assert any("AKIA" in o.redacted_match for o in cred_obs)


@patch("subprocess.run")
@patch("subprocess.Popen")
@patch("os.system")
def test_zero_subprocess_execution_during_mcp_ingest(mock_system, mock_popen, mock_run, sample_mcp_file: Path):
    """Security assertion: ETW NEVER executes server commands or spawns subprocesses."""
    res = ingest_mcp_config(sample_mcp_file)

    assert mock_run.call_count == 0
    assert mock_popen.call_count == 0
    assert mock_system.call_count == 0
    assert res.successful_count == 4


@patch("socket.socket")
def test_zero_network_calls_during_mcp_ingest(mock_socket, sample_mcp_file: Path):
    """Security assertion: ETW NEVER makes network calls or connects to remote MCP sockets."""
    res = ingest_mcp_config(sample_mcp_file)

    assert mock_socket.call_count == 0
    assert res.successful_count == 4


def test_malformed_mcp_json_quarantine(tmp_path: Path):
    """Malformed MCP configuration files are quarantined safely without raising exceptions."""
    bad_file = tmp_path / "broken_config.json"
    bad_file.write_text("{ this is not valid json :", encoding="utf-8")

    res = ingest_mcp_config(bad_file)
    assert res.quarantined_count == 1
    assert len(res.errors) == 1
    assert res.errors[0].error_code == "JSON_PARSE_ERROR"
    assert len(res.observations) == 0


def test_invalid_mcp_schema_quarantine(tmp_path: Path):
    """Non-dict server configuration is quarantined safely."""
    bad_schema = tmp_path / "bad_schema.json"
    bad_schema.write_text(json.dumps({"mcpServers": {"broken": "not-an-object"}}), encoding="utf-8")

    res = ingest_mcp_config(bad_schema)
    assert res.quarantined_count == 1
    assert res.errors[0].error_code == "INVALID_SERVER_CONFIG"
