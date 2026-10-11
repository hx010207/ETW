"""
Streaming and safe JSON parser for Model Context Protocol (MCP) configuration files.

Strict Safety Guarantees:
1. Pure AST / JSON reading only: NEVER executes commands or invokes subprocesses.
2. NEVER performs network checks, DNS lookups, or HTTP requests.
3. NEVER expands environment variables or modifies the local system.
4. Quarantines malformed or unparseable configuration files safely.
"""

import json
from pathlib import Path
from typing import Optional, Union

from etw.ingest.common import IngestError, IngestResult, validate_file_size
from etw.rules.mcp import analyze_mcp_server_config
from etw.storage.fingerprint import get_hmac_key


def ingest_mcp_config(
    file_path: Union[str, Path],
    hmac_key: Optional[bytes] = None,
) -> IngestResult:
    """
    Passively ingests and parses an MCP configuration file (e.g. claude_desktop_config.json).

    Args:
        file_path: Path to configuration file.
        hmac_key: Optional HMAC key for secret fingerprinting.

    Returns:
        IngestResult containing observations and quarantine errors.
    """
    if hmac_key is None:
        hmac_key = get_hmac_key()

    result = IngestResult()
    path = Path(file_path)

    try:
        validate_file_size(path)
    except Exception as exc:
        result.errors.append(
            IngestError(record_index=0, error_code="FILE_SIZE_ERROR", message=str(exc))
        )
        result.quarantined_count = 1
        return result

    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
    except Exception as exc:
        result.errors.append(
            IngestError(record_index=0, error_code="JSON_PARSE_ERROR", message=f"Failed to parse JSON: {exc}")
        )
        result.quarantined_count = 1
        return result

    if not isinstance(data, dict):
        result.errors.append(
            IngestError(record_index=0, error_code="INVALID_SCHEMA", message="Top-level configuration must be a JSON object")
        )
        result.quarantined_count = 1
        return result

    servers = data.get("mcpServers")
    if not servers or not isinstance(servers, dict):
        # Configuration file has no mcpServers section
        return result

    for server_name, server_cfg in servers.items():
        result.total_read += 1
        if not isinstance(server_cfg, dict):
            result.errors.append(
                IngestError(
                    record_index=result.total_read,
                    error_code="INVALID_SERVER_CONFIG",
                    message=f"Configuration for server '{server_name}' must be an object",
                )
            )
            result.quarantined_count += 1
            continue

        obs_list = analyze_mcp_server_config(
            server_name=server_name,
            server_config=server_cfg,
            file_path=str(path),
            hmac_key=hmac_key,
        )
        result.observations.extend(obs_list)
        result.successful_count += 1

    return result
