"""
Passive, static indicators for Model Context Protocol (MCP) configuration files.

Guarantees:
1. Zero process execution: commands in configuration are never spawned.
2. Zero network probing: endpoints are never contacted.
3. Zero environment variable expansion: literal values inspected only.
4. Raw secrets found in config strings are HMAC-fingerprinted and redacted.
"""

import re
from typing import Any, Dict, List, Optional
import uuid

from etw.models.enums import EvidenceLevel, SourceValidity
from etw.models.evidence import AssetCandidate, LocationEvidence
from etw.models.observation import Observation
from etw.storage.fingerprint import compute_fingerprint
from etw.storage.redaction import redact_secret


# Pattern for cleartext remote HTTP transport
CLEARTEXT_HTTP_PATTERN = re.compile(r"^http://[^\s'\"]+", re.IGNORECASE)

# Dangerous root/broad filesystem arguments
ROOT_PATH_PATTERNS = [
    re.compile(r"^/$"),
    re.compile(r"^[a-zA-Z]:\\?$"),
    re.compile(r"^[a-zA-Z]:/$"),
    re.compile(r"^~$"),
    re.compile(r"^/etc/?"),
    re.compile(r"^[a-zA-Z]:\\Windows", re.IGNORECASE),
]

# High-confidence credential patterns in config strings
CREDENTIAL_LITERAL_PATTERNS = [
    (re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"), "aws-access-key-id"),
    (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "github-pat"),
    (re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,72}"), "slack-token"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "stripe-live-key"),
    (re.compile(r"SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}"), "sendgrid-api-key"),
    (re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}"), "square-access-token"),
]


def analyze_mcp_server_config(
    server_name: str,
    server_config: Dict[str, Any],
    file_path: str,
    hmac_key: Optional[bytes] = None,
) -> List[Observation]:
    """
    Passively evaluates static security indicators against an MCP server definition.

    Returns:
        List of normalized Observation entities.
    """
    observations: List[Observation] = []
    asset_scope = f"mcp-server:{server_name}"

    # 1. MCP-CFG-001: Cleartext remote transport check
    # Check 'url' field if present or any HTTP URL in args
    candidate_urls: List[str] = []
    if "url" in server_config and isinstance(server_config["url"], str):
        candidate_urls.append(server_config["url"])

    args = server_config.get("args", [])
    if isinstance(args, list):
        for arg in args:
            if isinstance(arg, str) and arg.lower().startswith("http://"):
                candidate_urls.append(arg)

    for url_str in candidate_urls:
        if CLEARTEXT_HTTP_PATTERN.match(url_str):
            obs_id = f"obs-mcp-{uuid.uuid4().hex[:8]}"
            fp = compute_fingerprint(url_str, key=hmac_key)
            obs = Observation(
                id=obs_id,
                detector="mcp_config",
                rule_id="MCP-CFG-001",
                source_reported_validity=SourceValidity.NOT_CHECKED,
                location=LocationEvidence(
                    file_path=file_path,
                    repo_name=asset_scope,
                ),
                asset_scope=asset_scope,
                candidate_fingerprint=fp,
                redacted_match=redact_secret(url_str),
                raw_secret=url_str,
                extracted_assets=[
                    AssetCandidate(identifier=url_str, asset_type="url", evidence_level=EvidenceLevel.OBSERVED)
                ],
            )
            observations.append(obs)

    # 2. MCP-CFG-007: Dangerous filesystem root access check
    if isinstance(args, list):
        for idx, arg in enumerate(args):
            if isinstance(arg, str):
                for pat in ROOT_PATH_PATTERNS:
                    if pat.match(arg.strip()):
                        obs_id = f"obs-mcp-{uuid.uuid4().hex[:8]}"
                        fp = compute_fingerprint(f"{server_name}:root_path:{arg}", key=hmac_key)
                        obs = Observation(
                            id=obs_id,
                            detector="mcp_config",
                            rule_id="MCP-CFG-007",
                            source_reported_validity=SourceValidity.NOT_CHECKED,
                            location=LocationEvidence(
                                file_path=file_path,
                                repo_name=asset_scope,
                            ),
                            asset_scope=asset_scope,
                            candidate_fingerprint=fp,
                            redacted_match=arg,
                            raw_secret=arg,
                            extracted_assets=[
                                AssetCandidate(identifier=arg, asset_type="filesystem_path", evidence_level=EvidenceLevel.OBSERVED)
                            ],
                        )
                        observations.append(obs)

    # 3. MCP-CFG-003: Literal credential in env or args
    # Inspect env dict
    env = server_config.get("env", {})
    if isinstance(env, dict):
        for env_var, env_val in env.items():
            if isinstance(env_val, str):
                for pat, cred_type in CREDENTIAL_LITERAL_PATTERNS:
                    match = pat.search(env_val)
                    if match:
                        raw_match = match.group(0)
                        obs_id = f"obs-mcp-{uuid.uuid4().hex[:8]}"
                        fp = compute_fingerprint(raw_match, key=hmac_key)
                        obs = Observation(
                            id=obs_id,
                            detector="mcp_config",
                            rule_id="MCP-CFG-003",
                            source_reported_validity=SourceValidity.NOT_CHECKED,
                            location=LocationEvidence(
                                file_path=file_path,
                                repo_name=asset_scope,
                            ),
                            asset_scope=asset_scope,
                            candidate_fingerprint=fp,
                            redacted_match=redact_secret(raw_match),
                            raw_secret=raw_match,
                            extracted_assets=[
                                AssetCandidate(identifier=env_var, asset_type="environment_variable", evidence_level=EvidenceLevel.OBSERVED)
                            ],
                        )
                        observations.append(obs)

    # Inspect args list for literal secrets
    if isinstance(args, list):
        for arg in args:
            if isinstance(arg, str):
                for pat, cred_type in CREDENTIAL_LITERAL_PATTERNS:
                    match = pat.search(arg)
                    if match:
                        raw_match = match.group(0)
                        obs_id = f"obs-mcp-{uuid.uuid4().hex[:8]}"
                        fp = compute_fingerprint(raw_match, key=hmac_key)
                        obs = Observation(
                            id=obs_id,
                            detector="mcp_config",
                            rule_id="MCP-CFG-003",
                            source_reported_validity=SourceValidity.NOT_CHECKED,
                            location=LocationEvidence(
                                file_path=file_path,
                                repo_name=asset_scope,
                            ),
                            asset_scope=asset_scope,
                            candidate_fingerprint=fp,
                            redacted_match=redact_secret(raw_match),
                            raw_secret=raw_match,
                        )
                        observations.append(obs)

    return observations
