import uuid
from pathlib import Path
from typing import Optional, Union

from etw.models.enums import SourceValidity, EvidenceLevel
from etw.models.evidence import LocationEvidence, AssetCandidate
from etw.models.observation import Observation
from etw.storage.fingerprint import compute_fingerprint, get_hmac_key
from etw.storage.redaction import redact_secret
from etw.ingest.common import IngestResult, IngestError, iter_json_records


def ingest_gitleaks(
    file_path: Union[str, Path],
    asset_scope: str = "default-scope",
    hmac_key: Optional[bytes] = None,
) -> IngestResult:
    """Ingest Gitleaks v8 JSON report into normalized Observation models.
    
    Streaming and bounded: enforces size limits and quarantines malformed records.
    Raw secrets are processed in-memory only and excluded from persistence.
    """
    if hmac_key is None:
        hmac_key = get_hmac_key()

    result = IngestResult()

    for idx, record, err in iter_json_records(file_path):
        result.total_read += 1
        if err is not None:
            result.errors.append(err)
            result.quarantined_count += 1
            continue

        # Extract raw secret match
        raw_secret = record.get("Secret") or record.get("Match")
        if not raw_secret or not isinstance(raw_secret, str):
            result.errors.append(
                IngestError(
                    record_index=idx,
                    error_code="MISSING_SECRET_FIELD",
                    message=f"Record {idx} missing valid Secret or Match value",
                )
            )
            result.quarantined_count += 1
            continue

        # Extract detector rule ID
        rule_id = str(record.get("RuleID") or record.get("Description") or "gitleaks-rule")

        # Gitleaks is a static regex scanner; does not verify live credentials
        validity = SourceValidity.NOT_CHECKED

        # Extract location evidence
        file_path_val = record.get("File") or "unknown_file"
        line_start = record.get("StartLine")
        line_end = record.get("EndLine")
        col_start = record.get("StartColumn")
        col_end = record.get("EndColumn")
        commit_hash = record.get("Commit")
        author = record.get("Email") or record.get("Author")
        date_val = record.get("Date")

        location = LocationEvidence(
            file_path=str(file_path_val),
            line_start=int(line_start) if isinstance(line_start, int) else None,
            line_end=int(line_end) if isinstance(line_end, int) else None,
            column_start=int(col_start) if isinstance(col_start, int) else None,
            column_end=int(col_end) if isinstance(col_end, int) else None,
            commit_hash=str(commit_hash) if commit_hash else None,
            commit_author=str(author) if author else None,
            commit_timestamp=str(date_val) if date_val else None,
            repo_name=asset_scope,
        )

        # Compute keyed fingerprint
        fingerprint = compute_fingerprint(raw_secret, key=hmac_key)

        # Redaction
        redacted = redact_secret(raw_secret)

        # Context / Candidate Asset associations
        assets = []
        if asset_scope and asset_scope != "default-scope":
            assets.append(
                AssetCandidate(
                    identifier=asset_scope,
                    asset_type="repo",
                    evidence_level=EvidenceLevel.OBSERVED,
                )
            )
        if file_path_val and file_path_val != "unknown_file":
            assets.append(
                AssetCandidate(
                    identifier=str(file_path_val),
                    asset_type="file",
                    evidence_level=EvidenceLevel.OBSERVED,
                )
            )

        obs = Observation(
            id=f"obs-gl-{uuid.uuid4().hex[:12]}",
            detector="gitleaks",
            rule_id=rule_id,
            source_reported_validity=validity,
            location=location,
            asset_scope=asset_scope,
            candidate_fingerprint=fingerprint,
            redacted_match=redacted,
            raw_secret=raw_secret,  # in-memory only; Field(exclude=True)
            extracted_assets=assets,
        )

        result.observations.append(obs)
        result.successful_count += 1

    return result
