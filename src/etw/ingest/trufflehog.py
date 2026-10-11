import uuid
from pathlib import Path
from typing import Optional, Union

from etw.models.enums import SourceValidity, EvidenceLevel
from etw.models.evidence import LocationEvidence, AssetCandidate
from etw.models.observation import Observation
from etw.storage.fingerprint import compute_fingerprint, get_hmac_key
from etw.storage.redaction import redact_secret
from etw.ingest.common import IngestResult, IngestError, iter_json_records


def ingest_trufflehog(
    file_path: Union[str, Path],
    asset_scope: str = "default-scope",
    hmac_key: Optional[bytes] = None,
) -> IngestResult:
    """Ingest TruffleHog v3 JSON or JSONL report into normalized Observation models.
    
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

        # Extract raw candidate value
        raw_secret = (
            record.get("Raw")
            or record.get("RawV2")
            or record.get("Secret")
            or record.get("Match")
        )
        if not raw_secret or not isinstance(raw_secret, str):
            result.errors.append(
                IngestError(
                    record_index=idx,
                    error_code="MISSING_SECRET_FIELD",
                    message=f"Record {idx} missing valid Raw secret value",
                )
            )
            result.quarantined_count += 1
            continue

        # Extract detector metadata
        rule_id = str(record.get("DetectorName") or record.get("DetectorDescription") or "trufflehog-finding")

        # Map source validity
        verified_val = record.get("Verified")
        if verified_val is True:
            validity = SourceValidity.VERIFIED
        elif verified_val is False:
            validity = SourceValidity.UNVERIFIED
        else:
            validity = SourceValidity.UNKNOWN

        # Extract location evidence
        src_meta = record.get("SourceMetadata") or {}
        src_data = src_meta.get("Data") or {}
        git_data = src_data.get("Git") or {}
        fs_data = src_data.get("Filesystem") or {}

        file_path_val = (
            git_data.get("file")
            or fs_data.get("file")
            or record.get("File")
            or "unknown_file"
        )
        line_start = git_data.get("line") or fs_data.get("line") or record.get("Line")
        commit_hash = git_data.get("commit")
        commit_author = git_data.get("email") or git_data.get("author")
        repo_name = git_data.get("repository")

        location = LocationEvidence(
            file_path=str(file_path_val),
            line_start=int(line_start) if isinstance(line_start, (int, str)) and str(line_start).isdigit() else None,
            commit_hash=str(commit_hash) if commit_hash else None,
            commit_author=str(commit_author) if commit_author else None,
            repo_name=str(repo_name) if repo_name else None,
        )

        effective_scope = location.repo_name or asset_scope

        # Compute keyed fingerprint
        fingerprint = compute_fingerprint(raw_secret, key=hmac_key)

        # Always enforce ETW redaction guarantee
        redacted = redact_secret(raw_secret)

        # Context / Candidate Asset associations
        assets = []
        if location.repo_name:
            assets.append(
                AssetCandidate(
                    identifier=location.repo_name,
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
            id=f"obs-th-{uuid.uuid4().hex[:12]}",
            detector="trufflehog",
            rule_id=rule_id,
            source_reported_validity=validity,
            location=location,
            asset_scope=effective_scope,
            candidate_fingerprint=fingerprint,
            redacted_match=redacted,
            raw_secret=raw_secret,  # in-memory only; Field(exclude=True)
            extracted_assets=assets,
        )

        result.observations.append(obs)
        result.successful_count += 1

    return result
