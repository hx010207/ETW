import json
import pytest
from pathlib import Path

from etw.models.enums import SourceValidity
from etw.ingest.trufflehog import ingest_trufflehog
from etw.ingest.gitleaks import ingest_gitleaks
from etw.ingest.common import MAX_FILE_SIZE_BYTES, MAX_RECORD_SIZE_BYTES


def test_trufflehog_ingest_json_array(tmp_path):
    records = [
        {
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "commit": "aabbcc112233",
                        "file": "backend/auth.py",
                        "line": 42,
                        "email": "dev@company.com",
                        "repository": "https://github.com/company/backend",
                    }
                }
            },
            "DetectorName": "AWS",
            "Verified": True,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "Redacted": "AKIA****************",
        },
        {
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "docs/quickstart.md",
                        "line": 15,
                    }
                }
            },
            "DetectorName": "SlackWebhook",
            "Verified": False,
            "Raw": "https://hooks.slack.com/services/T000/B000/XXXXXEXAMPLE",
            "Redacted": "https://hooks.slack.com/services/T000/B000/****************",
        },
    ]

    file_path = tmp_path / "trufflehog_sample.json"
    file_path.write_text(json.dumps(records), encoding="utf-8")

    result = ingest_trufflehog(str(file_path), asset_scope="company/backend")
    assert result.successful_count == 2
    assert result.quarantined_count == 0
    assert len(result.observations) == 2

    obs1 = result.observations[0]
    assert obs1.detector == "trufflehog"
    assert obs1.rule_id == "AWS"
    assert obs1.source_reported_validity == SourceValidity.VERIFIED
    assert obs1.location.file_path == "backend/auth.py"
    assert obs1.location.line_start == 42
    assert obs1.location.commit_hash == "aabbcc112233"
    assert obs1.candidate_fingerprint.startswith("hmac-sha256:")
    assert obs1.raw_secret == "AKIAIOSFODNN7EXAMPLE"

    obs2 = result.observations[1]
    assert obs2.source_reported_validity == SourceValidity.UNVERIFIED
    assert obs2.location.file_path == "docs/quickstart.md"


def test_trufflehog_ingest_jsonl(tmp_path):
    lines = [
        json.dumps({
            "DetectorName": "GitHubToken",
            "Verified": False,
            "Raw": "ghp_EXAMPLETOKEN1234567890abcdefghij",
            "SourceMetadata": {"Data": {"Git": {"file": "token.txt", "line": 1}}}
        }),
        json.dumps({
            "DetectorName": "StripeKey",
            "Verified": False,
            "Raw": "sk_test_EXAMPLE1234567890abcdef",
            "SourceMetadata": {"Data": {"Git": {"file": "stripe.py", "line": 10}}}
        }),
    ]

    file_path = tmp_path / "trufflehog_sample.jsonl"
    file_path.write_text("\n".join(lines), encoding="utf-8")

    result = ingest_trufflehog(str(file_path), asset_scope="my-repo")
    assert result.successful_count == 2
    assert result.quarantined_count == 0


def test_gitleaks_ingest_valid(tmp_path):
    records = [
        {
            "Description": "AWS Access Token",
            "StartLine": 10,
            "EndLine": 10,
            "StartColumn": 1,
            "EndColumn": 20,
            "Match": "AKIAEXAMPLEKEY987654",
            "Secret": "AKIAEXAMPLEKEY987654",
            "File": "src/settings.py",
            "Commit": "fedcba9876543210",
            "Author": "alice",
            "Email": "alice@company.com",
            "Date": "2026-01-15T10:00:00Z",
            "RuleID": "aws-access-key",
        }
    ]

    file_path = tmp_path / "gitleaks_sample.json"
    file_path.write_text(json.dumps(records), encoding="utf-8")

    result = ingest_gitleaks(str(file_path), asset_scope="company/service")
    assert result.successful_count == 1
    assert result.quarantined_count == 0

    obs = result.observations[0]
    assert obs.detector == "gitleaks"
    assert obs.rule_id == "aws-access-key"
    assert obs.source_reported_validity == SourceValidity.NOT_CHECKED
    assert obs.location.file_path == "src/settings.py"
    assert obs.location.line_start == 10
    assert obs.location.commit_author == "alice@company.com"
    assert obs.raw_secret == "AKIAEXAMPLEKEY987654"


def test_malformed_records_quarantine_without_crashing(tmp_path):
    # One valid record, one malformed JSON line, one record missing secret
    lines = [
        json.dumps({
            "DetectorName": "APIKey",
            "Raw": "valid_api_key_12345",
            "SourceMetadata": {"Data": {"Git": {"file": "valid.py", "line": 5}}}
        }),
        "{ corrupted json line: missing closing brace",
        json.dumps({
            "DetectorName": "EmptyFinding",
            # missing "Raw"
            "SourceMetadata": {"Data": {"Git": {"file": "empty.py", "line": 8}}}
        }),
    ]

    file_path = tmp_path / "mixed.jsonl"
    file_path.write_text("\n".join(lines), encoding="utf-8")

    result = ingest_trufflehog(str(file_path), asset_scope="test-scope")
    assert result.successful_count == 1
    assert result.quarantined_count == 2
    assert len(result.errors) == 2

    # Check errors don't leak raw secrets
    for err in result.errors:
        assert "valid_api_key_12345" not in err.message


def test_empty_input_file(tmp_path):
    file_path = tmp_path / "empty.json"
    file_path.write_text("", encoding="utf-8")

    result = ingest_trufflehog(str(file_path), asset_scope="test-scope")
    assert result.successful_count == 0
    assert result.quarantined_count == 0
    assert len(result.observations) == 0


def test_oversized_file_raises_value_error(tmp_path, monkeypatch):
    file_path = tmp_path / "huge.json"
    file_path.write_text("dummy", encoding="utf-8")

    # Mock MAX_FILE_SIZE_BYTES to tiny value for test
    from etw.ingest import common
    monkeypatch.setattr(common, "MAX_FILE_SIZE_BYTES", 3)

    with pytest.raises(ValueError, match="exceeds maximum allowed size"):
        ingest_trufflehog(str(file_path), asset_scope="test-scope")
