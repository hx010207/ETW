import json
from pathlib import Path
import pytest

from etw.ingest.trufflehog import ingest_trufflehog
from etw.ingest.gitleaks import ingest_gitleaks


def test_zero_raw_secrets_in_model_serialization():
    th_file = Path("datasets/fixtures-v1/trufflehog_fixtures.jsonl")
    gl_file = Path("datasets/fixtures-v1/gitleaks_fixtures.json")

    th_result = ingest_trufflehog(str(th_file))
    gl_result = ingest_gitleaks(str(gl_file))

    all_obs = th_result.observations + gl_result.observations

    # Extract all raw secrets from the in-memory models
    raw_secrets = [obs.raw_secret for obs in all_obs if obs.raw_secret]
    assert len(raw_secrets) > 0, "Expected non-empty set of raw secrets in memory"

    for obs in all_obs:
        dumped_dict = obs.model_dump()
        dumped_json = obs.model_dump_json()
        obs_repr = repr(obs)
        obs_str = str(obs)

        # Assert no raw secret survives in any serialized representation
        for secret in raw_secrets:
            # Skip very short common prefixes/substrings, only check substantial secrets (>= 8 chars)
            if len(secret) < 8:
                continue

            assert secret not in dumped_dict.values(), (
                f"Secret leaked in model_dump() dict values: {secret[:4]}..."
            )
            assert secret not in str(dumped_dict), (
                f"Secret leaked in str(model_dump()): {secret[:4]}..."
            )
            assert secret not in dumped_json, (
                f"Secret leaked in model_dump_json(): {secret[:4]}..."
            )
            assert secret not in obs_repr, (
                f"Secret leaked in repr(Observation): {secret[:4]}..."
            )
            assert secret not in obs_str, (
                f"Secret leaked in str(Observation): {secret[:4]}..."
            )


def test_zero_raw_secrets_in_error_messages(tmp_path):
    # Craft a synthetic canary secret
    canary_secret = "CANARY_TOKEN_UNDER_LEAK_TEST_998877"
    malformed_line = (
        f'{{"DetectorName": "CanaryTest", "Raw": "{canary_secret}", '
        f'"SourceMetadata": {{"broken_json'
    )

    bad_file = tmp_path / "bad_input.jsonl"
    bad_file.write_text(malformed_line, encoding="utf-8")

    result = ingest_trufflehog(str(bad_file))
    assert result.quarantined_count == 1
    assert len(result.errors) == 1

    err = result.errors[0]
    # Verify the canary secret was never echoed into the error message
    assert canary_secret not in err.message
    assert canary_secret not in str(err)
    assert canary_secret not in repr(err)


def test_seeded_secret_not_in_quarantined_records(tmp_path):
    seeded_secret = "SEEDED_SUPER_SECRET_VALUE_ABCXYZ_99"
    # Finding with non-string raw secret type to trigger quarantine
    bad_record = {
        "DetectorName": "BadType",
        "Raw": 123456789,  # invalid type
        "Comment": f"Notes referencing {seeded_secret}",
    }

    bad_file = tmp_path / "bad_type.json"
    bad_file.write_text(json.dumps([bad_record]), encoding="utf-8")

    result = ingest_gitleaks(str(bad_file))
    assert result.quarantined_count == 1

    for err in result.errors:
        assert seeded_secret not in err.message
        assert seeded_secret not in err.model_dump_json()
