import json
from pathlib import Path
import pytest

from etw.ingest.trufflehog import ingest_trufflehog
from etw.ingest.gitleaks import ingest_gitleaks

FIXTURE_DIR = Path("datasets/fixtures-v1")


def test_fixture_counts_and_symmetry():
    th_file = FIXTURE_DIR / "trufflehog_fixtures.jsonl"
    gl_file = FIXTURE_DIR / "gitleaks_fixtures.json"
    gt_file = FIXTURE_DIR / "ground_truth.json"

    assert th_file.is_file()
    assert gl_file.is_file()
    assert gt_file.is_file()

    # Ground truth must contain exactly 68 items
    ground_truth = json.loads(gt_file.read_text(encoding="utf-8"))
    assert len(ground_truth) == 68

    # TruffleHog must have 34 lines
    th_lines = [line for line in th_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(th_lines) == 34

    # Gitleaks must have 34 objects in list
    gl_data = json.loads(gl_file.read_text(encoding="utf-8"))
    assert isinstance(gl_data, list)
    assert len(gl_data) == 34


def test_trufflehog_fixtures_ingestion():
    th_file = FIXTURE_DIR / "trufflehog_fixtures.jsonl"
    result = ingest_trufflehog(str(th_file))

    # 34 total: 31 valid records + 3 malformed edge cases quarantined
    assert result.total_read == 34
    assert result.successful_count == 31
    assert result.quarantined_count == 3
    assert len(result.observations) == 31
    assert len(result.errors) == 3


def test_gitleaks_fixtures_ingestion():
    gl_file = FIXTURE_DIR / "gitleaks_fixtures.json"
    result = ingest_gitleaks(str(gl_file))

    # 34 total: 31 valid records + 3 malformed edge cases quarantined
    assert result.total_read == 34
    assert result.successful_count == 31
    assert result.quarantined_count == 3
    assert len(result.observations) == 31
    assert len(result.errors) == 3


def test_combined_dataset_totals():
    th_file = FIXTURE_DIR / "trufflehog_fixtures.jsonl"
    gl_file = FIXTURE_DIR / "gitleaks_fixtures.json"

    th_res = ingest_trufflehog(str(th_file))
    gl_res = ingest_gitleaks(str(gl_file))

    total_valid = th_res.successful_count + gl_res.successful_count
    total_quarantined = th_res.quarantined_count + gl_res.quarantined_count

    assert total_valid == 62
    assert total_quarantined == 6
    assert (total_valid + total_quarantined) == 68
