import os
import pytest
from etw.storage.fingerprint import compute_fingerprint, get_hmac_key, KEY_ENV_VAR


def test_compute_fingerprint_deterministic():
    key = b"test-key-32-bytes-long-for-hmac!!"
    secret_a = "my-secret-token-12345"
    fp1 = compute_fingerprint(secret_a, key=key)
    fp2 = compute_fingerprint(secret_a, key=key)

    assert fp1 == fp2
    assert fp1.startswith("hmac-sha256:")
    # Check length: "hmac-sha256:" (12 chars) + 32 hex chars = 44 chars
    assert len(fp1) == 44


def test_compute_fingerprint_differs_for_different_secrets():
    key = b"test-key-32-bytes-long-for-hmac!!"
    fp1 = compute_fingerprint("secret-one", key=key)
    fp2 = compute_fingerprint("secret-two", key=key)
    assert fp1 != fp2


def test_get_hmac_key_from_env(monkeypatch):
    monkeypatch.setenv(KEY_ENV_VAR, "custom-env-secret-key-123")
    key = get_hmac_key()
    assert key == b"custom-env-secret-key-123"


def test_get_hmac_key_from_file(tmp_path, monkeypatch):
    monkeypatch.delenv(KEY_ENV_VAR, raising=False)
    key_file = tmp_path / "test_hmac.key"
    key1 = get_hmac_key(key_path=str(key_file))
    assert key_file.exists()
    assert len(key1) == 32

    # Second call reads the same persisted key
    key2 = get_hmac_key(key_path=str(key_file))
    assert key1 == key2
