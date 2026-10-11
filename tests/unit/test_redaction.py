import pytest
from etw.storage.redaction import redact_secret, mask_snippet, sanitize_message


def test_redact_secret_long():
    secret = "AKIA1234567890EXAMPLEKEY"
    redacted = redact_secret(secret)
    assert "AKIA" in redacted
    assert "EY" in redacted
    assert "[REDACTED]" in redacted
    assert "1234567890EXAMPLE" not in redacted


def test_redact_secret_short():
    short_secret = "abc12"
    redacted = redact_secret(short_secret)
    assert redacted == "[REDACTED_SECRET]"


def test_mask_snippet():
    secret = "super_secret_token_123"
    snippet = "Authorization: Bearer super_secret_token_123\nHost: api.example.com"
    masked = mask_snippet(snippet, secret)
    assert secret not in masked
    assert "supe...[REDACTED]...23" in masked
    assert "Authorization: Bearer " in masked
    assert "Host: api.example.com" in masked


def test_sanitize_message():
    secret = "sensitive_password_xyz987"
    msg = f"Failed to connect using credentials sensitive_password_xyz987 at line 5"
    sanitized = sanitize_message(msg, known_secrets=[secret])
    assert secret not in sanitized
    assert "[REDACTED_SECRET]" in sanitized
