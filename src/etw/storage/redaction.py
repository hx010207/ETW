import re
from typing import List, Optional


def redact_secret(raw_secret: str, show_prefix_len: int = 4, show_suffix_len: int = 2) -> str:
    """Mask a secret string preserving non-sensitive prefix and suffix if sufficiently long."""
    if not raw_secret:
        return "[EMPTY]"

    if len(raw_secret) < (show_prefix_len + show_suffix_len + 3):
        return "[REDACTED_SECRET]"

    prefix = raw_secret[:show_prefix_len]
    suffix = raw_secret[-show_suffix_len:]
    return f"{prefix}...[REDACTED]...{suffix}"


def mask_snippet(snippet: str, raw_secret: str) -> str:
    """Mask occurrences of a raw secret within surrounding context code."""
    if not snippet or not raw_secret:
        return snippet or ""

    redacted = redact_secret(raw_secret)
    return snippet.replace(raw_secret, redacted)


def sanitize_message(message: str, known_secrets: Optional[List[str]] = None) -> str:
    """Sanitize error messages or log entries against a list of known secrets."""
    if not message:
        return ""

    sanitized = message
    if known_secrets:
        for secret in known_secrets:
            if secret and len(secret) >= 3:
                sanitized = sanitized.replace(secret, "[REDACTED_SECRET]")

    return sanitized


ANSI_ESCAPE_PATTERN = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
NON_PRINTABLE_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_terminal_output(text: str) -> str:
    """
    Strip ANSI escape codes and dangerous terminal control characters from text.
    Protects against terminal injection, screen clearing, and cursor manipulation attacks.
    """
    if not text:
        return ""
    clean = ANSI_ESCAPE_PATTERN.sub("", str(text))
    clean = NON_PRINTABLE_PATTERN.sub("", clean)
    return clean

