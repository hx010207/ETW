import hashlib
import hmac
import os
import secrets
from pathlib import Path
from typing import Optional

KEY_ENV_VAR = "ETW_HMAC_KEY"
DEFAULT_KEY_PATH = ".etw/hmac.key"


def get_hmac_key(explicit_key: Optional[str] = None, key_path: Optional[str] = None) -> bytes:
    """Retrieve or generate the HMAC secret key.
    
    Order of precedence:
    1. Explicit key argument.
    2. Environment variable ETW_HMAC_KEY.
    3. Local file (default .etw/hmac.key). If absent, generate a 32-byte cryptographically secure key.
    """
    if explicit_key:
        return explicit_key.encode("utf-8")

    env_key = os.environ.get(KEY_ENV_VAR)
    if env_key:
        return env_key.encode("utf-8")

    path = Path(key_path or DEFAULT_KEY_PATH)
    if path.is_file():
        existing = path.read_bytes()
        if len(existing.strip()) >= 16:
            return existing

    # Generate new secure key
    path.parent.mkdir(parents=True, exist_ok=True)
    new_key = secrets.token_bytes(32)
    path.write_bytes(new_key)

    # Restrict permissions on POSIX
    try:
        os.chmod(path, 0o600)
    except (OSError, AttributeError):
        pass

    return new_key


def compute_fingerprint(raw_secret: str, key: Optional[bytes] = None) -> str:
    """Generate a keyed HMAC-SHA256 fingerprint truncated to 32 hex characters.
    
    Format: hmac-sha256:[a-f0-9]{32}
    """
    if key is None:
        key = get_hmac_key()

    normalized = raw_secret.strip().encode("utf-8")
    digest = hmac.new(key, normalized, hashlib.sha256).hexdigest()[:32]
    return f"hmac-sha256:{digest}"
