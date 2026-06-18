from __future__ import annotations

import base64
import hashlib
import hmac
import os


HASH_NAME = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 600_000


def hash_password(
    password: str,
    *,
    iterations: int = DEFAULT_ITERATIONS,
    salt: bytes | None = None,
) -> str:
    """Create a PBKDF2 password hash suitable for Streamlit secrets."""
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "$".join((
        HASH_NAME,
        str(iterations),
        base64.urlsafe_b64encode(salt).decode(),
        base64.urlsafe_b64encode(digest).decode(),
    ))


def verify_password(password: str, encoded_hash: str) -> bool:
    """Validate a password without exposing timing differences."""
    try:
        name, iterations_text, salt_text, digest_text = encoded_hash.split("$", 3)
        if name != HASH_NAME:
            return False
        iterations = int(iterations_text)
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
    except (TypeError, ValueError, UnicodeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return hmac.compare_digest(actual, expected)
