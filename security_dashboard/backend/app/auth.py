from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import HTTPException


def verify_ingestion(
    body: bytes,
    timestamp: str,
    signature: str,
    secret: str,
    max_age_seconds: int = 300,
) -> str:
    try:
        sent_at = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise HTTPException(401, "Invalid ingestion timestamp") from exc
    if abs(int(time.time()) - sent_at) > max_age_seconds:
        raise HTTPException(401, "Expired ingestion request")
    expected = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "Invalid ingestion signature")
    return hashlib.sha256(signature.encode()).hexdigest()
