"""Security primitives: HMAC tokens, API-key checks and rate limiting.

Deliberately stdlib-only (hmac/hashlib/base64) so the audit service has no
extra crypto dependency to get wrong.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable


class SecurityError(Exception):
    """Raised when a request fails an authentication or rate check."""

    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.status_code = status_code


# --------------------------------------------------------------------------
# Signed tokens
# --------------------------------------------------------------------------
def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def issue_token(secret: str, subject: str, ttl_seconds: int) -> str:
    """Return an ``<payload>.<signature>`` token signed with HMAC-SHA256."""
    payload = {"sub": subject, "exp": int(time.time()) + int(ttl_seconds)}
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64encode(sig)}"


def verify_token(secret: str, token: str) -> dict:
    """Validate a token, returning its payload or raising ``SecurityError``."""
    try:
        body, sig = token.rsplit(".", 1)
    except ValueError as exc:
        raise SecurityError("malformed token") from exc

    expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64decode(sig), expected):
        raise SecurityError("bad signature")

    try:
        payload = json.loads(_b64decode(body))
    except (ValueError, json.JSONDecodeError) as exc:
        raise SecurityError("unreadable payload") from exc

    if int(payload.get("exp", 0)) < time.time():
        raise SecurityError("token expired")
    return payload


def check_api_key(configured: Iterable[str], supplied: str | None) -> bool:
    """Constant-time API key comparison.

    An empty ``configured`` list means auth is disabled and every key passes.
    """
    configured = list(configured)
    if not configured:
        return True
    if not supplied:
        return False
    return any(hmac.compare_digest(k, supplied) for k in configured)


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------
@dataclass
class _Bucket:
    tokens: float
    updated: float


class TokenBucketRateLimiter:
    """Thread-safe per-key token bucket.

    Chosen over a Redis-backed limiter so the service works standalone; the
    interface is intentionally narrow so a distributed backend can be swapped
    in later.
    """

    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self._buckets: dict[str, _Bucket] = defaultdict(
            lambda: _Bucket(tokens=self.capacity, updated=time.monotonic())
        )
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        with self._lock:
            bucket = self._buckets[key]
            now = time.monotonic()
            elapsed = now - bucket.updated
            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.refill_per_sec)
            bucket.updated = now
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True
            return False

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


def client_key(headers: dict[str, str], fallback_ip: str | None) -> str:
    """Derive a stable rate-limit key, preferring an API key over an IP."""
    api_key = headers.get("x-api-key") or headers.get("authorization")
    if api_key:
        return "key:" + hashlib.sha256(api_key.encode()).hexdigest()[:16]
    return "ip:" + (fallback_ip or "unknown")
