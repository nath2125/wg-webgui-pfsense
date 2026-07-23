"""Auth/security helpers: password hashing, CSRF, login lockout.

Uses only the standard library (scrypt) so there is no extra dependency for
password hashing.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from urllib.parse import quote

from starlette.requests import Request

# scrypt work factors (OpenSSL needs maxmem >= 128*r*N).
_N = 2 ** 14
_R = 8
_P = 1
_MAXMEM = 128 * _R * _N * 2  # comfortable headroom


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(
        password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32, maxmem=_MAXMEM
    )
    return "scrypt${}${}".format(
        base64.b64encode(salt).decode(), base64.b64encode(dk).decode()
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_b64, dk_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(
            password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=len(expected), maxmem=_MAXMEM
        )
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# CSRF (double-submit via session)
# --------------------------------------------------------------------------- #
def get_or_create_csrf(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def verify_csrf(request: Request, provided: str | None) -> bool:
    expected = request.session.get("csrf", "")
    return bool(provided) and bool(expected) and hmac.compare_digest(provided, expected)


# --------------------------------------------------------------------------- #
# Login lockout (in-memory, per client IP)
# --------------------------------------------------------------------------- #
class LoginGuard:
    def __init__(self, max_attempts: int, lockout_seconds: int):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._state: dict[str, list[float]] = {}  # ip -> [fail_count, locked_until]

    def seconds_locked(self, ip: str) -> int:
        entry = self._state.get(ip)
        if not entry:
            return 0
        remaining = entry[1] - time.time()
        return int(remaining) if remaining > 0 else 0

    def record_failure(self, ip: str) -> None:
        entry = self._state.setdefault(ip, [0, 0.0])
        entry[0] += 1
        if entry[0] >= self.max_attempts:
            entry[1] = time.time() + self.lockout_seconds
            entry[0] = 0  # reset counter; lock window now governs

    def record_success(self, ip: str) -> None:
        self._state.pop(ip, None)


# --------------------------------------------------------------------------- #
# TOTP 2FA (RFC 6238, HMAC-SHA1, 6 digits, 30s) — stdlib only
# --------------------------------------------------------------------------- #
def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32 + pad, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    code = code.zfill(6)
    counter = int(time.time() // 30)
    for w in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret, counter + w), code):
            return True
    return False


def totp_provisioning_uri(secret: str, account: str, issuer: str) -> str:
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
            "&algorithm=SHA1&digits=6&period=30")


def client_ip(request: Request, trust_proxy: bool = False) -> str:
    """The client address used to key login lockout.

    X-Forwarded-For is only honoured when the deployment explicitly says it sits
    behind a trusted reverse proxy. Otherwise any client could vary the header per
    request and never accumulate failures against a single key — i.e. walk straight
    past the lockout.
    """
    if trust_proxy:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
