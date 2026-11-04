"""Session signing and input validation helpers (standard library only)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
import unicodedata

SESSION_COOKIE = "bcps_session"
SESSION_TTL_SECONDS = 8 * 60 * 60

_NAME_RE = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9 _-]{0,22}[A-Za-z0-9_-]$")
_RESERVED = {"admin", "administrator", "owner", "coowner", "moderator", "mod", "staff", "system",
             "bcps", "teacher", "principal", "developer", "helper", "superadmin", "official"}
_BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_session(session: dict, secret: str) -> str:
    payload = _b64(json.dumps(session, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    return f"{payload}.{_b64(sig)}"


def verify_session(token: str | None, secret: str) -> dict | None:
    if not token or token.count(".") != 1 or len(token) > 1024:
        return None
    payload, sig = token.split(".")
    try:
        expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(sig)):
            return None
        session = json.loads(_unb64(payload))
    except (ValueError, TypeError):
        return None
    if not isinstance(session, dict) or not isinstance(session.get("id"), str):
        return None
    if float(session.get("expiresAt", 0)) < time.time():
        return None
    return session


def read_cookie(header: str | None, name: str = SESSION_COOKIE) -> str | None:
    if not header:
        return None
    for part in header.split(";"):
        key, _, value = part.strip().partition("=")
        if key == name:
            return value
    return None


def normalize_display_name(value: object) -> str | None:
    """2-24 chars: letters, numbers, spaces, hyphens, underscores. Reserved staff words are refused."""
    if not isinstance(value, str):
        return None
    name = " ".join(value.split())
    if not _NAME_RE.fullmatch(name):
        return None
    tokens = re.split(r"[\s_-]+", name.lower())
    if any(t in _RESERVED for t in tokens) or name.lower().replace(" ", "") in _RESERVED:
        return None
    return name


def clean_text(value: object, min_len: int, max_len: int, multiline: bool = False) -> str | None:
    """Trim and validate free text. Rejects control characters and bidi-override tricks."""
    if not isinstance(value, str):
        return None
    text = value.replace("\r\n", "\n").strip()
    if not (min_len <= len(text) <= max_len):
        return None
    for ch in text:
        if ch in _BIDI:
            return None
        if ch == "\n":
            if not multiline:
                return None
            continue
        if unicodedata.category(ch) in {"Cc", "Cs", "Co", "Cn"}:
            return None
    if multiline and text.count("\n") > 8:
        return None
    return text


def validate_message(value: object) -> str | None:
    return clean_text(value, 1, 500, multiline=True)
