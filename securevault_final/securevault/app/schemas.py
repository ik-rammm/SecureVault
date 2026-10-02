"""
SecureVault — Input Validation Schemas
========================================
Centralised, strict validation for all API payloads.
Provides clear error messages without any external dependency.
"""
from __future__ import annotations

import re
from typing import Any

# ── Patterns ───────────────────────────────────────────────────────────────────

_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_-]{3,32}$')
_URL_RE      = re.compile(r'^https?://', re.IGNORECASE)
_HEX64_RE    = re.compile(r'^[0-9a-fA-F]{64}$')   # 32 bytes (salt / SHA-256 hash)

MAX_BLOB_LEN = 8 * 1024 * 1024   # 8 MB of base64 ciphertext — generous per-vault cap


# ── Exception ──────────────────────────────────────────────────────────────────

class ValidationError(Exception):
    """Raised when input fails validation. Carries field + message."""

    def __init__(self, field: str, message: str) -> None:
        self.field   = field
        self.message = message
        super().__init__(f'{field}: {message}')

    def to_response(self) -> dict[str, str]:
        return {'error': self.message, 'field': self.field}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _str(data: dict[str, Any], key: str, default: str = '') -> str:
    return str(data.get(key, default))


def _int_clamp(data: dict[str, Any], key: str, default: int,
               lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(data.get(key, default))))
    except (TypeError, ValueError):
        return default


def _bool(data: dict[str, Any], key: str, default: bool = True) -> bool:
    val = data.get(key, default)
    if isinstance(val, bool):
        return val
    return str(val).lower() not in ('false', '0', 'no', '')


# ── Schemas ────────────────────────────────────────────────────────────────────

def validate_register(data: dict[str, Any]) -> dict[str, Any]:
    """
    Validate /api/v1/auth/register payload (zero-knowledge).

    The client computes all cryptographic material in the browser and sends:
      - username
      - salt_hex   : 32-byte public salt (hex)
      - auth_hash  : SHA-256(K_auth) (hex) — the only credential the server sees
      - kdf        : 'pbkdf2' | 'argon2'
      - blob       : initial AES-256-GCM encrypted vault (base64)
    The master password is NEVER part of this payload.
    """
    username  = _str(data, 'username').strip()
    salt_hex  = _str(data, 'salt_hex').strip()
    auth_hash = _str(data, 'auth_hash').strip()
    kdf       = _str(data, 'kdf', 'pbkdf2')
    blob      = _str(data, 'blob')

    if not _USERNAME_RE.match(username):
        raise ValidationError('username', 'Must be 3–32 characters: letters, digits, _ or -')
    if not _HEX64_RE.match(salt_hex):
        raise ValidationError('salt_hex', 'Must be 64 hex characters (32 bytes)')
    if not _HEX64_RE.match(auth_hash):
        raise ValidationError('auth_hash', 'Must be 64 hex characters (SHA-256)')
    if kdf not in ('pbkdf2', 'argon2'):
        raise ValidationError('kdf', "Must be 'pbkdf2' or 'argon2'")
    if not blob:
        raise ValidationError('blob', 'Initial encrypted vault required')
    if len(blob) > MAX_BLOB_LEN:
        raise ValidationError('blob', 'Encrypted vault too large')

    return {
        'username':  username.lower(),
        'salt_hex':  salt_hex.lower(),
        'auth_hash': auth_hash.lower(),
        'kdf':       kdf,
        'blob':      blob,
    }


def validate_login(data: dict[str, Any]) -> dict[str, str]:
    """
    Validate /api/v1/auth/login payload (zero-knowledge).

    The client derives the keys locally and sends only Auth_Hash = SHA-256(K_auth).
    """
    username  = _str(data, 'username').strip().lower()
    auth_hash = _str(data, 'auth_hash').strip()

    if not username:
        raise ValidationError('username', 'Required')
    if not _HEX64_RE.match(auth_hash):
        raise ValidationError('auth_hash', 'Invalid authentication proof')

    return {'username': username, 'auth_hash': auth_hash.lower()}


def validate_blob(data: dict[str, Any]) -> dict[str, str]:
    """Validate a vault-blob upload (PUT /api/v1/vault/blob)."""
    blob = _str(data, 'blob')
    if not blob:
        raise ValidationError('blob', 'Encrypted vault required')
    if len(blob) > MAX_BLOB_LEN:
        raise ValidationError('blob', 'Encrypted vault too large')
    return {'blob': blob}


def validate_entry(data: dict[str, Any]) -> dict[str, Any]:
    """Validate vault entry create/update payload."""
    title = _str(data, 'title').strip()
    if not title:
        raise ValidationError('title', 'Required')
    if len(title) > 255:
        raise ValidationError('title', 'Must be at most 255 characters')

    url = _str(data, 'url').strip()
    if url and not _URL_RE.match(url):
        raise ValidationError('url', 'Must start with http:// or https://')
    if len(url) > 2048:
        raise ValidationError('url', 'Must be at most 2048 characters')

    notes = _str(data, 'notes')
    if len(notes) > 10_000:
        raise ValidationError('notes', 'Must be at most 10,000 characters')

    raw_tags = data.get('tags', [])
    if not isinstance(raw_tags, list):
        raw_tags = []
    tags = [str(t)[:50] for t in raw_tags[:20]]

    return {
        'title':    title[:255],
        'username': _str(data, 'username')[:255],
        'password': _str(data, 'password')[:4096],
        'url':      url,
        'notes':    notes,
        'category': _str(data, 'category', 'General')[:50],
        'tags':     tags,
    }


def validate_generate(data: dict[str, Any]) -> dict[str, Any]:
    """Validate /api/v1/generate payload."""
    return {
        'length':   _int_clamp(data, 'length', 20, 8, 128),
        'uppercase': _bool(data, 'uppercase', True),
        'digits':   _bool(data, 'digits', True),
        'symbols':  _bool(data, 'symbols', True),
        'exclude':  _str(data, 'exclude')[:64],
    }


def validate_strength(data: dict[str, Any]) -> dict[str, str]:
    """Validate /api/v1/security/strength payload."""
    pwd = _str(data, 'password')
    if len(pwd) > 4096:
        raise ValidationError('password', 'Too long')
    return {'password': pwd}
