"""
SecureVault Database Layer — SQLite backend (Zero-Knowledge)
============================================================
SQLite in WAL mode: safe concurrent access, atomic transactions, crash safety.

True zero-knowledge persistence (report §2.2 / §2.3):
  - The server stores, per user, ONE opaque ciphertext blob (the whole vault,
    AES-256-GCM encrypted *in the browser* with K_enc). The server never holds
    K_enc, the master password, or any plaintext entry.
  - Authentication stores only Auth_Hash = SHA-256(K_auth) and the public salt.
    The master password is never transmitted nor stored — only verified by a
    constant-time comparison of the client-supplied Auth_Hash.

Persistence model (maps to the UML class diagram):
  users           → Utilisateur   (auth_hash = master_password_hash, salt_hex)
  vaults          → EntreeCoffreFort (composition 1→0..*, ON DELETE CASCADE)
  security_events → JournalAudit  (type_evenement, details, score_risque_ia, ts)
"""
from __future__ import annotations

import os
import sqlite3
import time
import uuid
import threading
from pathlib import Path
from typing import Optional

# ── Configuration ──────────────────────────────────────────────────────────────

DATA_DIR = Path(os.environ.get('DATA_DIR', Path(__file__).parent.parent / 'data'))
DB_PATH = DATA_DIR / 'securevault.db'

_lock = threading.Lock()   # guards the in-memory login-attempt counter only

# ── Login-attempt rate limiting / lockout (in-memory) ───────────────────────────

_attempts: dict[str, list[float]] = {}
MAX_ATTEMPTS = 5
WINDOW_SECS = 300   # 5 minutes


# ── Database bootstrap ─────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    """Open a connection with WAL mode and foreign-key enforcement."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create schema if it does not exist. Called once at app startup."""
    with _connect() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id            TEXT PRIMARY KEY,
                username      TEXT UNIQUE NOT NULL COLLATE NOCASE,
                auth_hash     TEXT NOT NULL,         -- SHA-256(K_auth), hex
                salt_hex      TEXT NOT NULL,         -- public 32-byte salt, hex
                kdf           TEXT NOT NULL DEFAULT 'pbkdf2',
                created_at    REAL NOT NULL,
                last_login    REAL
            );

            CREATE TABLE IF NOT EXISTS vaults (
                user_id        TEXT PRIMARY KEY
                               REFERENCES users(id) ON DELETE CASCADE,
                encrypted_blob TEXT NOT NULL,        -- opaque AES-256-GCM blob
                updated_at     REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
                username    TEXT,
                event_type  TEXT NOT NULL,           -- type_evenement
                detail      TEXT NOT NULL,           -- details_metadonnees
                ip_hash     TEXT,
                risk_score  INTEGER NOT NULL DEFAULT 0,  -- score_risque_ia
                ts          REAL NOT NULL            -- horodatage_utc
            );

            CREATE INDEX IF NOT EXISTS idx_sec_events_user
                ON security_events(username, ts DESC);
            CREATE INDEX IF NOT EXISTS idx_sec_events_ts
                ON security_events(ts DESC);
        ''')


# ── User helpers ───────────────────────────────────────────────────────────────

def user_exists(username: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            'SELECT 1 FROM users WHERE username = ?', (username.lower(),)
        ).fetchone()
    return row is not None


def _get_user_row(username: str) -> Optional[sqlite3.Row]:
    with _connect() as conn:
        return conn.execute(
            'SELECT id, username, auth_hash, salt_hex, kdf FROM users WHERE username = ?',
            (username.lower(),)
        ).fetchone()


def get_salt(username: str) -> Optional[str]:
    """Return the public salt (hex) for a user, or None if unknown."""
    row = _get_user_row(username)
    return row['salt_hex'] if row else None


def get_user_kdf(username: str) -> str:
    row = _get_user_row(username)
    return row['kdf'] if row else 'pbkdf2'


def create_user(username: str, auth_hash: str, salt_hex: str,
                kdf: str, blob: str) -> tuple[bool, str]:
    """
    Register a zero-knowledge account.

    All cryptographic material is computed in the browser; the server only
    persists the public salt, Auth_Hash and the initial encrypted blob.
    """
    username = username.lower().strip()
    if len(username) < 3:
        return False, 'Username must be at least 3 characters'
    if kdf not in ('pbkdf2', 'argon2'):
        kdf = 'pbkdf2'

    uid = str(uuid.uuid4())
    now = time.time()
    try:
        with _connect() as conn:
            conn.execute(
                'INSERT INTO users (id, username, auth_hash, salt_hex, kdf, created_at) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (uid, username, auth_hash, salt_hex, kdf, now)
            )
            conn.execute(
                'INSERT INTO vaults (user_id, encrypted_blob, updated_at) VALUES (?, ?, ?)',
                (uid, blob, now)
            )
        return True, 'Account created successfully'
    except sqlite3.IntegrityError:
        return False, 'Username already taken'


def verify_auth_hash(username: str, auth_hash: str) -> tuple[bool, str]:
    """
    Authenticate by comparing the client-supplied Auth_Hash against the stored
    one in *constant time* (report §2.1). Includes an in-memory brute-force
    lockout (5 attempts / 5 minutes per username).
    """
    import hmac

    username = username.lower().strip()
    now = time.time()

    with _lock:
        recent = [t for t in _attempts.get(username, []) if now - t < WINDOW_SECS]
        if len(recent) >= MAX_ATTEMPTS:
            wait = int(WINDOW_SECS - (now - recent[0]))
            return False, f'Account locked. Try again in {wait}s'

    row = _get_user_row(username)
    # Always perform a comparison to keep timing uniform whether or not the user
    # exists (mitigates user-enumeration via response time).
    stored = row['auth_hash'] if row else ('0' * 64)
    match = hmac.compare_digest(str(stored), str(auth_hash))

    if row is not None and match:
        with _lock:
            _attempts.pop(username, None)
        with _connect() as conn:
            conn.execute('UPDATE users SET last_login = ? WHERE id = ?', (now, row['id']))
        return True, 'OK'

    with _lock:
        recent = recent + [now]
        _attempts[username] = recent
        remaining = MAX_ATTEMPTS - len(recent)
    if remaining <= 0:
        return False, f'Account locked for {WINDOW_SECS // 60} minutes'
    return False, 'Invalid username or password'


# ── Vault (opaque zero-knowledge blob) ──────────────────────────────────────────

def get_blob(username: str) -> Optional[str]:
    """Return the user's opaque encrypted vault blob, or None."""
    row = _get_user_row(username)
    if not row:
        return None
    with _connect() as conn:
        vrow = conn.execute(
            'SELECT encrypted_blob FROM vaults WHERE user_id = ?', (row['id'],)
        ).fetchone()
    return vrow['encrypted_blob'] if vrow else None


def set_blob(username: str, blob: str) -> bool:
    """Replace the user's encrypted vault blob (server stays blind)."""
    row = _get_user_row(username)
    if not row:
        return False
    with _connect() as conn:
        conn.execute(
            'UPDATE vaults SET encrypted_blob = ?, updated_at = ? WHERE user_id = ?',
            (blob, time.time(), row['id'])
        )
    return True


# ── Security events (JournalAudit) ──────────────────────────────────────────────

def log_event(username: Optional[str], event_type: str, detail: str,
              ip_hash: str = '', risk_score: int = 0) -> None:
    """Persist a security event for the SOC dashboard. Never stores secrets."""
    uid = None
    if username:
        row = _get_user_row(username)
        uid = row['id'] if row else None
    try:
        with _connect() as conn:
            conn.execute(
                'INSERT INTO security_events '
                '(user_id, username, event_type, detail, ip_hash, risk_score, ts) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (uid, (username or '').lower() or None, event_type, detail,
                 ip_hash, int(risk_score), time.time())
            )
    except sqlite3.Error:
        pass


def get_events(username: Optional[str] = None, limit: int = 200) -> list[dict]:
    """Return recent security events (most recent first)."""
    with _connect() as conn:
        if username:
            rows = conn.execute(
                'SELECT event_type, detail, ip_hash, risk_score, ts '
                'FROM security_events WHERE username = ? ORDER BY ts DESC LIMIT ?',
                (username.lower(), limit)
            ).fetchall()
        else:
            rows = conn.execute(
                'SELECT event_type, detail, ip_hash, risk_score, ts '
                'FROM security_events ORDER BY ts DESC LIMIT ?',
                (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


def get_last_logins(username: str, limit: int = 10) -> list[dict]:
    """Return recent successful logins for the 'last connections' widget."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT detail, ip_hash, ts FROM security_events "
            "WHERE username = ? AND event_type = 'LOGIN_OK' ORDER BY ts DESC LIMIT ?",
            (username.lower(), limit)
        ).fetchall()
    return [dict(r) for r in rows]
