"""
SecureVault — Unit Tests: Database Layer (Zero-Knowledge)
=========================================================
Validates the SQLite persistence layer: ZK account creation, constant-time
Auth_Hash verification, brute-force lockout, opaque blob storage, the security
event journal (JournalAudit) and the ON DELETE CASCADE composition.

Run:
    cd securevault
    python -m pytest tests/test_database.py -v
"""
from __future__ import annotations

import base64
import hashlib
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def _hex32() -> str:
    return os.urandom(32).hex()


def _ah(secret: bytes) -> str:
    return hashlib.sha256(secret).hexdigest()


def _blob(payload: bytes = b'{}') -> str:
    return base64.b64encode(payload).decode()


@pytest.fixture()
def db(tmp_path, monkeypatch):
    """Fresh, isolated database module per test."""
    monkeypatch.setenv('DATA_DIR', str(tmp_path))
    import app.database as database
    importlib.reload(database)
    database.init_db()
    return database


# ── Account creation ─────────────────────────────────────────────────────────

class TestAccounts:
    def test_create_user_succeeds(self, db):
        ok, msg = db.create_user('alice', _ah(b's'), _hex32(), 'pbkdf2', _blob())
        assert ok is True

    def test_duplicate_username_rejected(self, db):
        db.create_user('bob', _ah(b's'), _hex32(), 'pbkdf2', _blob())
        ok, msg = db.create_user('bob', _ah(b's2'), _hex32(), 'pbkdf2', _blob())
        assert ok is False

    def test_user_exists(self, db):
        assert db.user_exists('carol') is False
        db.create_user('carol', _ah(b's'), _hex32(), 'pbkdf2', _blob())
        assert db.user_exists('carol') is True

    def test_get_salt_and_kdf(self, db):
        salt = _hex32()
        db.create_user('dave', _ah(b's'), salt, 'argon2', _blob())
        assert db.get_salt('dave') == salt
        assert db.get_user_kdf('dave') == 'argon2'
        assert db.get_salt('ghost') is None


# ── Authentication (constant-time + lockout) ─────────────────────────────────

class TestAuth:
    def test_correct_proof_authenticates(self, db):
        db.create_user('eve', _ah(b'secret'), _hex32(), 'pbkdf2', _blob())
        ok, msg = db.verify_auth_hash('eve', _ah(b'secret'))
        assert ok is True

    def test_wrong_proof_rejected(self, db):
        db.create_user('frank', _ah(b'right'), _hex32(), 'pbkdf2', _blob())
        ok, msg = db.verify_auth_hash('frank', _ah(b'wrong'))
        assert ok is False

    def test_unknown_user_rejected(self, db):
        ok, msg = db.verify_auth_hash('nobody', _ah(b'x'))
        assert ok is False

    def test_lockout_after_max_attempts(self, db):
        db.create_user('grace', _ah(b'right'), _hex32(), 'pbkdf2', _blob())
        for _ in range(db.MAX_ATTEMPTS):
            db.verify_auth_hash('grace', _ah(b'bad'))
        ok, msg = db.verify_auth_hash('grace', _ah(b'right'))
        assert ok is False
        assert 'locked' in msg.lower()


# ── Vault blob (opaque) ──────────────────────────────────────────────────────

class TestVaultBlob:
    def test_initial_blob_present(self, db):
        blob = _blob(b'{"entries":[]}')
        db.create_user('heidi', _ah(b's'), _hex32(), 'pbkdf2', blob)
        assert db.get_blob('heidi') == blob

    def test_set_blob_updates(self, db):
        db.create_user('ivan', _ah(b's'), _hex32(), 'pbkdf2', _blob())
        new = _blob(b'{"entries":[{"id":"x"}]}')
        assert db.set_blob('ivan', new) is True
        assert db.get_blob('ivan') == new

    def test_get_blob_unknown_user(self, db):
        assert db.get_blob('ghost') is None


# ── Security events (JournalAudit) ───────────────────────────────────────────

class TestEvents:
    def test_log_and_get_events(self, db):
        db.create_user('judy', _ah(b's'), _hex32(), 'pbkdf2', _blob())
        db.log_event('judy', 'LOGIN_OK', 'ok', 'abc123', 10)
        db.log_event('judy', 'LOGIN_FAIL', 'bad', 'abc123', 40)
        evs = db.get_events('judy')
        assert len(evs) == 2
        assert evs[0]['event_type'] == 'LOGIN_FAIL'   # most recent first
        assert evs[0]['risk_score'] == 40

    def test_last_logins(self, db):
        db.create_user('mallory', _ah(b's'), _hex32(), 'pbkdf2', _blob())
        db.log_event('mallory', 'LOGIN_OK', 'ok', 'h', 0)
        db.log_event('mallory', 'LOGIN_FAIL', 'no', 'h', 0)
        last = db.get_last_logins('mallory')
        assert len(last) == 1


# ── Composition / CASCADE ────────────────────────────────────────────────────

class TestCascade:
    def test_deleting_user_cascades_vault(self, db):
        db.create_user('niaj', _ah(b's'), _hex32(), 'pbkdf2', _blob())
        with db._connect() as conn:
            uid = conn.execute('SELECT id FROM users WHERE username=?', ('niaj',)).fetchone()['id']
            conn.execute('DELETE FROM users WHERE id=?', (uid,))
        # The vault row must be gone too (ON DELETE CASCADE).
        assert db.get_blob('niaj') is None
