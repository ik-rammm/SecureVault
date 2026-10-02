"""
SecureVault — Integration Tests: REST API (Zero-Knowledge)
==========================================================
Tests the full HTTP stack: routing, ZK authentication (Auth_Hash), opaque
vault blob storage, validation, SIEM endpoints and security headers.

Because the server is zero-knowledge, it never derives keys — it merely stores
and compares the client-supplied Auth_Hash and opaque blob. Tests therefore use
arbitrary (but well-formed) hex credentials and an opaque base64 blob.

Run:
    cd securevault
    python -m pytest tests/test_routes.py -v
"""
from __future__ import annotations

import base64
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


# ── Helpers ──────────────────────────────────────────────────────────────────

def _hex32() -> str:
    return os.urandom(32).hex()


def _auth_hash(secret: bytes = b'k_auth_secret') -> str:
    return hashlib.sha256(secret).hexdigest()


def _blob(payload: bytes = b'{"entries":[]}') -> str:
    return base64.b64encode(payload).decode()


def _account(username: str, secret: bytes = b'k_auth_secret') -> dict:
    return {
        'username': username,
        'salt_hex': _hex32(),
        'auth_hash': _auth_hash(secret),
        'kdf': 'pbkdf2',
        'blob': _blob(),
    }


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope='module')
def app(tmp_path_factory):
    db_dir = tmp_path_factory.mktemp('data')
    key_dir = tmp_path_factory.mktemp('keys')
    os.environ['DATA_DIR'] = str(db_dir)
    os.environ['SECRET_KEY'] = 'test-secret-key-32chars-minimum!!'
    os.environ['JWT_PRIVATE_KEY_PATH'] = str(key_dir / 'priv.pem')
    os.environ['JWT_PUBLIC_KEY_PATH'] = str(key_dir / 'pub.pem')

    from app import create_app
    application = create_app()
    application.config['TESTING'] = True
    return application


@pytest.fixture(scope='module')
def client(app):
    return app.test_client()


@pytest.fixture(scope='module')
def auth(client):
    """Register + login a user; return (headers, secret)."""
    secret = b'integ_k_auth'
    client.post('/api/v1/auth/register', json=_account('integuser', secret))
    r = client.post('/api/v1/auth/login',
                    json={'username': 'integuser', 'auth_hash': _auth_hash(secret)})
    token = r.get_json()['token']
    return {'Authorization': f'Bearer {token}'}, secret


# ── Register ─────────────────────────────────────────────────────────────────

class TestRegister:
    def test_register_success(self, client):
        r = client.post('/api/v1/auth/register', json=_account('newuser42'))
        assert r.status_code == 201
        assert r.get_json()['success'] is True

    def test_register_duplicate_fails(self, client):
        client.post('/api/v1/auth/register', json=_account('dupuser'))
        r = client.post('/api/v1/auth/register', json=_account('dupuser'))
        assert r.status_code == 409

    def test_register_invalid_username_chars(self, client):
        acc = _account('bad user!')
        r = client.post('/api/v1/auth/register', json=acc)
        assert r.status_code == 422

    def test_register_invalid_salt(self, client):
        acc = _account('saltuser')
        acc['salt_hex'] = 'tooshort'
        r = client.post('/api/v1/auth/register', json=acc)
        assert r.status_code == 422

    def test_register_invalid_kdf(self, client):
        acc = _account('kdfuser')
        acc['kdf'] = 'bcrypt'
        r = client.post('/api/v1/auth/register', json=acc)
        assert r.status_code == 422


# ── Salt (anti-enumeration) ──────────────────────────────────────────────────

class TestSalt:
    def test_salt_for_known_user(self, client):
        acc = _account('saltknown')
        client.post('/api/v1/auth/register', json=acc)
        r = client.get('/api/v1/auth/salt?username=saltknown')
        assert r.status_code == 200
        body = r.get_json()
        assert body['salt'] == acc['salt_hex']
        assert body['kdf'] == 'pbkdf2'

    def test_salt_for_unknown_user_is_deterministic(self, client):
        r1 = client.get('/api/v1/auth/salt?username=ghost-xyz')
        r2 = client.get('/api/v1/auth/salt?username=ghost-xyz')
        assert r1.status_code == 200 and r2.status_code == 200
        # No 404 leak, and stable pseudo-salt → cannot enumerate accounts.
        assert r1.get_json()['salt'] == r2.get_json()['salt']


# ── Login ────────────────────────────────────────────────────────────────────

class TestLogin:
    def test_login_success(self, client):
        secret = b'login_secret'
        client.post('/api/v1/auth/register', json=_account('loginuser', secret))
        r = client.post('/api/v1/auth/login',
                        json={'username': 'loginuser', 'auth_hash': _auth_hash(secret)})
        assert r.status_code == 200
        assert r.get_json()['success'] is True

    def test_login_returns_rs256_jwt(self, client):
        secret = b'jwt_secret'
        client.post('/api/v1/auth/register', json=_account('jwtuser', secret))
        r = client.post('/api/v1/auth/login',
                        json={'username': 'jwtuser', 'auth_hash': _auth_hash(secret)})
        token = r.get_json()['token']
        import jwt as pyjwt
        header = pyjwt.get_unverified_header(token)
        assert header['alg'] == 'RS256'

    def test_login_wrong_proof_fails(self, client):
        client.post('/api/v1/auth/register', json=_account('wrongpw', b'right'))
        r = client.post('/api/v1/auth/login',
                        json={'username': 'wrongpw', 'auth_hash': _auth_hash(b'wrong')})
        assert r.status_code == 401

    def test_login_unknown_user_fails(self, client):
        r = client.post('/api/v1/auth/login',
                        json={'username': 'nobody-here', 'auth_hash': _auth_hash()})
        assert r.status_code == 401


# ── Vault blob (zero-knowledge) ──────────────────────────────────────────────

class TestVaultBlob:
    def test_get_blob_requires_token(self, client):
        r = client.get('/api/v1/vault/blob')
        assert r.status_code == 401

    def test_get_blob_with_token(self, client, auth):
        headers, _ = auth
        r = client.get('/api/v1/vault/blob', headers=headers)
        assert r.status_code == 200
        assert 'blob' in r.get_json()

    def test_put_and_get_blob_roundtrip(self, client, auth):
        headers, _ = auth
        new_blob = _blob(b'{"entries":[{"id":"1"}]}')
        r = client.put('/api/v1/vault/blob', headers=headers, json={'blob': new_blob})
        assert r.status_code == 200
        r2 = client.get('/api/v1/vault/blob', headers=headers)
        assert r2.get_json()['blob'] == new_blob

    def test_put_empty_blob_rejected(self, client, auth):
        headers, _ = auth
        r = client.put('/api/v1/vault/blob', headers=headers, json={'blob': ''})
        assert r.status_code == 422


# ── Logout ───────────────────────────────────────────────────────────────────

class TestLogout:
    def test_logout_invalidates_token(self, client):
        secret = b'logout_secret'
        client.post('/api/v1/auth/register', json=_account('logoutuser', secret))
        r = client.post('/api/v1/auth/login',
                        json={'username': 'logoutuser', 'auth_hash': _auth_hash(secret)})
        token = r.get_json()['token']
        h = {'Authorization': f'Bearer {token}'}
        assert client.get('/api/v1/vault/blob', headers=h).status_code == 200
        assert client.post('/api/v1/auth/logout', headers=h).status_code == 200
        # Token must now be rejected (blacklisted).
        assert client.get('/api/v1/vault/blob', headers=h).status_code == 401


# ── Security / SIEM ──────────────────────────────────────────────────────────

class TestSecurityEndpoints:
    def test_strength_endpoint(self, client):
        r = client.post('/api/v1/security/strength', json={'password': 'Tr0ub4dor&3xY!'})
        assert r.status_code == 200
        assert 'score' in r.get_json()

    def test_audit_log_records_events(self, client, auth):
        headers, _ = auth
        r = client.get('/api/v1/security/audit', headers=headers)
        assert r.status_code == 200
        assert isinstance(r.get_json()['log'], list)
        assert len(r.get_json()['log']) >= 1   # at least the login event

    def test_alerts_endpoint(self, client, auth):
        headers, _ = auth
        r = client.get('/api/v1/security/alerts', headers=headers)
        assert r.status_code == 200
        body = r.get_json()
        assert 'session_risk' in body and 'recent_events' in body

    def test_health(self, client):
        r = client.get('/api/v1/health')
        assert r.status_code == 200
        assert r.get_json()['status'] == 'ok'


# ── Generation ───────────────────────────────────────────────────────────────

class TestGeneration:
    def test_generate_password(self, client):
        r = client.post('/api/v1/generate', json={'length': 24})
        assert r.status_code == 200
        assert len(r.get_json()['password']) == 24

    def test_generate_memorable(self, client):
        r = client.post('/api/v1/generate/memorable', json={'words': 4})
        assert r.status_code == 200
        assert r.get_json()['password']


# ── Security headers ─────────────────────────────────────────────────────────

class TestSecurityHeaders:
    def test_csp_has_nonce_no_unsafe_inline(self, client):
        r = client.get('/')
        csp = r.headers.get('Content-Security-Policy', '')
        assert 'nonce-' in csp
        assert 'unsafe-inline' not in csp

    def test_hardening_headers_present(self, client):
        r = client.get('/')
        assert r.headers.get('X-Content-Type-Options') == 'nosniff'
        assert r.headers.get('X-Frame-Options') == 'DENY'
        assert 'max-age=' in r.headers.get('Strict-Transport-Security', '')
