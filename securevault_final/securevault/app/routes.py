"""
SecureVault — REST API (v1)  ·  Zero-Knowledge edition
======================================================
All endpoints are versioned under /api/v1/.
Input validation is handled by app.schemas before any business logic runs.

Zero-knowledge contract (report Part 1 & 2):
  - The server never receives the master password, K_enc, or any plaintext entry.
  - Authentication is proven by Auth_Hash = SHA-256(K_auth), compared in
    constant time. JWTs are signed with RS256 (asymmetric).
  - The vault is stored and served as a single opaque AES-256-GCM blob.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import string
import time
import uuid as _uuid
from functools import wraps
from typing import Any

import jwt as pyjwt
from flask import Blueprint, current_app, g, jsonify, render_template, request

from app.crypto import password_score, sha1_prefix
from app.database import (
    create_user, get_blob, get_events, get_last_logins, get_salt,
    log_event, set_blob, user_exists, verify_auth_hash,
)
from app.schemas import (
    ValidationError, validate_blob, validate_generate,
    validate_login, validate_register, validate_strength,
)
from app.security import compute_session_risk, log_security_event, rate_limit

bp = Blueprint('main', __name__)

TOKEN_EXPIRY_SECONDS = 900   # 15 minutes


# ── Token helpers (RS256, report §2.1) ──────────────────────────────────────────

def _make_token(username: str, jti: str | None = None) -> str:
    if jti is None:
        jti = str(_uuid.uuid4())
    payload = {
        'sub': username,
        'jti': jti,
        'exp': time.time() + TOKEN_EXPIRY_SECONDS,
        'iat': time.time(),
    }
    return pyjwt.encode(
        payload,
        current_app.config['JWT_PRIVATE_KEY'],
        algorithm=current_app.config['JWT_ALGORITHM'],
    )


def _get_redis():
    try:
        import redis
        r = redis.from_url(
            os.environ.get('REDIS_URL', 'redis://redis:6379'),
            password=os.environ.get('REDIS_PASSWORD', 'securevault_redis_pass'),
            decode_responses=True,
            socket_connect_timeout=2,
        )
        r.ping()
        return r
    except Exception:
        return None


# In-memory fallback blacklist (used when Redis is unavailable, e.g. local demo)
_local_blacklist: dict[str, float] = {}


def _blacklist_token(jti: str, expiry: int = TOKEN_EXPIRY_SECONDS) -> None:
    r = _get_redis()
    if r:
        r.setex(f'blacklist:{jti}', expiry, '1')
    else:
        _local_blacklist[jti] = time.time() + expiry


def _is_blacklisted(jti: str) -> bool:
    r = _get_redis()
    if r:
        return bool(r.exists(f'blacklist:{jti}'))
    exp = _local_blacklist.get(jti)
    if exp is None:
        return False
    if exp < time.time():
        _local_blacklist.pop(jti, None)
        return False
    return True


def _decode_token(token: str) -> dict | None:
    try:
        data = pyjwt.decode(
            token,
            current_app.config['JWT_PUBLIC_KEY'],
            algorithms=[current_app.config['JWT_ALGORITHM']],
        )
        if _is_blacklisted(data.get('jti', '')):
            return None
        return data
    except Exception:
        return None


# ── Decorators ─────────────────────────────────────────────────────────────────

def jwt_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Missing token'}), 401
        data = _decode_token(auth[7:])
        if not data:
            log_security_event('INVALID_JWT', request.remote_addr or '', 'Invalid or expired JWT')
            return jsonify({'error': 'Invalid or expired token'}), 401
        request.jwt_data = data
        return f(*args, **kwargs)
    return wrapper


def _user() -> str:
    return request.jwt_data['sub']


# ── UI ─────────────────────────────────────────────────────────────────────────

@bp.route('/')
def index():
    return render_template('index.html', csp_nonce=getattr(g, 'csp_nonce', ''))


@bp.route('/api/v1/health')
def health() -> tuple[Any, int]:
    """Lightweight system-status probe for the dashboard 'System' card."""
    return jsonify({
        'status': 'ok',
        'redis': _get_redis() is not None,
        'time': time.time(),
        'version': '3.0',
    }), 200


# ── OpenAPI spec ───────────────────────────────────────────────────────────────

@bp.route('/api/v1/openapi.json')
def openapi_spec() -> tuple[Any, int]:
    import pathlib
    spec_path = pathlib.Path(__file__).parent.parent / 'openapi.json'
    if spec_path.exists():
        return current_app.response_class(
            spec_path.read_text(), mimetype='application/json'
        ), 200
    return jsonify({'error': 'Spec not found'}), 404


# ── Auth (zero-knowledge) ───────────────────────────────────────────────────────

@bp.route('/api/v1/auth/salt', methods=['GET'])
@rate_limit(30, 60)
def auth_salt() -> tuple[Any, int]:
    """
    Return the public salt for a username so the client can derive its keys.

    For unknown users we return a *deterministic pseudo-salt* (HMAC of the
    username) instead of 404, so an attacker cannot enumerate accounts by
    probing this endpoint.
    """
    username = (request.args.get('username') or '').strip().lower()
    if not username:
        return jsonify({'error': 'username required'}), 400

    salt = get_salt(username)
    if salt is None:
        import hmac
        secret = current_app.config['SECRET_KEY'].encode()
        salt = hmac.new(secret, f'salt:{username}'.encode(), hashlib.sha256).hexdigest()
        kdf = 'pbkdf2'
    else:
        from app.database import get_user_kdf
        kdf = get_user_kdf(username)
    return jsonify({'salt': salt, 'kdf': kdf}), 200


@bp.route('/api/v1/auth/register', methods=['POST'])
@rate_limit(10, 60)
def register() -> tuple[Any, int]:
    try:
        body = validate_register(request.get_json(force=True) or {})
    except ValidationError as e:
        return jsonify(e.to_response()), 422

    ok, msg = create_user(
        body['username'], body['auth_hash'], body['salt_hex'], body['kdf'], body['blob']
    )
    if ok:
        log_security_event('REGISTER', request.remote_addr or '',
                           'New account created', body['username'])
    return jsonify({'success': ok, 'message': msg}), (201 if ok else 409)


@bp.route('/api/v1/auth/login', methods=['POST'])
@rate_limit(10, 60)
def login() -> tuple[Any, int]:
    try:
        body = validate_login(request.get_json(force=True) or {})
    except ValidationError as e:
        return jsonify(e.to_response()), 422

    username = body['username']
    ok, msg = verify_auth_hash(username, body['auth_hash'])
    if not ok:
        log_security_event('LOGIN_FAIL', request.remote_addr or '',
                           f'Failed login for {username}', username)
        return jsonify({'success': False, 'message': msg}), 401

    # Feed the AI anomaly model (behavioural baseline) — no secrets involved.
    try:
        from app.ai import record_login
        now = time.localtime()
        record_login(username, {
            'hour': now.tm_hour,
            'dow': now.tm_wday,
            'country': request.headers.get('CF-IPCountry', 'XX'),
            'ua_hash': hash(request.headers.get('User-Agent', '')) & 0xFFFFFF,
        })
    except Exception:
        pass

    risk = compute_session_risk(username, request)
    log_security_event('LOGIN_OK', request.remote_addr or '',
                       f'Successful login (risk {risk["score"]})', username,
                       risk_score=risk['score'])
    return jsonify({
        'success': True,
        'token': _make_token(username),
        'username': username,
        'salt': get_salt(username),
        'session_risk': risk,
    }), 200


@bp.route('/api/v1/auth/refresh', methods=['POST'])
@jwt_required
@rate_limit(10, 60)
def refresh_token() -> tuple[Any, int]:
    """Rotate the JWT (invalidates the old one against session hijacking)."""
    old_jti = request.jwt_data.get('jti', '')
    username = _user()
    if old_jti:
        _blacklist_token(old_jti)
    log_security_event('TOKEN_REFRESH', request.remote_addr or '', 'Token rotated', username)
    return jsonify({'success': True, 'token': _make_token(username)}), 200


@bp.route('/api/v1/auth/logout', methods=['POST'])
@jwt_required
def logout() -> tuple[Any, int]:
    """Invalidate the current JWT immediately via the blacklist."""
    jti = request.jwt_data.get('jti', '')
    username = _user()
    if jti:
        _blacklist_token(jti)
    log_security_event('LOGOUT', request.remote_addr or '', 'User logged out', username)
    return jsonify({'success': True, 'message': 'Logged out'}), 200


# ── Vault (opaque blob — zero-knowledge) ────────────────────────────────────────

@bp.route('/api/v1/vault/blob', methods=['GET'])
@jwt_required
def get_vault_blob() -> tuple[Any, int]:
    """Return the user's opaque encrypted vault. The server cannot read it."""
    blob = get_blob(_user())
    if blob is None:
        return jsonify({'error': 'Vault not found'}), 404
    log_security_event('VAULT_ACCESS', request.remote_addr or '', 'Vault retrieved', _user())
    return jsonify({'blob': blob}), 200


@bp.route('/api/v1/vault/blob', methods=['PUT'])
@jwt_required
@rate_limit(60, 60)
def put_vault_blob() -> tuple[Any, int]:
    """Store a new opaque encrypted vault (client re-encrypts before upload)."""
    try:
        body = validate_blob(request.get_json(force=True) or {})
    except ValidationError as e:
        return jsonify(e.to_response()), 422
    if not set_blob(_user(), body['blob']):
        return jsonify({'error': 'Vault not found'}), 404
    log_security_event('VAULT_UPDATE', request.remote_addr or '', 'Vault saved', _user())
    return jsonify({'success': True}), 200


# ── Security / SIEM ──────────────────────────────────────────────────────────────

@bp.route('/api/v1/security/strength', methods=['POST'])
@rate_limit(60, 60)
def strength_check() -> tuple[Any, int]:
    """
    Server-side AI strength scoring for a *candidate* password (e.g. before
    saving). The live meter in the UI runs fully client-side; this endpoint
    adds the ML/heuristic analysis on demand.
    """
    try:
        body = validate_strength(request.get_json(force=True) or {})
    except ValidationError as e:
        return jsonify(e.to_response()), 422
    try:
        from app.ai import ai_password_score
        result = ai_password_score(body['password'])
    except Exception:
        result = password_score(body['password'])
    return jsonify(result), 200


@bp.route('/api/v1/security/hibp', methods=['POST'])
@rate_limit(15, 60)
def hibp_check() -> tuple[Any, int]:
    """HaveIBeenPwned check via k-anonymity — only a SHA-1 prefix leaves the host."""
    data = request.get_json(force=True) or {}
    pwd = str(data.get('password', ''))
    if not pwd:
        return jsonify({'error': 'No password provided'}), 400
    prefix, suffix = sha1_prefix(pwd)
    try:
        import urllib.request
        req = urllib.request.Request(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            headers={'Add-Padding': 'true', 'User-Agent': 'SecureVault/3.0'},
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read().decode()
        for line in body.splitlines():
            parts = line.split(':')
            if len(parts) == 2 and parts[0] == suffix:
                return jsonify({'pwned': True, 'count': int(parts[1])}), 200
        return jsonify({'pwned': False, 'count': 0}), 200
    except Exception as e:
        return jsonify({'pwned': None, 'error': 'HIBP unavailable', 'detail': str(e)}), 503


@bp.route('/api/v1/security/audit', methods=['GET'])
@jwt_required
def audit_log() -> tuple[Any, int]:
    """Return the server-side security event journal (JournalAudit) for the SOC."""
    try:
        log = get_events(_user(), limit=200)
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    return jsonify({'log': log}), 200


@bp.route('/api/v1/security/alerts', methods=['GET'])
@jwt_required
def security_alerts() -> tuple[Any, int]:
    """Live session-risk scoring + recent critical events for the alert centre."""
    u = _user()
    risk = compute_session_risk(u, request)
    events = get_events(u, limit=50)
    last_logins = get_last_logins(u, limit=5)
    alerts = [
        {'level': risk['level'], 'message': r, 'time': time.time()}
        for r in risk['reasons']
    ]
    return jsonify({
        'alerts': alerts,
        'session_risk': risk,
        'recent_events': events,
        'last_logins': last_logins,
    }), 200


# ── AI ───────────────────────────────────────────────────────────────────────────

@bp.route('/api/v1/ai/anomaly', methods=['POST'])
@jwt_required
def anomaly_check() -> tuple[Any, int]:
    u = _user()
    event = request.get_json(force=True) or {}
    try:
        from app.ai import score_login_anomaly
        result = score_login_anomaly(u, event)
    except Exception as e:
        result = {'error': str(e), 'is_anomaly': False}
    return jsonify(result), 200


@bp.route('/api/v1/ai/suggest', methods=['POST'])
@rate_limit(20, 60)
def ai_suggest() -> tuple[Any, int]:
    d = request.get_json(force=True) or {}
    try:
        from app.ai import contextual_password
        result = contextual_password(
            site_hint=str(d.get('site', '')),
            n_words=max(3, min(6, int(d.get('words', 4)))),
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/v1/ai/alternatives', methods=['POST'])
@rate_limit(20, 60)
def ai_alternatives() -> tuple[Any, int]:
    d = request.get_json(force=True) or {}
    try:
        from app.ai import suggest_alternatives
        alts = suggest_alternatives(str(d.get('password', '')))
    except Exception:
        alts = []
    return jsonify({'alternatives': alts}), 200


# ── Password generation (server-side helper; primary path is client CSPRNG) ──────

@bp.route('/api/v1/generate', methods=['POST'])
@rate_limit(60, 60)
def generate_password() -> tuple[Any, int]:
    try:
        opts = validate_generate(request.get_json(force=True) or {})
    except ValidationError as e:
        return jsonify(e.to_response()), 422

    exclude = set(opts['exclude'])
    charset = list(string.ascii_lowercase)
    if opts['uppercase']: charset += list(string.ascii_uppercase)
    if opts['digits']:    charset += list(string.digits)
    if opts['symbols']:   charset += list('!@#$%^&*()_+-=[]{}|;:,.<>?')
    charset = [c for c in charset if c not in exclude]
    if not charset:
        return jsonify({'error': 'No characters available with these settings'}), 400

    guaranteed = [secrets.choice(string.ascii_lowercase)]
    if opts['uppercase']: guaranteed.append(secrets.choice(string.ascii_uppercase))
    if opts['digits']:    guaranteed.append(secrets.choice(string.digits))
    if opts['symbols']:   guaranteed.append(secrets.choice('!@#$%^&*()_+-='))
    rest = [secrets.choice(charset) for _ in range(max(0, opts['length'] - len(guaranteed)))]
    chars = guaranteed + rest
    secrets.SystemRandom().shuffle(chars)
    pwd = ''.join(chars)

    try:
        from app.ai import ai_password_score
        strength = ai_password_score(pwd)
    except Exception:
        strength = password_score(pwd)
    return jsonify({'password': pwd, 'strength': strength}), 200


@bp.route('/api/v1/generate/memorable', methods=['POST'])
@rate_limit(60, 60)
def generate_memorable() -> tuple[Any, int]:
    d = request.get_json(force=True) or {}
    try:
        from app.ai import contextual_password
        result = contextual_password(
            site_hint=str(d.get('site', '')),
            n_words=max(3, min(8, int(d.get('words', 4)))),
        )
        return jsonify(result), 200
    except Exception:
        WORDS = ['correct', 'horse', 'battery', 'staple', 'ocean',
                 'tiger', 'purple', 'dragon', 'forest', 'silver']
        sep = str(d.get('separator', '-'))[:3]
        words = [secrets.choice(WORDS) for _ in range(4)]
        words.append(str(secrets.randbelow(9000) + 1000))
        pwd = sep.join(words)
        return jsonify({'password': pwd, 'strength': password_score(pwd)}), 200
