"""
SecureVault Security Middleware
================================
Implements:
  - Per-request CSP nonce (eliminates 'unsafe-inline')
  - HTTP security headers (HSTS, X-Frame-Options, Permissions-Policy …)
  - In-memory rate limiting (per-IP sliding window)
  - Session risk scoring
  - Privacy-preserving security event logging
  - WebSocket alerts for critical events
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import threading
import time
from collections import defaultdict
from functools import wraps

from flask import g, jsonify, request

# ── Logging ────────────────────────────────────────────────────────────────────

_security_logger = logging.getLogger('securevault.security')
_security_logger.setLevel(logging.INFO)

_log_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
os.makedirs(_log_dir, exist_ok=True)
try:
    _handler = logging.FileHandler(os.path.join(_log_dir, 'security.log'))
    _handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    _security_logger.addHandler(_handler)
except OSError:
    _security_logger.addHandler(logging.StreamHandler())

# ── Rate-limit store ───────────────────────────────────────────────────────────

_rl_lock:  threading.Lock           = threading.Lock()
_ip_hits:  dict[str, list[float]]   = defaultdict(list)


def _hash_ip(ip: str) -> str:
    """Hash an IP address for privacy-preserving log storage."""
    return hashlib.sha256(ip.encode()).hexdigest()[:12]


def _clean_window(hits: list[float], window: float, now: float) -> list[float]:
    return [t for t in hits if now - t < window]


# ── CSP nonce ─────────────────────────────────────────────────────────────────

def _generate_nonce() -> str:
    """Generate a fresh 128-bit base64 nonce for each request."""
    return base64.b64encode(os.urandom(16)).decode()


def before_request_nonce() -> None:
    """Store a fresh nonce on Flask's g so templates can use it."""
    g.csp_nonce = _generate_nonce()


# ── Security headers ───────────────────────────────────────────────────────────

_STATIC_HEADERS: dict[str, str] = {
    'X-Content-Type-Options':    'nosniff',
    'X-Frame-Options':           'DENY',
    'X-XSS-Protection':          '1; mode=block',
    'Referrer-Policy':           'strict-origin-when-cross-origin',
    'Permissions-Policy':        'geolocation=(), microphone=(), camera=()',
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
}


def apply_security_headers(response):
    """Attach security headers to every outgoing response."""
    nonce = getattr(g, 'csp_nonce', '')

    # Fully nonce-based CSP — no 'unsafe-inline' anywhere.
    # All styles live in external files / nonce'd <style> blocks; dynamic styling
    # is applied via the CSSOM (element.style), which CSP permits without a nonce.
    csp = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src  'self' 'nonce-{nonce}' https://fonts.googleapis.com; "
        "font-src   'self' https://fonts.gstatic.com; "
        "img-src    'self' data: https:; "
        "connect-src 'self' https://api.pwnedpasswords.com; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers['Content-Security-Policy'] = csp

    for header, value in _STATIC_HEADERS.items():
        response.headers[header] = value

    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)

    return response


# ── Rate limiting ──────────────────────────────────────────────────────────────

def rate_limit(max_calls: int, window_secs: float, per: str = 'ip'):
    """
    Decorator factory — sliding-window rate limiter.

    Args:
        max_calls:   Allowed requests in window.
        window_secs: Window length in seconds.
        per:         'ip' (default) or 'user' (requires JWT).
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs) -> tuple:
            # Bypass rate limiting under the test harness for deterministic runs.
            from flask import current_app
            if current_app and current_app.config.get('TESTING'):
                return f(*args, **kwargs)
            now = time.time()
            ip  = request.remote_addr or '0.0.0.0'
            key = _hash_ip(ip) if per == 'ip' else (
                getattr(request, 'jwt_data', {}).get('sub', ip)
            )

            with _rl_lock:
                hits = _clean_window(_ip_hits[key], window_secs, now)
                if len(hits) >= max_calls:
                    retry_after = int(window_secs - (now - hits[0]))
                    log_security_event(
                        'RATE_LIMIT', ip,
                        f'Endpoint {request.endpoint} exceeded {max_calls}/{window_secs}s'
                    )
                    resp = jsonify({'error': 'Too many requests', 'retry_after': retry_after})
                    resp.status_code = 429
                    resp.headers['Retry-After'] = str(retry_after)
                    return resp
                hits.append(now)
                _ip_hits[key] = hits

            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── Session risk scoring ───────────────────────────────────────────────────────

def compute_session_risk(username: str, request_obj) -> dict:
    """
    Compute a simple risk score (0–100) for the current session.

    Factors: off-hours access, high request rate, missing User-Agent.
    """
    ip   = request_obj.remote_addr or '0.0.0.0'
    hour = time.localtime().tm_hour
    risk = 0
    reasons: list[str] = []

    if hour < 5 or hour >= 23:
        risk += 20
        reasons.append('Off-hours access')

    with _rl_lock:
        recent = _clean_window(_ip_hits.get(_hash_ip(ip), []), 60, time.time())
    if len(recent) > 30:
        risk += 30
        reasons.append('High request frequency')

    if not request_obj.headers.get('User-Agent'):
        risk += 20
        reasons.append('Missing User-Agent header')

    risk = min(100, risk)
    level = 'normal' if risk == 0 else 'low' if risk < 30 else 'medium' if risk < 60 else 'high'

    return {'score': risk, 'level': level, 'reasons': reasons}


# ── Security event logging ─────────────────────────────────────────────────────

_CRITICAL_EVENTS = frozenset({'RATE_LIMIT', 'LOGIN_FAIL', 'INVALID_JWT', 'BRUTE_FORCE'})


def log_security_event(event_type: str, ip: str, detail: str,
                       username: str = '', risk_score: int = 0) -> None:
    """
    Log a security event to: (1) the rotating file log, (2) the SQLite
    JournalAudit table (for the SOC dashboard), and (3) — for critical events —
    a real-time Socket.IO push. IP is hashed; no credentials are ever logged.
    """
    ip_hash = _hash_ip(ip)
    _security_logger.info(
        'type=%s | ip_hash=%s | user=%s | %s',
        event_type, ip_hash, username or '—', detail
    )
    # Persist to the database journal so the dashboard can query it.
    try:
        from app.database import log_event
        log_event(username or None, event_type, detail, ip_hash, risk_score)
    except Exception:
        pass
    if event_type in _CRITICAL_EVENTS:
        try:
            from app import socketio
            socketio.emit('security_alert', {
                'type':   event_type,
                'detail': detail,
                'user':   username or '—',
                'time':   time.time(),
                'level':  'high' if event_type in {'BRUTE_FORCE', 'RATE_LIMIT'} else 'medium',
            })
        except Exception:
            pass


# ── CSRF helpers ───────────────────────────────────────────────────────────────

def generate_csrf_token(session_id: str, secret: str) -> str:
    """Generate a CSRF token tied to the session (1-hour granularity)."""
    raw = f'{session_id}:{int(time.time() // 3600)}:{secret}'
    return hashlib.sha256(raw.encode()).hexdigest()


def validate_csrf_token(token: str, session_id: str, secret: str) -> bool:
    """Validate a CSRF token (accepts current and previous hour)."""
    import hmac
    for offset in (0, 1):
        raw      = f'{session_id}:{int(time.time() // 3600) - offset}:{secret}'
        expected = hashlib.sha256(raw.encode()).hexdigest()
        if hmac.compare_digest(token, expected):
            return True
    return False
