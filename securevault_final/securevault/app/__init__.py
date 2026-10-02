"""
SecureVault — Flask Application Factory
=======================================
Zero-Knowledge password manager (EMSI 4CIRT, PFA).

This factory wires together:
  - the RS256 JWT signing keys (report §2.1) — asymmetric, auto-provisioned;
  - the SQLite persistence layer (init at startup);
  - the per-request CSP nonce + hardened security headers;
  - the REST API blueprint (versioned under /api/v1);
  - the Socket.IO channel used to push real-time SOC alerts to the dashboard.
"""
import logging
import os

from flask import Flask, jsonify, render_template
from flask_socketio import SocketIO

socketio = SocketIO()


def create_app() -> Flask:
    app = Flask(__name__, template_folder='../templates', static_folder='../static')

    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
    app.config['ENV'] = os.environ.get('FLASK_ENV', 'production')
    app.config['DEBUG'] = os.environ.get('FLASK_ENV') == 'development'

    # ── RS256 JWT keys (asymmetric signing, report §2.1) ────────────────────
    from app.jwt_keys import load_or_create_keys
    private_pem, public_pem = load_or_create_keys()
    app.config['JWT_PRIVATE_KEY'] = private_pem
    app.config['JWT_PUBLIC_KEY'] = public_pem
    app.config['JWT_ALGORITHM'] = 'RS256'

    # ── Database schema ─────────────────────────────────────────────────────
    from app.database import init_db
    with app.app_context():
        init_db()

    # ── Per-request CSP nonce + security headers ────────────────────────────
    from app.security import before_request_nonce, apply_security_headers
    app.before_request(before_request_nonce)
    app.after_request(apply_security_headers)

    # ── Routes ──────────────────────────────────────────────────────────────
    from app.routes import bp
    app.register_blueprint(bp)

    # ── Custom error pages (UX: no raw stack traces) ────────────────────────
    _register_error_handlers(app)

    socketio.init_app(app, cors_allowed_origins='*', async_mode='threading')

    if not app.config['DEBUG']:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)s %(name)s: %(message)s',
        )

    return app


def _wants_json(request) -> bool:
    return request.path.startswith('/api/') or 'application/json' in request.headers.get('Accept', '')


def _register_error_handlers(app: Flask) -> None:
    from flask import request, g

    @app.errorhandler(404)
    def not_found(_e):
        if _wants_json(request):
            return jsonify({'error': 'Resource not found'}), 404
        return render_template('404.html', csp_nonce=getattr(g, 'csp_nonce', '')), 404

    @app.errorhandler(500)
    def server_error(_e):
        if _wants_json(request):
            return jsonify({'error': 'Internal server error'}), 500
        return render_template('500.html', csp_nonce=getattr(g, 'csp_nonce', '')), 500

    @app.errorhandler(429)
    def too_many(_e):
        return jsonify({'error': 'Too many requests'}), 429
