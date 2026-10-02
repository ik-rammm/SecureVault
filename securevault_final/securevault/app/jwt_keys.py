"""
SecureVault — RS256 JWT Key Management
======================================
The report (Livrable 2, §2.1) mandates **RS256-signed JWTs**: tokens are signed
with an RSA *private* key and verified with the matching *public* key. This
asymmetry means a component that only needs to *verify* tokens never holds the
signing secret — a stronger posture than the symmetric HS256 used previously.

Keys are loaded from the paths given by the JWT_PRIVATE_KEY_PATH /
JWT_PUBLIC_KEY_PATH environment variables (report §3.1, "Configuration via .env").
If they are absent (e.g. first local run), a fresh 2048-bit RSA pair is generated
and persisted so the demo works out-of-the-box without manual key provisioning.
"""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Default location: <project>/keys/  (outside the versioned app package)
_DEFAULT_KEY_DIR = Path(__file__).resolve().parent.parent / 'keys'


def _key_paths() -> tuple[Path, Path]:
    priv = os.environ.get('JWT_PRIVATE_KEY_PATH')
    pub = os.environ.get('JWT_PUBLIC_KEY_PATH')
    if priv and pub:
        return Path(priv), Path(pub)
    return _DEFAULT_KEY_DIR / 'jwt_private.pem', _DEFAULT_KEY_DIR / 'jwt_public.pem'


def _generate_pair(priv_path: Path, pub_path: Path) -> None:
    """Generate and persist a 2048-bit RSA key pair (PEM, PKCS8)."""
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    # Best-effort: restrict private key permissions on POSIX systems.
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass


def load_or_create_keys() -> tuple[str, str]:
    """
    Return (private_pem, public_pem) as PEM strings, generating the pair on
    first use. Called once at application startup.
    """
    priv_path, pub_path = _key_paths()
    if not (priv_path.exists() and pub_path.exists()):
        _generate_pair(priv_path, pub_path)
    return priv_path.read_text(), pub_path.read_text()
