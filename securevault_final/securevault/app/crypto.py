import os, base64, hashlib, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type

PBKDF2_ITERATIONS = 600_000
ARGON2_MEMORY     = 65536   # 64 MB
ARGON2_TIME       = 3
ARGON2_PARALLEL   = 4
ARGON2_HASH_LEN   = 32

class WrongPassword(Exception):
    pass

# ── Key derivation ────────────────────────────────────────────────────────────

def derive_key_pbkdf2(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, iterations=PBKDF2_ITERATIONS
    )
    return kdf.derive(password.encode())

def derive_key_argon2(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_PARALLEL,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID
    )

def derive_key(password: str, salt: bytes, algo: str = 'pbkdf2') -> bytes:
    if algo == 'argon2':
        return derive_key_argon2(password, salt)
    return derive_key_pbkdf2(password, salt)

# ── Vault encryption / decryption ─────────────────────────────────────────────

MAGIC = b'SV2\x00'

def encrypt_vault(plaintext: bytes, password: str, algo: str = 'pbkdf2') -> str:
    salt  = os.urandom(16)
    nonce = os.urandom(12)
    key   = derive_key(password, salt, algo)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    algo_flag = b'\x01' if algo == 'argon2' else b'\x00'
    blob = MAGIC + algo_flag + salt + nonce + ct
    return base64.b64encode(blob).decode()

def decrypt_vault(encoded: str, password: str) -> bytes:
    try:
        blob = base64.b64decode(encoded, validate=True)
    except Exception:
        raise WrongPassword("Invalid vault format")
    if len(blob) < 49 or blob[:4] != MAGIC:
        raise WrongPassword("Invalid vault format")
    algo     = 'argon2' if blob[4:5] == b'\x01' else 'pbkdf2'
    salt     = blob[5:21]
    nonce    = blob[21:33]
    ct       = blob[33:]
    key      = derive_key(password, salt, algo)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except InvalidTag:
        raise WrongPassword("Wrong master password — vault locked")

# ── Password strength ─────────────────────────────────────────────────────────

import math, re, string

COMMON_PASSWORDS = {
    'password','123456','12345678','qwerty','abc123','monkey','1234567',
    'letmein','trustno1','dragon','baseball','iloveyou','master','sunshine',
    'ashley','bailey','passw0rd','shadow','123123','654321','superman',
    'qazwsx','michael','football','password1','password123','admin','welcome',
}

def password_entropy(pwd: str) -> float:
    charset = 0
    if re.search(r'[a-z]', pwd): charset += 26
    if re.search(r'[A-Z]', pwd): charset += 26
    if re.search(r'\d', pwd):    charset += 10
    if re.search(r'[^a-zA-Z0-9]', pwd): charset += 32
    return len(pwd) * math.log2(charset) if charset else 0

def password_score(pwd: str) -> dict:
    if not pwd:
        return {'score': 0, 'label': 'Empty', 'color': '#555', 'entropy': 0, 'crack_time': '< 1 sec'}

    score = 0
    issues = []

    # Length
    if len(pwd) >= 8:  score += 15
    if len(pwd) >= 12: score += 15
    if len(pwd) >= 16: score += 10
    else: issues.append('Use 16+ characters')

    # Complexity
    has_lower  = bool(re.search(r'[a-z]', pwd))
    has_upper  = bool(re.search(r'[A-Z]', pwd))
    has_digit  = bool(re.search(r'\d', pwd))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', pwd))

    if has_lower:  score += 10
    if has_upper:  score += 10
    if has_digit:  score += 10
    if has_symbol: score += 15
    if not has_upper:  issues.append('Add uppercase letters')
    if not has_digit:  issues.append('Add numbers')
    if not has_symbol: issues.append('Add symbols (!@#...)')

    # Penalize common passwords
    if pwd.lower() in COMMON_PASSWORDS:
        score = max(0, score - 40)
        issues.insert(0, 'This is a very common password!')

    # Penalize repetition/sequences
    if re.search(r'(.)\1{2,}', pwd):
        score = max(0, score - 10)
        issues.append('Avoid repeated characters')
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwe|asd)', pwd.lower()):
        score = max(0, score - 10)
        issues.append('Avoid sequential patterns')

    # Entropy bonus
    ent = password_entropy(pwd)
    if ent > 60: score += 10
    if ent > 80: score += 5

    score = min(100, score)

    # Crack time estimate (very rough)
    if ent < 30:   crack = '< 1 minute'
    elif ent < 40: crack = 'A few hours'
    elif ent < 55: crack = 'A few days'
    elif ent < 65: crack = 'Months'
    elif ent < 75: crack = 'Years'
    else:          crack = 'Centuries+'

    if score < 25:    label, color = 'Very Weak',  '#ef4444'
    elif score < 45:  label, color = 'Weak',       '#f97316'
    elif score < 65:  label, color = 'Fair',       '#eab308'
    elif score < 80:  label, color = 'Strong',     '#22c55e'
    else:             label, color = 'Very Strong','#06b6d4'

    return {
        'score':      score,
        'label':      label,
        'color':      color,
        'entropy':    round(ent, 1),
        'crack_time': crack,
        'issues':     issues[:3],
    }

# ── HaveIBeenPwned k-anonymity ────────────────────────────────────────────────

def sha1_prefix(password: str):
    h = hashlib.sha1(password.encode()).hexdigest().upper()
    return h[:5], h[5:]

# ── Constant-time comparison ──────────────────────────────────────────────────

def safe_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())

# ── Memory key zeroing (Attack #11 protection) ─────────────────────────────
import ctypes

def effacer_cle(key: bytes) -> None:
    """
    Zeroise a cryptographic key in memory after use.
    Protection against memory-read attacks (attack #11).
    Python bytes is immutable — we write directly via ctypes.
    """
    if not key:
        return
    try:
        buf = (ctypes.c_char * len(key)).from_buffer_copy(key)
        ctypes.memset(buf, 0, len(key))
    except Exception:
        pass

def generer_iv() -> bytes:
    """Generate a cryptographically secure 96-bit (12 byte) IV/nonce."""
    return os.urandom(12)

def generer_sel() -> bytes:
    """Generate a cryptographically secure 128-bit (16 byte) salt."""
    return os.urandom(16)
