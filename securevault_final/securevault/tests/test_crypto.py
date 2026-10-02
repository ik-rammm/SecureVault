"""
SecureVault — Unit Tests: Cryptographic Module
================================================
Tests for:
  - PBKDF2 and Argon2id key derivation
  - AES-256-GCM encryption / decryption
  - Vault encrypt/decrypt round-trip
  - Password strength scoring
  - HaveIBeenPwned k-anonymity helper
  - Constant-time comparison

Run:
    cd securevault
    python -m pytest tests/test_crypto.py -v
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.crypto import (
    derive_key_pbkdf2, derive_key_argon2, derive_key,
    encrypt_vault, decrypt_vault, WrongPassword,
    password_score, sha1_prefix, safe_compare,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

MASTER_PASSWORD = 'T3st!MasterP@ssw0rd'
SALT_16         = os.urandom(16)
PLAINTEXT       = b'{"entries":[],"audit":[]}'


# ── Key Derivation ────────────────────────────────────────────────────────────

class TestKeyDerivation:

    def test_pbkdf2_returns_32_bytes(self):
        key = derive_key_pbkdf2(MASTER_PASSWORD, SALT_16)
        assert len(key) == 32

    def test_pbkdf2_deterministic(self):
        """Same password + salt must always produce the same key."""
        salt = os.urandom(16)
        k1 = derive_key_pbkdf2(MASTER_PASSWORD, salt)
        k2 = derive_key_pbkdf2(MASTER_PASSWORD, salt)
        assert k1 == k2

    def test_pbkdf2_different_salts_produce_different_keys(self):
        k1 = derive_key_pbkdf2(MASTER_PASSWORD, os.urandom(16))
        k2 = derive_key_pbkdf2(MASTER_PASSWORD, os.urandom(16))
        assert k1 != k2

    def test_pbkdf2_different_passwords_produce_different_keys(self):
        salt = os.urandom(16)
        k1 = derive_key_pbkdf2('password1', salt)
        k2 = derive_key_pbkdf2('password2', salt)
        assert k1 != k2

    def test_argon2_returns_32_bytes(self):
        key = derive_key_argon2(MASTER_PASSWORD, SALT_16)
        assert len(key) == 32

    def test_argon2_deterministic(self):
        salt = os.urandom(16)
        k1 = derive_key_argon2(MASTER_PASSWORD, salt)
        k2 = derive_key_argon2(MASTER_PASSWORD, salt)
        assert k1 == k2

    def test_argon2_different_from_pbkdf2(self):
        """Argon2id and PBKDF2 must produce different keys from same inputs."""
        salt = os.urandom(16)
        k_pbkdf2 = derive_key_pbkdf2(MASTER_PASSWORD, salt)
        k_argon2 = derive_key_argon2(MASTER_PASSWORD, salt)
        assert k_pbkdf2 != k_argon2

    def test_derive_key_dispatch_pbkdf2(self):
        salt = os.urandom(16)
        assert derive_key(MASTER_PASSWORD, salt, 'pbkdf2') == derive_key_pbkdf2(MASTER_PASSWORD, salt)

    def test_derive_key_dispatch_argon2(self):
        salt = os.urandom(16)
        assert derive_key(MASTER_PASSWORD, salt, 'argon2') == derive_key_argon2(MASTER_PASSWORD, salt)

    def test_derive_key_default_is_pbkdf2(self):
        salt = os.urandom(16)
        assert derive_key(MASTER_PASSWORD, salt) == derive_key_pbkdf2(MASTER_PASSWORD, salt)


# ── Vault Encryption ──────────────────────────────────────────────────────────

class TestVaultEncryption:

    @pytest.mark.parametrize('algo', ['pbkdf2', 'argon2'])
    def test_encrypt_returns_string(self, algo):
        result = encrypt_vault(PLAINTEXT, MASTER_PASSWORD, algo)
        assert isinstance(result, str)
        assert len(result) > 0

    @pytest.mark.parametrize('algo', ['pbkdf2', 'argon2'])
    def test_round_trip(self, algo):
        """Encrypting then decrypting must return the original plaintext."""
        blob = encrypt_vault(PLAINTEXT, MASTER_PASSWORD, algo)
        recovered = decrypt_vault(blob, MASTER_PASSWORD)
        assert recovered == PLAINTEXT

    def test_wrong_password_raises(self):
        blob = encrypt_vault(PLAINTEXT, MASTER_PASSWORD, 'pbkdf2')
        with pytest.raises(WrongPassword):
            decrypt_vault(blob, 'WrongPassword!')

    def test_tampered_ciphertext_raises(self):
        import base64
        blob = encrypt_vault(PLAINTEXT, MASTER_PASSWORD, 'pbkdf2')
        raw  = bytearray(base64.b64decode(blob))
        raw[-1] ^= 0xFF   # Flip last byte (in GCM authentication tag area)
        tampered = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(WrongPassword):
            decrypt_vault(tampered, MASTER_PASSWORD)

    def test_each_encryption_produces_unique_ciphertext(self):
        """IV must be random → same plaintext encrypted twice must differ."""
        b1 = encrypt_vault(PLAINTEXT, MASTER_PASSWORD)
        b2 = encrypt_vault(PLAINTEXT, MASTER_PASSWORD)
        assert b1 != b2

    def test_invalid_format_raises(self):
        with pytest.raises(WrongPassword):
            decrypt_vault('not_a_valid_vault', MASTER_PASSWORD)

    def test_empty_plaintext(self):
        blob = encrypt_vault(b'', MASTER_PASSWORD)
        assert decrypt_vault(blob, MASTER_PASSWORD) == b''

    def test_large_plaintext(self):
        large = os.urandom(1024 * 1024)   # 1 MB
        blob = encrypt_vault(large, MASTER_PASSWORD)
        assert decrypt_vault(blob, MASTER_PASSWORD) == large


# ── Password Strength Scoring ─────────────────────────────────────────────────

class TestPasswordScore:

    def test_empty_password(self):
        result = password_score('')
        assert result['score'] == 0

    def test_very_weak_common_password(self):
        result = password_score('password')
        assert result['score'] < 25

    def test_strong_password_scores_high(self):
        result = password_score('Tr0ub4dor&3!Xy#Qp')
        assert result['score'] >= 70

    def test_score_between_0_and_100(self):
        for pwd in ['a', 'abc123', 'P@ssw0rd!12345678', 'x' * 128]:
            s = password_score(pwd)['score']
            assert 0 <= s <= 100, f'Score out of range for {repr(pwd)}: {s}'

    def test_returns_required_keys(self):
        result = password_score('TestPassword1!')
        for key in ('score', 'label', 'color', 'entropy', 'crack_time'):
            assert key in result

    def test_longer_password_generally_scores_higher(self):
        short  = password_score('Ab1!')
        long_p = password_score('Ab1!' * 4 + 'XyZ9#')
        assert long_p['score'] >= short['score']

    def test_labels_are_valid(self):
        valid_labels = {'Empty', 'Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'}
        for pwd in ['', 'a', 'abc123', 'StrongPass1!', 'V3ryStr0ng!P@ssword#2024']:
            label = password_score(pwd)['label']
            assert label in valid_labels, f'Unexpected label: {label}'


# ── HIBP k-anonymity helper ───────────────────────────────────────────────────

class TestHIBP:

    def test_sha1_prefix_returns_5_char_prefix(self):
        prefix, suffix = sha1_prefix('password')
        assert len(prefix) == 5

    def test_sha1_prefix_is_uppercase(self):
        prefix, suffix = sha1_prefix('test')
        assert prefix == prefix.upper()
        assert suffix == suffix.upper()

    def test_sha1_prefix_deterministic(self):
        p1, s1 = sha1_prefix('hello')
        p2, s2 = sha1_prefix('hello')
        assert p1 == p2 and s1 == s2

    def test_known_password_hash(self):
        """SHA1('password') = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"""
        prefix, suffix = sha1_prefix('password')
        assert prefix == '5BAA6'
        assert suffix == '1E4C9B93F3F0682250B6CF8331B7EE68FD8'


# ── Constant-time comparison ──────────────────────────────────────────────────

class TestSafeCompare:

    def test_equal_strings(self):
        assert safe_compare('abc', 'abc') is True

    def test_unequal_strings(self):
        assert safe_compare('abc', 'xyz') is False

    def test_different_lengths(self):
        # hmac.compare_digest raises if types differ, but same type different length = False
        assert safe_compare('short', 'much_longer_string') is False

    def test_empty_strings(self):
        assert safe_compare('', '') is True
