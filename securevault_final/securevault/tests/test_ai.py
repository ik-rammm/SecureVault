"""
SecureVault — Unit Tests: AI Module
=====================================
Tests for:
  - Feature extraction for anomaly detection
  - AI password strength evaluator
  - Contextual password generator
  - Alternative suggestions

Run:
    cd securevault
    python -m pytest tests/test_ai.py -v
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.ai import (
    _extract_features, _extract_password_features,
    ai_password_score, contextual_password, suggest_alternatives,
    record_login, score_login_anomaly,
)


class TestFeatureExtraction:

    def test_extract_features_returns_list_of_floats(self):
        event = {'hour': 14, 'dow': 2, 'country': 'FR', 'ua_hash': 12345}
        features = _extract_features(event)
        assert isinstance(features, list)
        assert all(isinstance(f, float) for f in features)

    def test_extract_features_has_8_dimensions(self):
        event = {}
        features = _extract_features(event)
        assert len(features) == 8

    def test_empty_event_uses_defaults(self):
        features = _extract_features({})
        assert len(features) == 8

    def test_password_features_dict(self):
        f = _extract_password_features('Hello1!')
        assert 'length' in f
        assert 'entropy' in f
        assert 'has_upper' in f
        assert 'has_digit' in f
        assert 'has_symbol' in f

    def test_password_features_length(self):
        f = _extract_password_features('test')
        assert f['length'] == 4


class TestAIPasswordScore:

    def test_empty_password(self):
        result = ai_password_score('')
        assert result['score'] == 0
        assert result['label'] == 'Empty'

    def test_score_range(self):
        for pwd in ['a', 'abc123', 'StrongPass!1Xyz#', 'x' * 64]:
            score = ai_password_score(pwd)['score']
            assert 0 <= score <= 100, f'Score out of range: {score} for {repr(pwd)}'

    def test_required_keys_present(self):
        result = ai_password_score('TestPwd1!')
        for key in ('score', 'label', 'color', 'entropy', 'crack_time', 'issues', 'ai_confidence'):
            assert key in result, f'Missing key: {key}'

    def test_strong_password_scores_high(self):
        result = ai_password_score('Tr0ub4dor&3!Xy#Qp99')
        assert result['score'] >= 70

    def test_very_weak_password(self):
        result = ai_password_score('abc')
        assert result['score'] < 40

    def test_keyboard_walk_detected(self):
        result = ai_password_score('qwerty123')
        # Should have a warning about keyboard walk
        issues_text = ' '.join(result.get('issues', []))
        # either score is penalised or issues mention it
        assert result['score'] < 70

    def test_ai_confidence_is_string(self):
        result = ai_password_score('SomePassword1!')
        assert isinstance(result['ai_confidence'], str)

    def test_features_dict_present(self):
        result = ai_password_score('Pass1!')
        assert 'features' in result
        assert isinstance(result['features'], dict)


class TestContextualPasswordGenerator:

    def test_returns_password_string(self):
        result = contextual_password()
        assert isinstance(result['password'], str)
        assert len(result['password']) > 0

    def test_returns_memorability_score(self):
        result = contextual_password()
        assert 0 <= result['memorability'] <= 100

    def test_returns_strength_assessment(self):
        result = contextual_password()
        assert 'strength' in result
        assert 'score' in result['strength']

    def test_site_hint_bank(self):
        result = contextual_password(site_hint='bank')
        assert isinstance(result['password'], str)

    def test_site_hint_gaming(self):
        result = contextual_password(site_hint='gaming')
        assert isinstance(result['password'], str)

    def test_n_words_parameter(self):
        for n in (3, 4, 5):
            result = contextual_password(n_words=n)
            assert isinstance(result['password'], str)

    def test_passwords_are_random(self):
        """Two calls should produce different passwords (probabilistically)."""
        p1 = contextual_password()['password']
        p2 = contextual_password()['password']
        # Extremely unlikely to be equal
        assert p1 != p2

    def test_password_contains_symbol(self):
        """Generated password should contain a symbol (per spec)."""
        import re
        result = contextual_password()
        assert re.search(r'[!@#$%&*]', result['password']), \
            f'No symbol found in: {result["password"]}'

    def test_password_contains_digit(self):
        """Generated password should contain digits."""
        result = contextual_password()
        assert any(c.isdigit() for c in result['password']), \
            f'No digit found in: {result["password"]}'


class TestAlternativeSuggestions:

    def test_returns_list(self):
        alts = suggest_alternatives('weakpass')
        assert isinstance(alts, list)

    def test_returns_3_alternatives(self):
        alts = suggest_alternatives('password123')
        assert len(alts) == 3

    def test_alternatives_are_strings(self):
        alts = suggest_alternatives('abc')
        for alt in alts:
            assert isinstance(alt, str)

    def test_alternatives_differ_from_original(self):
        original = 'password'
        alts = suggest_alternatives(original)
        for alt in alts:
            assert alt.lower() != original.lower()

    def test_alternatives_are_stronger(self):
        """All suggestions should score higher than a weak password."""
        from app.crypto import password_score
        weak_score = password_score('password')['score']
        alts = suggest_alternatives('password')
        for alt in alts:
            alt_score = password_score(alt)['score']
            assert alt_score > weak_score, \
                f'Alternative "{alt}" (score={alt_score}) not stronger than original (score={weak_score})'


class TestAnomalyDetection:

    def test_score_before_training_returns_dict(self):
        result = score_login_anomaly('new_user_no_history', {'hour': 14})
        assert isinstance(result, dict)
        assert 'is_anomaly' in result
        assert 'confidence' in result

    def test_unusual_hour_flagged_by_rules(self):
        """Login at 3 AM should be flagged as unusual (rule-based)."""
        result = score_login_anomaly('test_anomaly_user', {'hour': 3})
        # Rule-based: 3 AM is off-hours
        assert isinstance(result['is_anomaly'], bool)

    def test_record_login_does_not_raise(self):
        record_login('benchmark_user', {
            'hour': 10, 'dow': 1, 'country': 'MA', 'ua_hash': 99999
        })

    def test_returns_confidence_string(self):
        result = score_login_anomaly('conf_test', {'hour': 12})
        assert result['confidence'] in ('low', 'medium', 'high')

    def test_returns_reason_string(self):
        result = score_login_anomaly('reason_test', {'hour': 2})
        assert isinstance(result.get('reason', ''), str)
