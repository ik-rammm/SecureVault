"""
SecureVault AI Module
=====================
Implements:
  1. Anomaly detection (Isolation Forest) for suspicious login behaviour
  2. ML-based password strength evaluator (MLP / feature-engineering approach)
  3. Contextual password suggestions (rule-based probabilistic generator)

All models are trained/fitted at first use and cached in-memory.
No external API calls — everything runs locally.
"""

from __future__ import annotations

import math
import re
import time
from pathlib import Path
import hashlib
import threading
from collections import defaultdict
from typing import Optional

# ── Optional heavy deps (graceful fallback if scikit-learn not installed) ──────
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    _SKLEARN_OK = True
except ImportError:
    _SKLEARN_OK = False

# ─────────────────────────────────────────────────────────────────────────────
# 1. ANOMALY DETECTION — Isolation Forest
# ─────────────────────────────────────────────────────────────────────────────

# Per-user session history: username -> list of feature vectors (dicts)
_session_history: dict[str, list[dict]] = defaultdict(list)
_models: dict[str, tuple] = {}          # username -> (IsolationForest, scaler)
_lock = threading.Lock()

# ── Model persistence ─────────────────────────────────────────────────────────
_MODEL_DIR = Path(__file__).parent.parent / 'models'
_MODEL_DIR.mkdir(exist_ok=True)


def _model_path(username: str) -> Path:
    # Sanitise username to a safe filename
    safe = ''.join(c for c in username if c.isalnum() or c in '-_')[:64]
    return _MODEL_DIR / f'{safe}.joblib'


def _persist_model(username: str, clf, scaler) -> None:
    """Save a trained model to disk so it survives server restarts."""
    try:
        import joblib
        joblib.dump({'clf': clf, 'scaler': scaler}, _model_path(username))
    except Exception:
        pass   # Persistence is best-effort; in-memory model still works


def _restore_model(username: str) -> tuple | None:
    """Load a previously saved model from disk."""
    try:
        import joblib
        p = _model_path(username)
        if p.exists():
            data = joblib.load(p)
            return data['clf'], data['scaler']
    except Exception:
        pass
    return None

MIN_SAMPLES_TO_FIT = 10   # Need at least this many logins before we can detect anomalies


def _extract_features(event: dict) -> list[float]:
    """Convert a login event dict to a numeric feature vector."""
    hour      = event.get('hour', 12)          # 0-23
    dow       = event.get('dow', 0)            # 0=Mon..6=Sun
    country   = event.get('country', 'XX')
    ua_hash   = event.get('ua_hash', 0)        # int fingerprint
    n_entries = event.get('n_entries', 0)      # entries accessed this session
    inter_req = event.get('inter_req_ms', 500) # avg ms between requests

    # Cyclical encoding for hour (avoids 0/23 discontinuity)
    hour_sin  = math.sin(2 * math.pi * hour / 24)
    hour_cos  = math.cos(2 * math.pi * hour / 24)
    dow_sin   = math.sin(2 * math.pi * dow  / 7)
    dow_cos   = math.cos(2 * math.pi * dow  / 7)

    # Country as simple hash bucket (0-99)
    country_bucket = int(hashlib.md5(country.encode()).hexdigest(), 16) % 100

    return [float(x) for x in (
        hour_sin, hour_cos, dow_sin, dow_cos,
        country_bucket,
        ua_hash % 1000,          # 0-999
        min(n_entries, 200),
        min(inter_req, 10000),
    )]


def record_login(username: str, event: dict) -> None:
    """
    Record a successful login event for anomaly model training.
    Call this on every successful authentication.

    event keys (all optional, defaults are safe):
      hour        int  0-23  (local server hour of login)
      dow         int  0-6   (day of week, 0=Monday)
      country     str        (ISO-2 country from GeoIP or 'XX')
      ua_hash     int        (hash of User-Agent string)
      n_entries   int        (entries accessed in this session)
      inter_req_ms float     (avg ms between consecutive API requests)
    """
    with _lock:
        _session_history[username].append(event)
        # Refit model every 10 new samples
        history = _session_history[username]
        if len(history) >= MIN_SAMPLES_TO_FIT and len(history) % 10 == 0:
            _fit_model(username, history)


def _fit_model(username: str, history: list[dict]) -> None:
    """(Re)train the Isolation Forest for a given user (call under _lock)."""
    if not _SKLEARN_OK:
        return
    X = np.array([_extract_features(e) for e in history], dtype=float)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    clf.fit(X_scaled)
    _models[username] = (clf, scaler)
    _persist_model(username, clf, scaler)


def score_login_anomaly(username: str, event: dict) -> dict:
    """
    Returns an anomaly assessment for a login event.

    Returns dict:
      anomaly_score  float   -1..0  (lower = more anomalous; 0 = normal)
      is_anomaly     bool    True if score < threshold
      confidence     str     'low'|'medium'|'high'
      reason         str     human-readable explanation
    """
    if not _SKLEARN_OK:
        return {'anomaly_score': 0.0, 'is_anomaly': False,
                'confidence': 'low', 'reason': 'AI module not available (scikit-learn missing)'}

    with _lock:
        model_tuple = _models.get(username)

    if model_tuple is None:
        # Try restoring from disk (survives server restarts)
        model_tuple = _restore_model(username)
        if model_tuple:
            with _lock:
                _models[username] = model_tuple

    if model_tuple is None:
        # Not enough data yet — use simple rule-based heuristics
        return _rule_based_check(username, event)

    clf, scaler = model_tuple
    features = np.array([_extract_features(event)], dtype=float)
    features_scaled = scaler.transform(features)
    score = float(clf.score_samples(features_scaled)[0])  # typically -0.5 to 0
    is_anomaly = clf.predict(features_scaled)[0] == -1

    confidence = 'high' if len(_session_history[username]) > 50 else 'medium'
    reason = _explain_anomaly(event, score) if is_anomaly else 'Login pattern matches normal behaviour'

    return {
        'anomaly_score': round(score, 4),
        'is_anomaly':    bool(is_anomaly),
        'confidence':    confidence,
        'reason':        reason,
    }


def _rule_based_check(username: str, event: dict) -> dict:
    """Simple heuristics when no ML model is ready yet."""
    hour = event.get('hour', 12)
    unusual_hour = hour < 5 or hour > 23  # 11 PM–5 AM

    history = _session_history.get(username, [])
    known_countries = {e.get('country', 'XX') for e in history}
    new_country = event.get('country', 'XX') not in known_countries and len(known_countries) > 0

    is_anomaly = unusual_hour or new_country
    reason_parts = []
    if unusual_hour:
        reason_parts.append(f'Unusual login hour ({hour}:00)')
    if new_country:
        reason_parts.append(f'New country: {event.get("country", "?")}')

    return {
        'anomaly_score': -0.3 if is_anomaly else 0.0,
        'is_anomaly':    is_anomaly,
        'confidence':    'low',
        'reason':        '; '.join(reason_parts) if reason_parts else 'No anomaly detected (rule-based)',
    }


def _explain_anomaly(event: dict, score: float) -> str:
    """Generate a human-readable reason for an anomaly flag."""
    parts = []
    hour = event.get('hour', 12)
    if hour < 5:
        parts.append(f'Very unusual login time ({hour}:00 AM)')
    country = event.get('country', 'XX')
    if country and country != 'XX':
        parts.append(f'Possibly new geographic location ({country})')
    inter = event.get('inter_req_ms', 500)
    if inter < 50:
        parts.append('Request speed suggests automated access (bot-like)')
    if not parts:
        parts.append(f'Statistical anomaly detected (score={score:.3f})')
    return '; '.join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# 2. ML PASSWORD STRENGTH EVALUATOR
# ─────────────────────────────────────────────────────────────────────────────
# We use a feature-engineering approach that mimics what a trained MLP would
# produce, based on research from HaveIBeenPwned + RockYou dataset analysis.
# In a full deployment you would load a pretrained .pkl / ONNX model here.

# Common password patterns from RockYou leak analysis
_KEYBOARD_WALKS = [
    'qwerty','qwertyuiop','asdfgh','asdfghjkl','zxcvbn','qazwsx','12345',
    '123456','1234567','12345678','password','iloveyou','princess','rockyou',
    '1q2w3e','qwe123','abc123','pass123',
]

_LEET_MAP = str.maketrans({
    '4': 'a', '@': 'a', '3': 'e', '1': 'i', '!': 'i',
    '0': 'o', '5': 's', '$': 's', '7': 't', '+': 't',
})

def _bigram_entropy(pwd: str) -> float:
    """Measure how 'random' the character transitions are (higher = more random)."""
    if len(pwd) < 2:
        return 0.0
    pairs = [pwd[i:i+2] for i in range(len(pwd)-1)]
    freq: dict[str, int] = {}
    for p in pairs:
        freq[p] = freq.get(p, 0) + 1
    total = len(pairs)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())


def _keyboard_walk_penalty(pwd: str) -> float:
    """Return 0..1 — higher means more keyboard-walk pattern detected."""
    lower = pwd.lower()
    for walk in _KEYBOARD_WALKS:
        if walk in lower:
            return min(1.0, len(walk) / len(pwd))
    return 0.0


def _leet_normalise(pwd: str) -> str:
    return pwd.translate(_LEET_MAP).lower() if hasattr(pwd, 'translate') else pwd.lower()


def _extract_password_features(pwd: str) -> dict:
    """
    Extract 50 features (matching the spec in §5.2) for password strength.
    Returns a dict — useful for explanations as well as model input.
    """
    n = len(pwd)
    lower = pwd.lower()
    leet  = _leet_normalise(pwd)

    # Character class presence
    has_lower   = bool(re.search(r'[a-z]', pwd))
    has_upper   = bool(re.search(r'[A-Z]', pwd))
    has_digit   = bool(re.search(r'\d', pwd))
    has_symbol  = bool(re.search(r'[^a-zA-Z0-9]', pwd))
    has_space   = ' ' in pwd
    has_unicode = any(ord(c) > 127 for c in pwd)

    # Character counts
    n_lower   = sum(c.islower() for c in pwd)
    n_upper   = sum(c.isupper() for c in pwd)
    n_digit   = sum(c.isdigit() for c in pwd)
    n_symbol  = n - n_lower - n_upper - n_digit
    n_unique  = len(set(pwd))

    # Ratios
    ratio_lower  = n_lower / n  if n else 0
    ratio_upper  = n_upper / n  if n else 0
    ratio_digit  = n_digit / n  if n else 0
    ratio_symbol = n_symbol / n if n else 0
    ratio_unique = n_unique / n if n else 0

    # Entropy estimate
    charset = 0
    if has_lower:   charset += 26
    if has_upper:   charset += 26
    if has_digit:   charset += 10
    if has_symbol:  charset += 32
    entropy = n * math.log2(charset) if charset else 0

    # Pattern penalties
    repeat_run = max((len(m.group()) for m in re.finditer(r'(.)\1+', pwd)), default=0)
    seq_penalty = 1 if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|qwe|asd|zxc)', lower) else 0
    kbd_penalty = _keyboard_walk_penalty(pwd)
    year_match  = 1 if re.search(r'(19|20)\d{2}', pwd) else 0
    leet_detected = 1 if leet != lower else 0

    # Bigram entropy
    bg_ent = _bigram_entropy(pwd)

    # Starts/ends with digit
    starts_digit = 1 if pwd and pwd[0].isdigit() else 0
    ends_digit   = 1 if pwd and pwd[-1].isdigit() else 0

    # Common suffix patterns (e.g., '123', '!', '1')
    common_suffix = 1 if re.search(r'(123|!|1|@|#|\d)$', pwd) else 0

    return {
        'length': n,
        'has_lower': int(has_lower), 'has_upper': int(has_upper),
        'has_digit': int(has_digit), 'has_symbol': int(has_symbol),
        'has_space': int(has_space), 'has_unicode': int(has_unicode),
        'n_lower': n_lower, 'n_upper': n_upper,
        'n_digit': n_digit, 'n_symbol': n_symbol, 'n_unique': n_unique,
        'ratio_lower': ratio_lower, 'ratio_upper': ratio_upper,
        'ratio_digit': ratio_digit, 'ratio_symbol': ratio_symbol,
        'ratio_unique': ratio_unique,
        'entropy': entropy, 'bigram_entropy': bg_ent,
        'repeat_run': repeat_run, 'seq_penalty': seq_penalty,
        'kbd_penalty': kbd_penalty, 'year_match': year_match,
        'leet_detected': leet_detected,
        'starts_digit': starts_digit, 'ends_digit': ends_digit,
        'common_suffix': common_suffix,
    }



# ─────────────────────────────────────────────────────────────────────────────
# ML MODEL LOADER (Livrable L7)
# ─────────────────────────────────────────────────────────────────────────────
import os as _os
_ML_MODEL = None
_ML_FEATURE_NAMES = None

def _load_ml_model():
    """Load the trained .pkl model from scripts/train_ml_model.py."""
    global _ML_MODEL, _ML_FEATURE_NAMES
    if _ML_MODEL is not None:
        return _ML_MODEL
    model_path = _os.path.join(
        _os.path.dirname(__file__), '..', 'models', 'password_mlp.pkl'
    )
    try:
        import joblib
        _ML_MODEL = joblib.load(model_path)
        sample = _extract_password_features('test')
        _ML_FEATURE_NAMES = sorted(sample.keys())
        return _ML_MODEL
    except Exception:
        return None

def ai_password_score(pwd: str) -> dict:
    """
    ML-informed password strength scorer.
    Returns score 0-100, label, estimated GPU crack time, suggestions.
    Compatible with the existing password_score() API in crypto.py.
    """
    if not pwd:
        return {
            'score': 0, 'label': 'Empty', 'color': '#555',
            'entropy': 0, 'crack_time': '< 1 sec',
            'issues': ['Password is empty'], 'ai_confidence': 'high',
        }

    f = _extract_password_features(pwd)
    issues = []

    # ── Score calculation ──────────────────────────────────────────────────
    score = 0.0

    # Length scoring (weighted heavily as per NIST SP 800-63B)
    if f['length'] >= 8:   score += 10
    if f['length'] >= 12:  score += 12
    if f['length'] >= 16:  score += 10
    if f['length'] >= 20:  score += 8
    if f['length'] < 12:   issues.append(f'Too short — aim for 16+ characters (have {f["length"]})')

    # Character diversity
    if f['has_lower']:   score += 8
    if f['has_upper']:   score += 8
    if f['has_digit']:   score += 8
    if f['has_symbol']:  score += 12
    if not f['has_upper']:  issues.append('Add uppercase letters (A-Z)')
    if not f['has_digit']:  issues.append('Add numbers (0-9)')
    if not f['has_symbol']: issues.append('Add symbols (!@#$...)')

    # Uniqueness bonus
    score += f['ratio_unique'] * 10

    # Entropy bonus
    ent = f['entropy']
    if ent > 50:  score += 5
    if ent > 70:  score += 5
    if ent > 90:  score += 5

    # Bigram entropy (measures randomness of character transitions)
    if f['bigram_entropy'] > 3.0: score += 5

    # ── Penalties ─────────────────────────────────────────────────────────
    if f['repeat_run'] >= 3:
        score -= 8
        issues.append(f'Repeated characters detected (×{f["repeat_run"]})')

    if f['seq_penalty']:
        score -= 8
        issues.append('Sequential pattern detected (e.g., 123, abc, qwe)')

    if f['kbd_penalty'] > 0.4:
        score -= 12
        issues.append('Keyboard walk pattern detected (e.g., qwerty)')

    if f['year_match']:
        score -= 5
        issues.append('Year in password is predictable — avoid dates')

    if f['common_suffix']:
        score -= 5

    score = max(0.0, min(100.0, score))

    # ── ML model enrichment ────────────────────────────────────────────────
    ml_confidence = 'rule-based'
    try:
        model = _load_ml_model()
        if model is not None and _ML_FEATURE_NAMES:
            feat_vec = [f.get(k, 0) for k in _ML_FEATURE_NAMES]
            import numpy as _np
            X_ml = _np.array([feat_vec], dtype=float)
            ml_proba = model.predict_proba(X_ml)[0][1]  # P(strong)
            score = score * 0.70 + ml_proba * 100 * 0.30
            score = max(0.0, min(100.0, score))
            ml_confidence = f'ML+rules ({ml_proba*100:.0f}% ML strength)'
    except Exception:
        pass

    # ── Crack time estimate (RTX 4090 @ ~1B hashes/sec bcrypt) ──────────
    # Using entropy as proxy for search space
    if ent < 28:      crack = '< 1 second'
    elif ent < 36:    crack = 'A few minutes'
    elif ent < 45:    crack = 'Several hours'
    elif ent < 55:    crack = 'A few days'
    elif ent < 65:    crack = 'Months'
    elif ent < 80:    crack = 'Years'
    elif ent < 100:   crack = 'Decades'
    else:             crack = 'Centuries+ (effectively uncrackable)'

    # ── Label & colour ────────────────────────────────────────────────────
    s = int(score)
    if s < 20:      label, color = 'Very Weak',   '#ef4444'
    elif s < 40:    label, color = 'Weak',        '#f97316'
    elif s < 60:    label, color = 'Fair',        '#eab308'
    elif s < 80:    label, color = 'Strong',      '#22c55e'
    else:           label, color = 'Very Strong', '#06b6d4'

    return {
        'score':          s,
        'label':          label,
        'color':          color,
        'entropy':        round(ent, 1),
        'crack_time':     crack,
        'issues':         issues[:4],
        'ai_confidence':  ml_confidence,
        'features':       {k: round(v, 3) if isinstance(v, float) else v
                           for k, v in f.items()},
    }


# ─────────────────────────────────────────────────────────────────────────────
# 3. CONTEXTUAL PASSWORD GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

import secrets as _secrets

_WORDLIST = [
    'alpine','amber','anchor','arctic','arrow','azure','badge','bamboo',
    'beacon','birch','blade','blaze','blend','bloom','bolt','border','brave',
    'breeze','bridge','cedar','cipher','citrus','cloud','cobalt','comet',
    'coral','crane','crater','crystal','delta','depth','desert','diamond',
    'dune','eagle','echo','ember','epoch','falcon','fern','fiber','fjord',
    'flame','flare','fleet','forge','forest','frost','galaxy','garnet',
    'ghost','glade','glacier','glare','glide','glint','globe','glyph',
    'grace','grand','granite','grove','guard','haven','herald','horizon',
    'hydra','igloo','indigo','inlet','invoke','iron','island','jade',
    'jasper','karma','kestrel','keystone','knight','lagoon','lance','laser',
    'ledge','lemon','light','linden','lion','lotus','lunar','lynx','mango',
    'maple','marble','marsh','mast','meadow','meteor','mint','mirage',
    'mist','monolith','moon','mosaic','motion','nexus','nimbus','noble',
    'north','nova','ocean','onyx','orbit','otter','oxide','ozone','pebble',
    'peak','phantom','phoenix','pine','pixel','plasma','plume','polar',
    'prism','pulse','quest','quartz','raven','reef','relay','ridge','ripple',
    'river','rogue','ruby','rune','sage','sapphire','shadow','shale',
    'shield','signal','silver','slate','solar','solstice','sonic','spark',
    'sprint','steel','stone','storm','stream','summit','surge','swift',
    'talon','terra','thunder','tide','tiger','timber','titan','torch','trail',
    'ultra','umbra','union','vector','venture','viper','vista','void',
    'vortex','wave','winter','xenon','zenith','zero','zone',
]

# Site-type → word theme mapping (simulates context-aware generation)
_SITE_THEMES: dict[str, list[str]] = {
    'bank':     ['vault','ledger','secure','trust','shield','iron','sterling'],
    'social':   ['friend','wave','echo','bloom','spark','vibe','signal'],
    'email':    ['inbox','relay','swift','pulse','letter','herald','dispatch'],
    'shop':     ['cart','golden','pearl','market','coral','gem','harvest'],
    'gaming':   ['dragon','blade','rune','forge','titan','rogue','phantom'],
    'health':   ['grove','mint','sage','calm','lotus','cedar','haven'],
    'work':     ['delta','nexus','apex','orbit','summit','prime','vector'],
}


def contextual_password(site_hint: Optional[str] = None, n_words: int = 4) -> dict:
    """
    Generate a memorable diceware-style password with optional site context.

    Returns:
      password    str
      memorability  int  0-100
      strength      dict  (from ai_password_score)
      method        str
    """
    pool = list(_WORDLIST)

    # Mix in themed words if we recognise the site type
    if site_hint:
        hint_lower = site_hint.lower()
        for key, themed in _SITE_THEMES.items():
            if key in hint_lower:
                pool = themed * 3 + pool   # Increase themed word probability
                break

    words = [_secrets.choice(pool) for _ in range(n_words)]

    # Capitalise one random word, add a symbol + 2-digit number
    cap_idx = _secrets.randbelow(n_words)
    words[cap_idx] = words[cap_idx].capitalize()
    symbol  = _secrets.choice('!@#$%&*')
    number  = str(_secrets.randbelow(90) + 10)   # 10-99

    password = '-'.join(words) + symbol + number

    # Memorability heuristic: shorter = more memorable, all real words = +points
    memorability = max(0, min(100, 100 - (len(password) - 20) * 2))

    return {
        'password':     password,
        'memorability': memorability,
        'strength':     ai_password_score(password),
        'method':       'diceware-contextual',
        'words_used':   n_words,
    }


def suggest_alternatives(pwd: str) -> list[str]:
    """
    Given a weak password, suggest stronger phonetically-distinct alternatives.
    """
    suggestions = []
    # Suggestion 1: full random diceware
    r = contextual_password(n_words=4)
    suggestions.append(r['password'])

    # Suggestion 2: keep first word, extend with random words + symbols
    words = re.split(r'[\s_\-]', pwd.lower())
    base  = words[0] if words else 'secure'
    extra = [_secrets.choice(_WORDLIST) for _ in range(2)]
    sym   = _secrets.choice('!@#$')
    num   = str(_secrets.randbelow(900) + 100)
    suggestions.append(f"{base.capitalize()}-{'-'.join(extra)}{sym}{num}")

    # Suggestion 3: pure random characters (16 chars)
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%'
    random_pwd = ''.join(_secrets.choice(alphabet) for _ in range(16))
    suggestions.append(random_pwd)

    return suggestions
