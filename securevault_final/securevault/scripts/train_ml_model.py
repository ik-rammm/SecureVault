#!/usr/bin/env python3
"""
SecureVault — ML Password Strength Model Training
==================================================
Livrable L7 — Trained AI Model (CDC §7.1)

This script:
  1. Generates a labelled dataset (weak + strong passwords)
  2. Extracts the 50 features defined in ai.py (CDC §5.2)
  3. Trains an MLP (Multi-Layer Perceptron) as required by the CDC
  4. Evaluates performance (accuracy, F1, confusion matrix)
  5. Saves the model as .pkl (joblib)
  6. Generates a metrics report

Usage:
    cd securevault
    python scripts/train_ml_model.py
    python scripts/train_ml_model.py --samples 30000
    python scripts/train_ml_model.py --output models/password_mlp.pkl
"""

import sys
import os
import json
import random
import string
import argparse
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    import numpy as np
    from sklearn.neural_network import MLPClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (
        accuracy_score, f1_score, confusion_matrix,
        classification_report, roc_auc_score
    )
    from sklearn.pipeline import Pipeline
    import joblib
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    print("Install: pip install scikit-learn numpy joblib")
    sys.exit(1)

from app.ai import _extract_password_features

# ─────────────────────────────────────────────────────────────────────────────
# DATASET
# ─────────────────────────────────────────────────────────────────────────────

WEAK_PASSWORDS = [
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
    'letmein', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
    'ashley', 'bailey', 'passw0rd', 'shadow', '123123', '654321',
    'superman', 'qazwsx', 'michael', 'football', 'password1', 'admin',
    'welcome', 'login', 'pass', 'test', 'guest', 'hello', '111111',
    'password123', 'abc', '1234', 'temp', 'root', 'toor', 'admin123',
    'changeme', 'qwerty123', 'azerty', 'soleil', 'bonjour', '000000',
    'azertyuiop', 'motdepasse', 'marseille', 'password!', '12345',
]

KEYBOARD_WALKS = [
    'qwerty', 'qwertyuiop', 'asdfgh', 'zxcvbn', 'azerty',
    '1234567890', '0987654321', 'qazwsx', 'abcdef',
]

LEET_WEAK = [
    'p@ssw0rd', 'p455w0rd', '@dm1n', 'l3tm31n', 's3cur1ty',
    'h@ck3r', 'l0g1n', 'w3lc0m3',
]


def generate_weak_password() -> str:
    strategies = [
        lambda: random.choice(WEAK_PASSWORDS[:20]) + str(random.randint(1, 999)),
        lambda: random.choice(['john','alex','marie','pierre','emma','lucas']) + str(random.randint(1970, 2005)),
        lambda: random.choice(WEAK_PASSWORDS),
        lambda: random.choice(KEYBOARD_WALKS),
        lambda: random.choice('abcdefghij') * random.randint(6, 10),
        lambda: ''.join(str(i) for i in range(random.randint(4, 8))),
        lambda: random.choice(LEET_WEAK),
        lambda: random.choice(WEAK_PASSWORDS[:15]) + random.choice('!@#'),
        lambda: ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 7))),
    ]
    return random.choice(strategies)()


def generate_strong_password() -> str:
    strategies = [
        lambda: ''.join(random.choices(
            string.ascii_lowercase + string.ascii_uppercase + string.digits + '!@#$%^&*()_+',
            k=random.randint(16, 32)
        )),
        lambda: '-'.join(
            ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 8)))
            for _ in range(random.randint(4, 6))
        ) + random.choice('!@#$') + str(random.randint(10, 99)),
        lambda: ''.join(random.choices(string.ascii_letters, k=8))
                + str(random.randint(100, 9999))
                + random.choice('!@#$%&*')
                + ''.join(random.choices(string.ascii_letters, k=6)),
    ]
    pwd = random.choice(strategies)()
    chars = list(pwd)
    random.shuffle(chars)
    return ''.join(chars)


def build_dataset(n_samples: int = 20000) -> tuple:
    print(f"[INFO] Generating {n_samples} passwords...")
    passwords, labels = [], []
    half = n_samples // 2
    for _ in range(half):
        passwords.append(generate_weak_password())
        labels.append(0)
    for _ in range(half):
        passwords.append(generate_strong_password())
        labels.append(1)

    print("[INFO] Extracting features (50 features per password)...")
    feature_dicts = [_extract_password_features(p) for p in passwords]
    feature_names = sorted(feature_dicts[0].keys())
    X = np.array([[fd[k] for k in feature_names] for fd in feature_dicts], dtype=float)
    y = np.array(labels)
    print(f"[INFO] Dataset: {X.shape[0]} samples, {X.shape[1]} features")
    return X, y, feature_names, passwords


def train_model(X, y) -> Pipeline:
    """
    Trains an MLP (Multi-Layer Perceptron) with StandardScaler.
    Architecture: 50 → 128 → 64 → 32 → 1 (sigmoid) — CDC §5.2
    """
    print("\n[INFO] Training MLP...")
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('mlp', MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation='relu',
            solver='adam',
            alpha=0.001,
            batch_size=256,
            learning_rate='adaptive',
            max_iter=500,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=20,
            random_state=42,
            verbose=False,
        ))
    ])
    start = time.time()
    pipeline.fit(X, y)
    elapsed = time.time() - start
    print(f"[INFO] Training completed in {elapsed:.1f}s")
    return pipeline


def evaluate_model(pipeline, X_test, y_test, feature_names) -> dict:
    y_pred  = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred)
    auc  = roc_auc_score(y_test, y_proba)
    cm   = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(y_test, y_pred,
                                   target_names=['Weak', 'Strong'],
                                   output_dict=True)

    metrics = {
        'accuracy': round(acc, 4),
        'f1_score': round(f1, 4),
        'roc_auc':  round(auc, 4),
        'confusion_matrix': cm,
        'classification_report': report,
        'n_test_samples': len(y_test),
        'n_features': len(feature_names),
        'feature_names': feature_names,
    }

    print(f"\n{'='*55}")
    print("  MLP MODEL EVALUATION METRICS")
    print(f"{'='*55}")
    print(f"  Accuracy : {acc*100:.2f}%  (CDC target: >92%)")
    print(f"  F1-Score : {f1*100:.2f}%")
    print(f"  ROC-AUC  : {auc*100:.2f}%")
    print(f"\n  Confusion Matrix:")
    print(f"              Predicted Weak  Predicted Strong")
    print(f"  Real Weak       {cm[0][0]:>5}             {cm[0][1]:>5}")
    print(f"  Real Strong     {cm[1][0]:>5}             {cm[1][1]:>5}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['Weak', 'Strong'])}")

    if acc >= 0.92:
        print("  ✓ OBJECTIVE REACHED — Accuracy >= 92% (CDC §5.2 compliant)")
    else:
        print(f"  ✗ Accuracy {acc*100:.1f}% < 92% — Increase n_samples or adjust architecture")
    print(f"{'='*55}\n")

    return metrics


def main():
    parser = argparse.ArgumentParser(description='SecureVault — ML Model Training')
    parser.add_argument('--samples', type=int, default=20000)
    parser.add_argument('--output',  type=str, default='models/password_mlp.pkl')
    parser.add_argument('--report',  type=str, default='models/metrics_report.json')
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else 'models', exist_ok=True)

    X, y, feature_names, passwords = build_dataset(args.samples)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"[INFO] Split: {len(X_train)} train, {len(X_test)} test")

    pipeline = train_model(X_train, y_train)
    metrics  = evaluate_model(pipeline, X_test, y_test, feature_names)

    joblib.dump(pipeline, args.output)
    print(f"[OK] Model saved: {args.output}")

    metrics['model_path']        = args.output
    metrics['training_samples']  = len(X_train)
    metrics['algorithm']         = 'MLPClassifier (128-64-32)'
    metrics['dataset']           = 'Synthetic dataset (weak + strong)'
    with open(args.report, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    print(f"[OK] Metrics report: {args.report}")
    print(f"\n[LIVRABLE L7] Generated files:")
    print(f"  - {args.output}  (model .pkl — include in ZIP)")
    print(f"  - {args.report}  (metrics — include in technical report)")


if __name__ == '__main__':
    main()
