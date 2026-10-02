#!/usr/bin/env python3
"""
SecureVault — KDF Benchmark
============================
Compares PBKDF2-HMAC-SHA256 vs Argon2id performance on the current machine.
Generates a performance report with recommendations.

Usage:
    python scripts/benchmark_kdf.py
    python scripts/benchmark_kdf.py --output report.json
    python scripts/benchmark_kdf.py --iterations 3

Livrable L6 — Benchmark cryptographique (Section 7.1 du Cahier des Charges)
"""

import sys
import os
import time
import json
import statistics
import platform
import hashlib
import argparse

# Ensure we can import from parent
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def benchmark_pbkdf2(password: str, salt: bytes, iterations: int,
                     runs: int = 5) -> dict:
    """Benchmark PBKDF2-HMAC-SHA256."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    times = []
    for _ in range(runs):
        start = time.perf_counter()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        kdf.derive(password.encode())
        elapsed = time.perf_counter() - start
        times.append(elapsed * 1000)  # ms

    return {
        'algorithm':  'PBKDF2-HMAC-SHA256',
        'iterations': iterations,
        'runs':       runs,
        'mean_ms':    round(statistics.mean(times), 2),
        'median_ms':  round(statistics.median(times), 2),
        'min_ms':     round(min(times), 2),
        'max_ms':     round(max(times), 2),
        'stdev_ms':   round(statistics.stdev(times), 2) if runs > 1 else 0,
        'memory_mb':  'minimal (~1 KB)',
        'gpu_resistant': False,
        'nist_approved': True,
    }


def benchmark_argon2(password: str, salt: bytes,
                     time_cost: int = 3, memory_cost: int = 65536,
                     parallelism: int = 4, runs: int = 5) -> dict:
    """Benchmark Argon2id."""
    try:
        from argon2.low_level import hash_secret_raw, Type
    except ImportError:
        return {'error': 'argon2-cffi not installed. Run: pip install argon2-cffi'}

    times = []
    for _ in range(runs):
        start = time.perf_counter()
        hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            type=Type.ID,
        )
        elapsed = time.perf_counter() - start
        times.append(elapsed * 1000)  # ms

    return {
        'algorithm':    'Argon2id',
        'time_cost':    time_cost,
        'memory_cost':  f'{memory_cost // 1024} MB',
        'parallelism':  parallelism,
        'runs':         runs,
        'mean_ms':      round(statistics.mean(times), 2),
        'median_ms':    round(statistics.median(times), 2),
        'min_ms':       round(min(times), 2),
        'max_ms':       round(max(times), 2),
        'stdev_ms':     round(statistics.stdev(times), 2) if runs > 1 else 0,
        'memory_mb':    f'{memory_cost // 1024} MB (memory-hard)',
        'gpu_resistant': True,
        'nist_approved': False,   # Not NIST-approved yet (but widely recommended)
        'password_hashing_competition_winner': True,
    }


def estimate_attack_resistance(result: dict) -> dict:
    """
    Estimate attack resistance based on KDF timing.
    Reference GPU: RTX 4090 — can do ~1B MD5/sec, but KDF limits brute force.
    """
    time_per_attempt_sec = result.get('mean_ms', 1000) / 1000
    if time_per_attempt_sec == 0:
        time_per_attempt_sec = 0.001

    # Realistic parallel GPU attack (1000 threads on RTX 4090)
    attempts_per_sec_gpu   = 1000 / time_per_attempt_sec
    # 8-char lowercase (26^8 ≈ 208 billion combinations)
    charset_8lower         = 26 ** 8
    time_to_crack_8lower_h = charset_8lower / attempts_per_sec_gpu / 3600

    return {
        'attempts_per_sec_single_cpu':  round(1 / time_per_attempt_sec, 2),
        'attempts_per_sec_1000_gpu_threads': round(attempts_per_sec_gpu, 0),
        'time_to_crack_8char_lowercase_hours': round(time_to_crack_8lower_h, 1),
        'recommendation':
            'Excellent GPU resistance' if result.get('gpu_resistant') else
            'Adequate, but vulnerable to GPU acceleration'
    }


def print_report(pbkdf2_result: dict, argon2_result: dict,
                 pbkdf2_attack: dict, argon2_attack: dict,
                 system_info: dict) -> None:
    """Print a formatted benchmark report to stdout."""
    sep = '─' * 65

    print(f'\n{"═" * 65}')
    print('  SecureVault — KDF Benchmark Report')
    print(f'{"═" * 65}')
    print(f'  Platform : {system_info["platform"]}')
    print(f'  CPU      : {system_info["cpu"]}')
    print(f'  Python   : {system_info["python"]}')
    print(f'  Date     : {system_info["date"]}')
    print(sep)

    print('\n  📊 PBKDF2-HMAC-SHA256 (600,000 iterations)')
    print(sep)
    print(f'  Mean time        : {pbkdf2_result["mean_ms"]:>8.1f} ms')
    print(f'  Median time      : {pbkdf2_result["median_ms"]:>8.1f} ms')
    print(f'  Std deviation    : {pbkdf2_result["stdev_ms"]:>8.1f} ms')
    print(f'  Memory usage     : {pbkdf2_result["memory_mb"]}')
    print(f'  GPU resistant    : {"✗ No" if not pbkdf2_result["gpu_resistant"] else "✓ Yes"}')
    print(f'  NIST SP 800-63B  : ✓ Approved')
    print(f'  Attack: attempts/sec (1000 GPU threads): {pbkdf2_attack["attempts_per_sec_1000_gpu_threads"]:,.0f}')
    print(f'  Time to crack 8-char lowercase: {pbkdf2_attack["time_to_crack_8char_lowercase_hours"]:.1f} hours')

    print('\n  🛡️  Argon2id (t=3, m=64MB, p=4)')
    print(sep)
    if 'error' in argon2_result:
        print(f'  ERROR: {argon2_result["error"]}')
    else:
        print(f'  Mean time        : {argon2_result["mean_ms"]:>8.1f} ms')
        print(f'  Median time      : {argon2_result["median_ms"]:>8.1f} ms')
        print(f'  Std deviation    : {argon2_result["stdev_ms"]:>8.1f} ms')
        print(f'  Memory usage     : {argon2_result["memory_mb"]}')
        print(f'  GPU resistant    : ✓ Yes (memory-hard)')
        print(f'  PHC Winner 2015  : ✓ Yes')
        print(f'  Attack: attempts/sec (1000 GPU threads): {argon2_attack["attempts_per_sec_1000_gpu_threads"]:,.0f}')
        print(f'  Time to crack 8-char lowercase: {argon2_attack["time_to_crack_8char_lowercase_hours"]:.1f} hours')

    print('\n  🏆 RECOMMENDATION')
    print(sep)
    if 'error' not in argon2_result:
        ratio = pbkdf2_result['mean_ms'] / max(argon2_result['mean_ms'], 0.001)
        print(f'  Argon2id vs PBKDF2 speed ratio: {ratio:.2f}x slower')
        if ratio < 0.5:
            rec = 'Argon2id is faster AND more secure → USE ARGON2ID'
        else:
            rec = ('Argon2id is slower but offers superior GPU resistance.\n'
                   '  → Use ARGON2ID for maximum security (recommended default)\n'
                   '  → Use PBKDF2 only for NIST/FIPS compliance requirements')
        print(f'  {rec}')
    else:
        print('  Install argon2-cffi to enable Argon2id: pip install argon2-cffi')

    print(f'\n{"═" * 65}\n')


def main():
    parser = argparse.ArgumentParser(description='SecureVault KDF Benchmark')
    parser.add_argument('--runs', type=int, default=5, help='Number of benchmark runs per algorithm')
    parser.add_argument('--output', type=str, help='Save results to JSON file')
    parser.add_argument('--password', type=str, default='BenchmarkPassword123!',
                        help='Test password (irrelevant for timing)')
    args = parser.parse_args()

    import os as _os
    salt = _os.urandom(16)

    system_info = {
        'platform': platform.platform(),
        'cpu':      platform.processor() or platform.machine(),
        'python':   sys.version.split()[0],
        'date':     time.strftime('%Y-%m-%d %H:%M:%S'),
    }

    print(f'Running benchmark ({args.runs} runs per algorithm)...')
    print('This may take a minute — KDF algorithms are intentionally slow.\n')

    pbkdf2_result = benchmark_pbkdf2(args.password, salt, 600_000, args.runs)
    pbkdf2_attack = estimate_attack_resistance(pbkdf2_result)

    argon2_result = benchmark_argon2(args.password, salt, 3, 65536, 4, args.runs)
    argon2_attack = estimate_attack_resistance(argon2_result) if 'error' not in argon2_result else {}

    print_report(pbkdf2_result, argon2_result, pbkdf2_attack, argon2_attack, system_info)

    if args.output:
        report = {
            'system': system_info,
            'pbkdf2': {**pbkdf2_result, 'attack_analysis': pbkdf2_attack},
            'argon2': {**argon2_result, 'attack_analysis': argon2_attack},
        }
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f'Results saved to: {args.output}')


if __name__ == '__main__':
    main()
