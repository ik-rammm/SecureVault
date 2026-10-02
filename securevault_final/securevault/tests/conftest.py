"""
Shared pytest configuration for SecureVault test suite.
"""
import os
import sys

# Make sure 'app' package is importable from tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
