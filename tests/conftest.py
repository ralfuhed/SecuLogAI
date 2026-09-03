"""Shared test setup: put the repo root on sys.path and expose fixture helpers."""

import os
import sys
from datetime import datetime, timedelta

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')


@pytest.fixture
def fixture_path():
    """Resolve a filename inside tests/fixtures/."""
    def _resolve(name):
        return os.path.join(FIXTURE_DIR, name)
    return _resolve


@pytest.fixture
def auth_events():
    """
    Build SSH auth events programmatically.

    Rule thresholds are timing-sensitive, so tests need exact control over
    timestamps rather than whatever a log fixture happens to contain.
    """
    def _build(ip='198.51.100.99', count=5, spacing_seconds=10,
               event='failed_login', user='root', start=None):
        base = start or datetime(2025, 1, 10, 3, 0, 0)
        return [
            {
                'type': 'auth',
                'event': event,
                'ip': ip,
                'user': user,
                'timestamp': base + timedelta(seconds=i * spacing_seconds),
                'raw': f'synthetic {event} {i}',
            }
            for i in range(count)
        ]
    return _build


@pytest.fixture
def web_events():
    """Build web access events programmatically."""
    def _build(ip='172.16.0.99', paths=None, status=200, spacing_seconds=10, start=None):
        base = start or datetime(2025, 1, 10, 1, 30, 0)
        paths = paths or ['/index.html']
        return [
            {
                'type': 'web',
                'event': 'http_request',
                'ip': ip,
                'method': 'GET',
                'path': path,
                'status': status,
                'size': 512,
                'agent': 'pytest',
                'timestamp': base + timedelta(seconds=i * spacing_seconds),
                'raw': f'synthetic web request {i}',
            }
            for i, path in enumerate(paths)
        ]
    return _build
