"""End-to-end tests: generated logs through parse -> features -> rules -> ML.

These assert on detection *outcomes* rather than exact counts, so they stay
meaningful as thresholds are tuned, while still failing loudly if a known
attacker stops being caught.
"""

import os
import random
import subprocess
import sys

import pytest

from analyzer.feature_extractor import extract_auth_features, extract_web_features
from analyzer.log_parser import auto_parse
from analyzer.ml_detector import detect_anomalies, get_ip_scores
from analyzer.rule_engine import run_all_rules

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# IPs the sample generator plants attacks on
BRUTE_FORCER = '198.51.100.99'
STUFFER = '192.0.2.55'
SQLI_ATTACKER = '172.16.0.99'
TRAVERSAL_ATTACKER = '10.10.10.10'
SCANNER = '192.168.99.1'
BENIGN_AUTH_IPS = {'203.0.113.10', '203.0.113.20', '203.0.113.30'}


@pytest.fixture
def generated_auth_log(tmp_path):
    import generate_sample_logs
    random.seed(42)
    path = tmp_path / 'auth.log'
    generate_sample_logs.gen_auth_log(str(path))
    return str(path)


@pytest.fixture
def generated_web_log(tmp_path):
    import generate_sample_logs
    random.seed(42)
    path = tmp_path / 'access.log'
    generate_sample_logs.gen_web_log(str(path))
    return str(path)


def _analyse(path):
    events, log_type = auto_parse(path)
    features = extract_auth_features(events) if log_type == 'auth' else extract_web_features(events)
    return events, log_type, features, run_all_rules(events, log_type)


class TestAuthPipeline:
    def test_catches_the_brute_forcer(self, generated_auth_log):
        _, _, _, threats = _analyse(generated_auth_log)
        brute = [t for t in threats if t['threat_type'] == 'Brute Force Attack']
        assert [t['ip'] for t in brute] == [BRUTE_FORCER]
        assert brute[0]['severity'] == 'CRITICAL'

    def test_catches_the_credential_stuffer(self, generated_auth_log):
        _, _, _, threats = _analyse(generated_auth_log)
        stuffing_ips = {t['ip'] for t in threats if t['threat_type'] == 'Credential Stuffing'}
        assert STUFFER in stuffing_ips

    def test_leaves_ordinary_users_alone(self, generated_auth_log):
        """The three normal users each mistype a password once. None should alert."""
        _, _, _, threats = _analyse(generated_auth_log)
        assert BENIGN_AUTH_IPS.isdisjoint({t['ip'] for t in threats})

    def test_features_cover_every_ip(self, generated_auth_log):
        events, _, features, _ = _analyse(generated_auth_log)
        assert len(features) == len({e['ip'] for e in events})
        assert features['failure_rate'].between(0, 1).all()


class TestWebPipeline:
    def test_catches_each_attack_class(self, generated_web_log):
        _, _, _, threats = _analyse(generated_web_log)
        by_type = {t['threat_type']: t['ip'] for t in threats}
        assert by_type.get('SQL Injection Attempt') == SQLI_ATTACKER
        assert by_type.get('Directory Traversal') == TRAVERSAL_ATTACKER
        assert by_type.get('Path Scanner Detected') == SCANNER

    def test_leaves_ordinary_browsing_alone(self, generated_web_log):
        _, _, _, threats = _analyse(generated_web_log)
        flagged = {t['ip'] for t in threats}
        assert all(not ip.startswith('10.0.0.') for ip in flagged)


class TestMLDeterminism:
    """Isolation Forest is seeded; identical input must give identical scores."""

    def test_scores_are_reproducible(self, generated_auth_log):
        _, log_type, features, _ = _analyse(generated_auth_log)
        first = get_ip_scores(features, log_type)
        second = get_ip_scores(features, log_type)
        assert first['anomaly_score'].tolist() == second['anomaly_score'].tolist()

    def test_scores_stay_in_unit_range(self, generated_auth_log):
        _, log_type, features, _ = _analyse(generated_auth_log)
        scores = get_ip_scores(features, log_type)['anomaly_score']
        assert scores.between(0, 1).all()

    def test_handles_empty_features(self):
        import pandas as pd
        assert detect_anomalies(pd.DataFrame(), 'auth') == []
        assert get_ip_scores(pd.DataFrame(), 'auth').empty


def _benign_web_events(n_ips, seed):
    """Ordinary browsing only: no attack in the log at all."""
    from datetime import datetime, timedelta
    rng = random.Random(seed)
    pages = ['/', '/index.html', '/about', '/products', '/contact',
             '/blog/post-1', '/blog/post-2', '/static/app.js', '/img/logo.png']
    base = datetime(2025, 1, 10, 9, 0)
    return [
        {'type': 'web', 'event': 'http_request', 'ip': f'10.0.0.{i + 1}', 'method': 'GET',
         'path': rng.choice(pages), 'status': rng.choice([200] * 19 + [404]), 'size': 512,
         'agent': 'Mozilla/5.0', 'timestamp': base + timedelta(minutes=rng.randint(0, 480)),
         'raw': ''}
        for i in range(n_ips) for _ in range(rng.randint(5, 40))
    ]


class TestMLPrecision:
    """
    The model used to flag a fixed 10% of IPs and rescale scores so the most
    unusual IP in every upload scored 1.0. A log of nothing but ordinary
    traffic therefore always produced alerts, one of them CRITICAL, while a
    log with more than 10% attackers could not have them all flagged.
    """

    @pytest.mark.parametrize('n_ips', [5, 20, 100])
    def test_ordinary_traffic_raises_no_ml_alert(self, n_ips):
        events = _benign_web_events(n_ips, seed=n_ips)
        assert detect_anomalies(extract_web_features(events), 'web') == []

    def test_labelled_dataset_recall(self):
        """Ground truth: 11 of 51 IPs are malicious. The 10% cap caught 5."""
        events, _ = auto_parse(os.path.join(REPO_ROOT, 'data', 'ssh_anomaly_dataset.csv'))
        malicious = {e['ip'] for e in events if e.get('label', 'normal') not in ('normal', '')}
        flagged = {t['ip'] for t in detect_anomalies(extract_auth_features(events), 'auth')}
        assert len(flagged & malicious) >= 9
        assert flagged - malicious == set()

    def test_an_outlier_alone_is_never_critical(self, generated_web_log):
        _, log_type, features, _ = _analyse(generated_web_log)
        threats = detect_anomalies(features, log_type)
        assert threats, 'the planted attackers should still be flagged'
        assert all(t['severity'] in ('HIGH', 'MEDIUM') for t in threats)

    def test_alerts_carry_the_time_of_the_activity(self, generated_auth_log):
        _, log_type, features, _ = _analyse(generated_auth_log)
        first_seen = dict(zip(features['ip'], features['first_seen']))
        for t in detect_anomalies(features, log_type):
            assert t['timestamp'] == first_seen[t['ip']]


class TestCommandLineInterface:
    def test_analyze_command_runs_clean(self, generated_auth_log):
        result = subprocess.run(
            [sys.executable, 'cli.py', 'analyze', generated_auth_log],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=180,
        )
        assert result.returncode == 0, result.stderr
        assert 'Brute Force Attack' in result.stdout

    def test_reports_missing_file_without_traceback(self):
        result = subprocess.run(
            [sys.executable, 'cli.py', 'analyze', 'does_not_exist.log'],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 1
        assert 'Traceback' not in result.stderr
