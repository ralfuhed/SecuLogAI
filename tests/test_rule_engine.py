"""Rule engine tests.

Two things matter for a detection rule, and both are tested here:
  1. it fires on the behaviour it claims to catch (no false negatives), and
  2. it stays silent on benign traffic (no false positives).

Threshold rules are tested at the boundary on both sides, because an
off-by-one in a detection threshold is invisible until it matters.
"""

from datetime import datetime, timedelta

from analyzer.rule_engine import (
    BRUTE_FORCE_THRESHOLD,
    CREDENTIAL_STUFF_USERS,
    SCAN_404_THRESHOLD,
    detect_brute_force,
    detect_command_injection,
    detect_credential_stuffing,
    detect_directory_traversal,
    detect_scanner,
    detect_sql_injection,
    detect_xss,
    run_all_rules,
)


def _stuffing_events(ip, usernames, start=None):
    base = start or datetime(2025, 1, 10, 2, 0, 0)
    return [
        {'type': 'auth', 'event': 'failed_login', 'ip': ip, 'user': user,
         'timestamp': base + timedelta(minutes=i * 3), 'raw': ''}
        for i, user in enumerate(usernames)
    ]


class TestBruteForce:
    def test_fires_at_threshold(self, auth_events):
        threats = detect_brute_force(auth_events(count=BRUTE_FORCE_THRESHOLD))
        assert len(threats) == 1
        assert threats[0]['threat_type'] == 'Brute Force Attack'
        assert threats[0]['ip'] == '198.51.100.99'

    def test_silent_one_below_threshold(self, auth_events):
        assert detect_brute_force(auth_events(count=BRUTE_FORCE_THRESHOLD - 1)) == []

    def test_respects_the_sliding_window(self, auth_events):
        """Enough failures overall, but spread too thin to be a burst."""
        spread = auth_events(count=BRUTE_FORCE_THRESHOLD, spacing_seconds=200)
        assert detect_brute_force(spread) == []

    def test_counts_invalid_user_as_a_failure(self, auth_events):
        events = auth_events(count=BRUTE_FORCE_THRESHOLD, event='invalid_user')
        assert len(detect_brute_force(events)) == 1

    def test_ignores_successful_logins(self, auth_events):
        events = auth_events(count=20, event='successful_login')
        assert detect_brute_force(events) == []

    def test_one_alert_per_ip_not_per_attempt(self, auth_events):
        threats = detect_brute_force(auth_events(count=100, spacing_seconds=1))
        assert len(threats) == 1

    def test_severity_escalates_with_volume(self, auth_events):
        def sev(n):
            threats = detect_brute_force(auth_events(count=n, spacing_seconds=1))
            assert threats, f'{n} rapid failures should have raised an alert'
            return threats[0]['severity']
        assert sev(5) == 'MEDIUM'
        assert sev(20) == 'HIGH'
        assert sev(50) == 'CRITICAL'


class TestCredentialStuffing:
    def test_fires_at_threshold(self):
        users = [f'user{i}' for i in range(CREDENTIAL_STUFF_USERS)]
        threats = detect_credential_stuffing(_stuffing_events('192.0.2.55', users))
        assert len(threats) == 1
        assert threats[0]['count'] == CREDENTIAL_STUFF_USERS

    def test_silent_one_below_threshold(self):
        users = [f'user{i}' for i in range(CREDENTIAL_STUFF_USERS - 1)]
        assert detect_credential_stuffing(_stuffing_events('192.0.2.55', users)) == []

    def test_repeated_attempts_on_one_account_are_not_stuffing(self):
        """A user fat-fingering the same password 20 times is not credential stuffing."""
        events = _stuffing_events('203.0.113.10', ['alice'] * 20)
        assert detect_credential_stuffing(events) == []


class TestWebAttackSignatures:
    def test_detects_sql_injection(self, web_events):
        events = web_events(paths=["/login.php?user=admin'--&pass=x"])
        threats = detect_sql_injection(events)
        assert len(threats) == 1
        assert threats[0]['threat_type'] == 'SQL Injection Attempt'

    def test_detects_directory_traversal(self, web_events):
        events = web_events(paths=['/download?file=../../etc/passwd'])
        assert len(detect_directory_traversal(events)) == 1

    def test_detects_url_encoded_traversal(self, web_events):
        events = web_events(paths=['/file?name=%2e%2e%2fetc%2fpasswd'])
        assert len(detect_directory_traversal(events)) == 1

    def test_detects_xss(self, web_events):
        events = web_events(paths=['/search?q=<script>alert(1)</script>'])
        assert len(detect_xss(events)) == 1

    def test_detects_command_injection(self, web_events):
        events = web_events(paths=['/ping?host=8.8.8.8;/bin/sh'])
        assert len(detect_command_injection(events)) == 1

    def test_sql_injection_severity_escalates_with_volume(self, web_events):
        one = web_events(paths=["/x?id=1' OR '1'='1"])
        assert detect_sql_injection(one)[0]['severity'] == 'HIGH'
        many = web_events(paths=["/x?id=1' OR '1'='1"] * 10)
        assert detect_sql_injection(many)[0]['severity'] == 'CRITICAL'


class TestScanner:
    def test_fires_at_threshold(self, web_events):
        events = web_events(paths=[f'/path{i}' for i in range(SCAN_404_THRESHOLD)], status=404)
        threats = detect_scanner(events)
        assert len(threats) == 1
        assert threats[0]['count'] == SCAN_404_THRESHOLD

    def test_silent_one_below_threshold(self, web_events):
        events = web_events(paths=[f'/path{i}' for i in range(SCAN_404_THRESHOLD - 1)], status=404)
        assert detect_scanner(events) == []

    def test_ignores_successful_requests(self, web_events):
        events = web_events(paths=[f'/path{i}' for i in range(100)], status=200)
        assert detect_scanner(events) == []


class TestNoFalsePositivesOnBenignTraffic:
    """The quiet half of detection engineering: normal activity must stay quiet."""

    BENIGN_PATHS = ['/index.html', '/about.html', '/products', '/contact',
                    '/api/users', '/dashboard', '/static/app.js']

    def test_normal_browsing_produces_no_threats(self, web_events):
        events = web_events(ip='10.0.0.1', paths=self.BENIGN_PATHS, status=200)
        assert run_all_rules(events, 'web') == []

    def test_normal_logins_produce_no_threats(self, auth_events):
        events = auth_events(ip='203.0.113.10', count=3, spacing_seconds=3600,
                             event='successful_login', user='alice')
        assert run_all_rules(events, 'auth') == []

    def test_occasional_mistyped_password_is_not_an_attack(self, auth_events):
        events = auth_events(ip='203.0.113.20', count=2, spacing_seconds=45,
                             event='failed_login', user='bob')
        assert run_all_rules(events, 'auth') == []


class TestRunAllRules:
    def test_dispatches_auth_rules_only_for_auth_logs(self, auth_events):
        events = auth_events(count=BRUTE_FORCE_THRESHOLD)
        assert len(run_all_rules(events, 'auth')) >= 1
        # Same events routed as 'web' should match nothing
        assert run_all_rules(events, 'web') == []

    def test_sorts_most_severe_first(self, web_events):
        events = (
            web_events(ip='1.1.1.1', paths=["/x?id=1' OR '1'='1"] * 10)   # CRITICAL
            + web_events(ip='2.2.2.2', paths=['/download?file=../../etc/passwd'])  # HIGH
        )
        threats = run_all_rules(events, 'web')
        severities = [t['severity'] for t in threats]
        assert severities == sorted(
            severities, key=lambda s: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}[s]
        )

    def test_empty_input_is_safe(self):
        assert run_all_rules([], 'auth') == []
        assert run_all_rules([], 'web') == []
