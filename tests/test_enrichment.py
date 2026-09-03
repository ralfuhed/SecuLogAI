"""Threat-intel enrichment tests.

Enrichment changes severity, so it needs to be exactly as trustworthy as the
detection itself. These cover the parsing of the indicator file, the
escalation rules, and, importantly, that analysis still works with no
indicator list present at all.
"""

from datetime import datetime

import pytest

from analyzer.enrichment import enrich_threats, load_iocs


@pytest.fixture
def ioc_file(tmp_path):
    path = tmp_path / 'iocs.txt'
    path.write_text(
        '# a comment line\n'
        '\n'
        '198.51.100.99   ssh-brute-source   2026-08-14\n'
        '203.0.113.5     c2                 \n'
        '10.10.10.10     scanner\n'
        'not-an-ip       garbage            2026-01-01\n'
        '192.0.2.7  trailing-comment  2026-02-02  # inline note\n'
    )
    return str(path)


def _threat(ip, severity='HIGH', evidence='5 failed logins'):
    return {'threat_type': 'Brute Force Attack', 'severity': severity, 'ip': ip,
            'evidence': evidence, 'timestamp': datetime(2025, 1, 10, 3, 0), 'count': 5}


class TestLoadingIndicators:
    def test_parses_indicators(self, ioc_file):
        iocs = load_iocs(ioc_file)
        assert iocs['198.51.100.99']['category'] == 'ssh-brute-source'
        assert iocs['198.51.100.99']['first_seen'] == '2026-08-14'

    def test_skips_comments_and_blank_lines(self, ioc_file):
        assert '#' not in ''.join(load_iocs(ioc_file).keys())

    def test_strips_inline_comments(self, ioc_file):
        assert load_iocs(ioc_file)['192.0.2.7']['category'] == 'trailing-comment'

    def test_skips_lines_that_are_not_ip_addresses(self, ioc_file):
        """One malformed line must not sink the whole list."""
        iocs = load_iocs(ioc_file)
        assert 'not-an-ip' not in iocs
        assert len(iocs) == 4

    def test_missing_category_defaults_to_unknown(self, tmp_path):
        path = tmp_path / 'bare.txt'
        path.write_text('198.51.100.1\n')
        assert load_iocs(str(path))['198.51.100.1']['category'] == 'unknown'

    def test_missing_file_is_not_an_error(self, tmp_path):
        """Enrichment is optional; analysis must work without an indicator list."""
        assert load_iocs(str(tmp_path / 'nope.txt')) == {}

    def test_bundled_list_loads(self):
        """The shipped list must stay parseable."""
        assert len(load_iocs()) >= 1


class TestEnrichment:
    def test_annotates_a_matching_threat(self, ioc_file):
        result = enrich_threats([_threat('198.51.100.99')], load_iocs(ioc_file))
        assert result[0]['ioc_match']['category'] == 'ssh-brute-source'
        assert 'indicator list' in result[0]['evidence']

    def test_escalates_severity_one_tier(self, ioc_file):
        iocs = load_iocs(ioc_file)
        assert enrich_threats([_threat('198.51.100.99', 'HIGH')], iocs)[0]['severity'] == 'CRITICAL'
        assert enrich_threats([_threat('198.51.100.99', 'MEDIUM')], iocs)[0]['severity'] == 'HIGH'
        assert enrich_threats([_threat('198.51.100.99', 'LOW')], iocs)[0]['severity'] == 'MEDIUM'

    def test_critical_does_not_overflow(self, ioc_file):
        result = enrich_threats([_threat('198.51.100.99', 'CRITICAL')], load_iocs(ioc_file))
        assert result[0]['severity'] == 'CRITICAL'

    def test_leaves_unlisted_sources_untouched(self, ioc_file):
        original = _threat('192.0.2.55', 'HIGH')
        result = enrich_threats([original], load_iocs(ioc_file))
        assert result[0]['severity'] == 'HIGH'
        assert 'ioc_match' not in result[0]

    def test_does_not_mutate_the_input(self, ioc_file):
        """Callers keep the raw detection output."""
        original = _threat('198.51.100.99', 'HIGH')
        enrich_threats([original], load_iocs(ioc_file))
        assert original['severity'] == 'HIGH'
        assert 'ioc_match' not in original

    def test_empty_indicator_list_is_a_no_op(self):
        threats = [_threat('198.51.100.99')]
        assert enrich_threats(threats, {}) is threats

    def test_handles_no_threats(self, ioc_file):
        assert enrich_threats([], load_iocs(ioc_file)) == []


class TestPipelineIntegration:
    @pytest.fixture
    def generated_auth_log(self, tmp_path):
        """
        Generate the log rather than reading data/sample_auth.log.

        The sample logs are gitignored, so depending on one makes the test pass
        only on a machine that happens to have run the generator.
        """
        import random

        import generate_sample_logs
        random.seed(42)
        path = tmp_path / 'auth.log'
        generate_sample_logs.gen_auth_log(str(path))
        return str(path)

    def test_sample_log_threat_is_escalated_and_annotated(self, generated_auth_log):
        """End to end: the bundled IOC list must reach real detections."""
        from analyzer.log_parser import auto_parse
        from analyzer.rule_engine import run_all_rules

        events, log_type = auto_parse(generated_auth_log)
        threats = enrich_threats(run_all_rules(events, log_type))

        listed = [t for t in threats if t['ip'] == '198.51.100.99']
        assert listed, 'expected a detection on the known-bad sample IP'
        assert all(t.get('ioc_match') for t in listed)
        assert all(t['severity'] == 'CRITICAL' for t in listed)

        # An attacker not on the list keeps its original severity
        unlisted = [t for t in threats if t['ip'] == '192.0.2.55']
        assert unlisted and not any(t.get('ioc_match') for t in unlisted)
