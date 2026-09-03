"""Parser tests: correct extraction, and graceful handling of junk input.

A parser that silently drops lines is a false-negative generator, so these
tests assert on exact event counts, not just "it didn't crash".
"""

from analyzer.log_parser import (
    auto_parse,
    parse_auth_log,
    parse_web_log,
)


class TestAuthLogParser:
    def test_extracts_every_recognised_event(self, fixture_path):
        events = parse_auth_log(fixture_path('auth_sample.log'))
        # 6 lines in the fixture, one of which is deliberate junk
        assert len(events) == 5

    def test_classifies_event_types(self, fixture_path):
        events = parse_auth_log(fixture_path('auth_sample.log'))
        kinds = [e['event'] for e in events]
        assert kinds.count('successful_login') == 2
        assert kinds.count('failed_login') == 2
        assert kinds.count('invalid_user') == 1

    def test_extracts_ip_and_user(self, fixture_path):
        events = parse_auth_log(fixture_path('auth_sample.log'))
        first = events[0]
        assert first['ip'] == '203.0.113.10'
        assert first['user'] == 'alice'
        assert first['event'] == 'successful_login'

    def test_failed_password_for_invalid_user_is_a_failure(self, fixture_path):
        """'Failed password for invalid user X' must not be misread as a plain invalid_user."""
        events = parse_auth_log(fixture_path('auth_sample.log'))
        admin = [e for e in events if e['user'] == 'admin']
        assert len(admin) == 1
        assert admin[0]['event'] == 'failed_login'
        assert admin[0]['ip'] == '198.51.100.99'

    def test_accepts_publickey_as_well_as_password(self, fixture_path):
        events = parse_auth_log(fixture_path('auth_sample.log'))
        carol = [e for e in events if e['user'] == 'carol']
        assert len(carol) == 1
        assert carol[0]['event'] == 'successful_login'

    def test_malformed_lines_are_skipped_not_raised(self, tmp_path):
        junk = tmp_path / 'junk.log'
        junk.write_text('total nonsense\n\n\nmore nonsense\n')
        assert parse_auth_log(str(junk)) == []

    def test_empty_file_returns_empty_list(self, tmp_path):
        empty = tmp_path / 'empty.log'
        empty.write_text('')
        assert parse_auth_log(str(empty)) == []


class TestWebLogParser:
    def test_extracts_every_recognised_request(self, fixture_path):
        events = parse_web_log(fixture_path('web_sample.log'))
        assert len(events) == 3

    def test_extracts_request_fields(self, fixture_path):
        events = parse_web_log(fixture_path('web_sample.log'))
        first = events[0]
        assert first['ip'] == '10.0.0.1'
        assert first['method'] == 'GET'
        assert first['path'] == '/index.html'
        assert first['status'] == 200
        assert first['size'] == 1043

    def test_dash_size_becomes_zero(self, fixture_path):
        """Apache writes '-' for a zero-byte body; that must not crash int()."""
        events = parse_web_log(fixture_path('web_sample.log'))
        scanner_hit = [e for e in events if e['status'] == 404][0]
        assert scanner_hit['size'] == 0

    def test_captures_user_agent(self, fixture_path):
        events = parse_web_log(fixture_path('web_sample.log'))
        assert any('Nikto' in e['agent'] for e in events)

    def test_malformed_lines_are_skipped_not_raised(self, tmp_path):
        junk = tmp_path / 'junk.log'
        junk.write_text('not a log line\n<<<>>>\n')
        assert parse_web_log(str(junk)) == []


class TestPayloadsContainingSpaces:
    """
    Regression cover for a false-negative class: attack payloads with raw
    spaces or quotes in the request path. A \\S+ path pattern drops these,
    which means the parser silently discards the most interesting lines in
    the log while reporting success.
    """

    def test_parses_every_line_including_spaced_payloads(self, fixture_path):
        events = parse_web_log(fixture_path('web_spaced_payloads.log'))
        assert len(events) == 6

    def test_preserves_the_full_sql_payload(self, fixture_path):
        events = parse_web_log(fixture_path('web_spaced_payloads.log'))
        union = [e for e in events if 'UNION' in e['path']]
        assert len(union) == 1
        assert union[0]['path'] == '/products?id=1 UNION SELECT username,password FROM users--'

    def test_handles_a_quote_inside_the_payload(self, fixture_path):
        """The XSS payload contains an unescaped double quote."""
        events = parse_web_log(fixture_path('web_spaced_payloads.log'))
        xss = [e for e in events if 'onerror' in e['path']]
        assert len(xss) == 1
        assert xss[0]['status'] == 200

    def test_spaced_payloads_reach_the_detection_rules(self, fixture_path):
        """Parsing is only half of it — the rules must actually fire on them."""
        from analyzer.rule_engine import run_all_rules
        events = parse_web_log(fixture_path('web_spaced_payloads.log'))
        threats = run_all_rules(events, 'web')
        assert any(t['threat_type'] == 'SQL Injection Attempt' for t in threats)
        sqli = [t for t in threats if t['threat_type'] == 'SQL Injection Attempt'][0]
        assert sqli['count'] == 4

    def test_status_and_size_still_parse_correctly(self, fixture_path):
        """A lazy path match must not swallow the fields that follow it."""
        events = parse_web_log(fixture_path('web_spaced_payloads.log'))
        assert [e['status'] for e in events] == [500, 500, 500, 500, 200, 200]
        assert events[-1]['size'] == 1043


class TestAutoDetection:
    def test_detects_auth_log(self, fixture_path):
        events, log_type = auto_parse(fixture_path('auth_sample.log'))
        assert log_type == 'auth'
        assert len(events) == 5

    def test_detects_web_log(self, fixture_path):
        events, log_type = auto_parse(fixture_path('web_sample.log'))
        assert log_type == 'web'
        assert len(events) == 3

    def test_detects_csv_by_extension(self, tmp_path):
        csv = tmp_path / 'data.csv'
        csv.write_text(
            'timestamp,source_ip,username,event_type,status,label,detail\n'
            '2025-01-10 03:00:00,198.51.100.99,root,Failed password,failure,brute_force,x\n'
        )
        events, log_type = auto_parse(str(csv))
        assert log_type == 'auth'
        assert len(events) == 1
        assert events[0]['label'] == 'brute_force'
        assert events[0]['event'] == 'failed_login'
