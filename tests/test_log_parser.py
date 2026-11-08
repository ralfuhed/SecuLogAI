"""Parser tests: correct extraction, and graceful handling of junk input.

A parser that silently drops lines is a false-negative generator, so these
tests assert on exact event counts, not just "it didn't crash".
"""

import subprocess
import sys

import pytest

from conftest import REPO_ROOT

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
        """Parsing is only half of it, the rules must actually fire on them."""
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


class TestIPv6Sources:
    """
    Both parsers matched IPv4 only, so any event from an IPv6 source was
    dropped without a word. Same false-negative class as the spaced-payload
    bug: the parser reports success while discarding events.
    """

    def test_parses_ipv6_web_request(self, tmp_path):
        log = tmp_path / 'v6.log'
        log.write_text(
            '2001:db8::1 - - [10/Jan/2025:08:00:01 +0000] '
            '"GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0"\n'
        )
        events = parse_web_log(str(log))
        assert len(events) == 1
        assert events[0]['ip'] == '2001:db8::1'

    def test_parses_ipv6_auth_failure(self, tmp_path):
        log = tmp_path / 'v6auth.log'
        log.write_text(
            'Jan 10 03:14:22 srv sshd[12]: Failed password for root '
            'from 2001:db8::1 port 22 ssh2\n'
        )
        events = parse_auth_log(str(log))
        assert len(events) == 1
        assert events[0]['ip'] == '2001:db8::1'
        assert events[0]['event'] == 'failed_login'

    def test_ipv4_still_parses(self, fixture_path):
        events = parse_web_log(fixture_path('web_sample.log'))
        assert events[0]['ip'] == '10.0.0.1'

    def test_ipv6_attacker_reaches_the_rules(self, tmp_path):
        from analyzer.rule_engine import run_all_rules
        log = tmp_path / 'v6brute.log'
        log.write_text('\n'.join(
            f'Jan 10 03:{m:02d}:00 srv sshd[12]: Failed password for root '
            f'from 2001:db8::99 port 22 ssh2' for m in range(6)
        ))
        events = parse_auth_log(str(log))
        threats = run_all_rules(events, 'auth')
        assert any(t['ip'] == '2001:db8::99' for t in threats)


class TestHostileLineShapes:
    """
    Every line is attacker-influenced, so parsing must stay linear in line
    length. The web pattern used to be cubic on a run of spaces (about 45
    seconds for 4 KB) and the auth patterns quadratic on one long word. Each
    case here took minutes to hours before and takes well under a second now;
    the 10 second limit is generous so a slow CI runner cannot make it flaky.
    """

    HEAD = '1.2.3.4 - - [10/Jan/2025:08:00:01 +0000] "GET'
    SIZE = 200_000

    def _parses_within(self, parser, path, seconds=10):
        """
        Parse in a child process with a hard limit. A regression back to
        super-linear matching then fails quickly instead of hanging CI.
        """
        code = f'from analyzer.log_parser import {parser}; {parser}({str(path)!r})'
        try:
            subprocess.run([sys.executable, '-c', code], cwd=REPO_ROOT,
                           check=True, timeout=seconds)
        except subprocess.TimeoutExpired:
            pytest.fail(f'{parser} took over {seconds}s on a hostile line')

    @pytest.mark.parametrize('line', [
        pytest.param(HEAD + ' ' * SIZE + 'a', id='run of spaces'),
        # Only quadratic, so it needs a bigger line to stand out: about a
        # minute before, a tenth of a second now.
        pytest.param(HEAD + ' a HTTP/' * (5 * SIZE // 8), id='fake HTTP/ repeated'),
    ])
    def test_web_parse_is_linear(self, tmp_path, line):
        log = tmp_path / 'hostile.log'
        log.write_text(line + '\n')
        self._parses_within('parse_web_log', log)

    def test_auth_parse_is_linear(self, tmp_path):
        log = tmp_path / 'hostile_auth.log'
        log.write_text('a' * self.SIZE + '\n')
        self._parses_within('parse_auth_log', log)

    def test_payload_after_a_fake_protocol_is_not_hidden(self, tmp_path):
        """
        The path used to end at the first " HTTP/", and everything after it
        was swallowed as the protocol version, invisible to every rule.
        """
        from analyzer.rule_engine import detect_sql_injection
        payload = "?id=1 UNION SELECT username,password FROM users WHERE id=1--"
        log = tmp_path / 'smuggled.log'
        log.write_text(
            f'{self.HEAD} /products HTTP/1.1{payload} HTTP/1.1" 500 0 "-" "sqlmap"\n'
        )
        events = parse_web_log(str(log))
        assert len(events) == 1
        assert payload in events[0]['path']
        assert detect_sql_injection(events)

    @pytest.mark.parametrize('tail, rule', [
        ("?id=1 UNION SELECT 1,2--", 'detect_sql_injection'),
        ("?u=admin' OR '1'='1", 'detect_sql_injection'),
        ("?q=<script>alert(1)</script>", 'detect_xss'),
        ("?f=../../etc/passwd", 'detect_directory_traversal'),
        ("?h=8.8.8.8;cat /etc/passwd", 'detect_command_injection'),
    ])
    def test_short_payload_after_a_fake_protocol_is_scanned(self, tmp_path, tail, rule):
        """
        Under 64 characters the payload still lands in the protocol field, not
        the path. The rules scan any protocol that is not a plain HTTP version.
        """
        from analyzer import rule_engine
        log = tmp_path / 'smuggled_short.log'
        log.write_text(f'{self.HEAD} /p HTTP/1.1{tail} HTTP/1.1" 200 1 "-" "x"\n')
        events = parse_web_log(str(log))
        assert len(events) == 1
        assert events[0]['path'] == '/p'
        threats = getattr(rule_engine, rule)(events)
        assert threats
        assert tail[:20] in threats[0]['evidence']

    @pytest.mark.parametrize('protocol', ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0', 'HTTP/2'])
    def test_plain_protocols_add_nothing_to_scan(self, tmp_path, protocol):
        from analyzer.rule_engine import _request_text, run_all_rules
        log = tmp_path / 'plain.log'
        log.write_text(f'{self.HEAD} /index.html {protocol}" 200 1 "-" "x"\n')
        events = parse_web_log(str(log))
        assert events[0]['protocol'] == protocol
        assert _request_text(events[0]) == '/index.html'
        assert run_all_rules(events, 'web') == []

    def test_empty_request_path_still_parses(self, tmp_path):
        log = tmp_path / 'empty_path.log'
        log.write_text(f'{self.HEAD}  HTTP/1.1" 400 0 "-" "-"\n')
        events = parse_web_log(str(log))
        assert len(events) == 1
        assert events[0]['path'] == ''
