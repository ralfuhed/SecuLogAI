"""
rule_engine.py — Signature-based (rule-based) threat detection.

Like airport security rules: explicit, transparent conditions.
  "Same IP fails login >5 times in 10 min → Brute Force."
  "URL contains 'UNION SELECT' → SQL Injection."

Each detector returns a list of threat dicts:
  { threat_type, severity, ip, evidence, timestamp, count }

Severity scale: LOW → MEDIUM → HIGH → CRITICAL
"""

from collections import defaultdict
from datetime import timedelta
import re

# ── Tunable thresholds ───────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD  = 5    # failed logins within the window to trigger alert
BRUTE_FORCE_WINDOW_MIN = 10   # sliding window size in minutes
CREDENTIAL_STUFF_USERS = 4    # distinct usernames from one IP = stuffing
SCAN_404_THRESHOLD     = 20   # 404s from one IP = scanner

# ── Attack signatures ────────────────────────────────────────────────────────

# SQL Injection: attacker embeds SQL commands in URLs to manipulate the database
# e.g., /login?user=admin'-- bypasses the password check
_SQLI = re.compile(
    r"('|--|;|%27|%3B|%2D%2D|"
    r"\bunion\b|\bselect\b|\binsert\b|\bdelete\b|\bdrop\b|\btruncate\b|"
    r"\bexec\b|\bexecute\b|\bxp_|\bor\s+1\s*=\s*1|\band\s+1\s*=\s*1|"
    r"sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
    re.IGNORECASE
)

# Directory Traversal: ../ sequences to escape the web root and read system files
# e.g., /download?file=../../etc/passwd
_TRAVERSAL = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./|/etc/passwd|/proc/self)",
    re.IGNORECASE
)

# XSS: injects JavaScript into pages to steal cookies from other users
# e.g., /search?q=<script>alert(document.cookie)</script>
_XSS = re.compile(
    r"(<script|%3cscript|javascript:|onerror\s*=|onload\s*=|"
    r"alert\s*\(|document\.cookie|eval\s*\(|base64_decode)",
    re.IGNORECASE
)

# Command Injection: passes shell commands through web inputs
# e.g., /ping?host=8.8.8.8; rm -rf /
_CMDI = re.compile(
    r"(\||;|\$\(|`|&&|/bin/sh|/bin/bash|cmd\.exe|powershell)",
    re.IGNORECASE
)


def _threat(threat_type, severity, ip, evidence, timestamp, count=1):
    """Build a standardised threat dict."""
    return {'threat_type': threat_type, 'severity': severity, 'ip': ip,
            'evidence': evidence, 'timestamp': timestamp, 'count': count}


# ── Auth rules ───────────────────────────────────────────────────────────────

def detect_brute_force(events):
    """
    Flag IPs with many failed logins in a short window.
    Uses a sliding window: for each failure, counts how many follow within
    BRUTE_FORCE_WINDOW_MIN minutes. If >= BRUTE_FORCE_THRESHOLD → alert.
    """
    threats = []
    by_ip   = defaultdict(list)

    for e in events:
        if e.get('event') in ('failed_login', 'invalid_user'):
            by_ip[e['ip']].append(e['timestamp'])

    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MIN)
    for ip, times in by_ip.items():
        times.sort()
        for i, start in enumerate(times):
            burst = [t for t in times[i:] if t - start <= window]
            if len(burst) >= BRUTE_FORCE_THRESHOLD:
                sev = 'CRITICAL' if len(burst) >= 50 else 'HIGH' if len(burst) >= 20 else 'MEDIUM'
                threats.append(_threat(
                    'Brute Force Attack', sev, ip,
                    f'{len(burst)} failed logins in {BRUTE_FORCE_WINDOW_MIN}-min window',
                    burst[0], len(burst)
                ))
                break   # one alert per IP
    return threats


def detect_credential_stuffing(events):
    """
    Flag IPs that try many different usernames.
    Normal users log in with one username. Stuffers use a different username
    each time (from leaked credential lists). >= CREDENTIAL_STUFF_USERS → alert.
    """
    threats  = []
    by_ip    = defaultdict(set)
    ts_by_ip = defaultdict(list)

    for e in events:
        if e.get('event') in ('failed_login', 'invalid_user'):
            by_ip[e['ip']].add(e.get('user', ''))
            ts_by_ip[e['ip']].append(e['timestamp'])

    for ip, users in by_ip.items():
        if len(users) >= CREDENTIAL_STUFF_USERS:
            sample = ', '.join(list(users)[:5]) + ('...' if len(users) > 5 else '')
            threats.append(_threat(
                'Credential Stuffing', 'HIGH', ip,
                f'{len(users)} distinct usernames tried: {sample}',
                min(ts_by_ip[ip]), len(users)
            ))
    return threats


# ── Web rules ────────────────────────────────────────────────────────────────

def detect_sql_injection(events):
    """Flag IPs whose request paths contain SQL keywords or special characters."""
    threats = []
    by_ip   = defaultdict(list)
    for e in events:
        if e.get('type') == 'web' and _SQLI.search(e.get('path', '')):
            by_ip[e['ip']].append(e)
    for ip, hits in by_ip.items():
        sev = 'CRITICAL' if len(hits) >= 10 else 'HIGH'
        threats.append(_threat('SQL Injection Attempt', sev, ip,
            f'{len(hits)} request(s). Example: {hits[0]["path"][:80]}',
            hits[0]['timestamp'], len(hits)))
    return threats


def detect_directory_traversal(events):
    """Flag IPs using ../ sequences to escape the web root."""
    threats = []
    by_ip   = defaultdict(list)
    for e in events:
        if e.get('type') == 'web' and _TRAVERSAL.search(e.get('path', '')):
            by_ip[e['ip']].append(e)
    for ip, hits in by_ip.items():
        threats.append(_threat('Directory Traversal', 'HIGH', ip,
            f'{len(hits)} attempt(s). Example: {hits[0]["path"][:80]}',
            hits[0]['timestamp'], len(hits)))
    return threats


def detect_xss(events):
    """Flag IPs injecting script tags or JS event handlers into URLs."""
    threats = []
    by_ip   = defaultdict(list)
    for e in events:
        if e.get('type') == 'web' and _XSS.search(e.get('path', '')):
            by_ip[e['ip']].append(e)
    for ip, hits in by_ip.items():
        threats.append(_threat('XSS Attempt', 'HIGH', ip,
            f'{len(hits)} request(s). Example: {hits[0]["path"][:80]}',
            hits[0]['timestamp'], len(hits)))
    return threats


def detect_command_injection(events):
    """Flag IPs embedding shell operators (|, ;, &&, backtick) in URLs."""
    threats = []
    by_ip   = defaultdict(list)
    for e in events:
        if e.get('type') == 'web' and _CMDI.search(e.get('path', '')):
            by_ip[e['ip']].append(e)
    for ip, hits in by_ip.items():
        threats.append(_threat('Command Injection Attempt', 'CRITICAL', ip,
            f'{len(hits)} attempt(s). Example: {hits[0]["path"][:80]}',
            hits[0]['timestamp'], len(hits)))
    return threats


def detect_scanner(events):
    """
    Flag automated web scanners.
    Tools like Nikto/gobuster hammer many paths quickly; most return 404.
    >= SCAN_404_THRESHOLD "Not Found" responses from one IP → alert.
    """
    threats = []
    by_ip   = defaultdict(list)
    for e in events:
        if e.get('type') == 'web' and e.get('status') == 404:
            by_ip[e['ip']].append(e)
    for ip, hits in by_ip.items():
        if len(hits) >= SCAN_404_THRESHOLD:
            sev = 'HIGH' if len(hits) >= 50 else 'MEDIUM'
            threats.append(_threat('Path Scanner Detected', sev, ip,
                f'{len(hits)} HTTP 404 responses -- automated scan suspected',
                hits[0]['timestamp'], len(hits)))
    return threats


# ── Master runner ────────────────────────────────────────────────────────────

def run_all_rules(events: list[dict], log_type: str) -> list[dict]:
    """Run all rules for the given log type. Returns threats sorted by severity."""
    threats = []
    if log_type == 'auth':
        threats += detect_brute_force(events)
        threats += detect_credential_stuffing(events)
    elif log_type == 'web':
        threats += detect_sql_injection(events)
        threats += detect_directory_traversal(events)
        threats += detect_xss(events)
        threats += detect_command_injection(events)
        threats += detect_scanner(events)

    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    threats.sort(key=lambda t: (sev_order.get(t['severity'], 4), t['timestamp']))
    return threats
