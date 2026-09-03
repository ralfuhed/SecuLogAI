"""
rule_engine.py: Signature-based (rule-based) threat detection.

Like airport security rules: explicit, transparent conditions.
  "Same IP fails login >5 times in 10 min → Brute Force."
  "URL contains 'UNION SELECT' → SQL Injection."

Each detector returns a list of threat dicts:
  { threat_type, severity, ip, evidence, timestamp, count }

Severity scale: LOW → MEDIUM → HIGH → CRITICAL
"""

from collections import defaultdict
from datetime import timedelta
from urllib.parse import unquote
import re

from analyzer.attack_mapping import technique_for

# ── Tunable thresholds ───────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD  = 5    # failed logins within the window to trigger alert
BRUTE_FORCE_WINDOW_MIN = 10   # sliding window size in minutes
CREDENTIAL_STUFF_USERS = 4    # distinct usernames from one IP = stuffing
SCAN_404_THRESHOLD     = 20   # 404s from one IP = scanner

# ── Windows tuning ───────────────────────────────────────────────────────────
# Account creation outside these hours is treated as worth a look. Adjust to
# match the environment: a 24/7 shop with follow-the-sun IT will want this
# widened, or the rule will produce noise rather than signal.
BUSINESS_HOURS_START = 7      # 07:00
BUSINESS_HOURS_END   = 19     # 19:00

# Accounts expected to hold admin-equivalent rights. Event 4672 on anything
# outside this set is flagged. This list is environment-specific by nature, # left near-empty on purpose so it fails loud rather than silently trusting
# names that happen to be in a default. Populate it before real use.
KNOWN_ADMIN_ACCOUNTS = {'administrator'}

# ── Attack signatures ────────────────────────────────────────────────────────
#
# Design rule for everything below: a single punctuation character is never
# enough to alert on.
#
# The first version of these patterns matched a bare apostrophe, a bare
# semicolon, a bare pipe and a bare double dash. Measured against ordinary
# traffic, 10 of 15 perfectly normal URLs fired an alert:
#
#   /search?q=O'Brien                    apostrophe in a surname
#   /products?ids=1;2;3                  semicolon-delimited list
#   /filter?tags=red|blue|green          pipe-delimited filter
#   /report?range=2024-01-01--2024-12-31 double dash in a date range
#   /docs/how-to-select-a-plan           the word "select" in a slug
#
# A rule that alerts on two thirds of normal traffic gets muted in a day, and
# a muted rule detects nothing. So each pattern now requires either a
# multi-token SQL construct, a metacharacter followed by an actual command, or
# a quote sitting in genuine SQL context.

def _decode(path: str) -> str:
    """
    Percent-decode twice before matching.

    Attackers encode payloads to slip past naive string matching, and double
    encoding (%2527 -> %27 -> ') is a standard evasion. Two passes is enough
    in practice and bounds the work per request.
    """
    out = path
    for _ in range(2):
        try:
            decoded = unquote(out)
        except Exception:
            break
        if decoded == out:
            break
        out = decoded
    return out


# SQL Injection: requires real SQL grammar, not stray punctuation.
# e.g. /login?user=admin'-- , /products?id=1 UNION SELECT ...
_SQLI = re.compile(
    r"("
    r"\bunion\s+(all\s+)?select\b"                  # UNION SELECT
    r"|\b(select)\b[\s\S]{0,60}?\bfrom\b"           # SELECT ... FROM
    r"|\binsert\s+into\b|\bdelete\s+from\b"
    r"|\bdrop\s+(table|database)\b|\btruncate\s+table\b"
    r"|\bupdate\b[\s\S]{0,40}?\bset\b"
    r"|\b(or|and)\b\s*['\"]?[\w.]+['\"]?\s*=\s*['\"]?[\w.]+['\"]?\s*(--|#|/\*|;|$)"
    r"|['\"]\s*(or|and)\b\s*['\"]?\d"               # ' OR 1  /  ' AND 1
    r"|['\"]\s*(--|#|/\*)"                          # quote immediately closing a comment
    r"|['\"]\s*;\s*\w"                              # quote then statement separator
    r"|\bsleep\s*\(\s*\d|\bbenchmark\s*\(|\bwaitfor\s+delay\b|\bpg_sleep\s*\("
    r"|\bxp_cmdshell\b|\binformation_schema\b|\bsysobjects\b"
    r"|\bload_file\s*\(|\binto\s+outfile\b"
    r")",
    re.IGNORECASE
)

# Directory Traversal: escape sequences aimed at the filesystem.
# e.g. /download?file=../../etc/passwd
_TRAVERSAL = re.compile(
    r"("
    r"\.\./|\.\.\\"                                  # ../ or ..\
    r"|%2e%2e[/\\%]|\.%2e[/\\]|%2e\.[/\\]"           # encoded variants
    r"|/etc/(passwd|shadow)\b|/proc/self\b"
    r"|\bboot\.ini\b|\bwin\.ini\b"
    r"|\\windows\\system32|/windows/system32"
    r")",
    re.IGNORECASE
)

# XSS: script delivery, not merely the word "alert".
# e.g. /search?q=<script>alert(document.cookie)</script>
_XSS = re.compile(
    r"("
    r"<\s*script\b|<\s*/\s*script\s*>"
    r"|<\s*(img|svg|iframe|body|video|audio|object|embed)\b[^>]{0,120}?\bon\w+\s*="
    r"|\bon(error|load|click|mouseover|focus|animationstart)\s*=\s*['\"]?[\w$.(]"
    r"|javascript:\s*[\w$.(]"
    r"|\bdocument\s*\.\s*(cookie|location|write)\b"
    r"|\bwindow\s*\.\s*location\b"
    r"|\beval\s*\(\s*['\"\w]|\batob\s*\(|\bbase64_decode\s*\("
    r"|\bfromCharCode\s*\("
    r")",
    re.IGNORECASE
)

# Command Injection: a shell metacharacter followed by something that is
# actually a command, or an unambiguous shell construct.
# e.g. /ping?host=8.8.8.8;cat /etc/passwd
_SHELL_COMMANDS = (
    r"(?:cat|ls|dir|rm|del|cp|mv|chmod|chown|wget|curl|nc|ncat|netcat|telnet|"
    r"bash|sh|zsh|ksh|python[23]?|perl|ruby|php|whoami|id|uname|hostname|"
    r"ifconfig|ipconfig|netstat|ps|kill|touch|echo|printf|env|export|"
    r"powershell|cmd|certutil|bitsadmin|nslookup|ping)"
)
_CMDI = re.compile(
    r"("
    rf"[;&|]{{1,2}}\s*{_SHELL_COMMANDS}\b"           # ; cat   |ls   && wget
    rf"|\|\s*{_SHELL_COMMANDS}\b"                    # piped into a command
    r"|\$\(\s*\w|`\s*\w+\s*`"                        # $(cmd) or `cmd`
    r"|\$\{IFS\}"                                    # space-evasion idiom
    r"|/bin/(ba|z|k)?sh\b|/usr/bin/\w+"
    r"|\bcmd\.exe\b|\bpowershell(\.exe)?\b"
    rf"|\bnewline\W|%0a\s*{_SHELL_COMMANDS}\b"       # newline injection
    r")",
    re.IGNORECASE
)


def _threat(threat_type, severity, ip, evidence, timestamp, count=1):
    """
    Build a standardised threat dict, tagged with its ATT&CK technique.

    Every rule funnels through here, so a detection cannot ship without a
    mapping, an unrecognised threat type gets the explicit 'unmapped' entry
    rather than silently carrying no technique at all.
    """
    mapping = technique_for(threat_type)
    return {'threat_type': threat_type, 'severity': severity, 'ip': ip,
            'evidence': evidence, 'timestamp': timestamp, 'count': count,
            'technique': mapping['technique'],
            'technique_name': mapping['technique_name'],
            'tactic': mapping['tactic'],
            'mapping_confidence': mapping['confidence']}


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
        if e.get('type') == 'web' and _SQLI.search(_decode(e.get('path', ''))):
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
        if e.get('type') == 'web' and _TRAVERSAL.search(_decode(e.get('path', ''))):
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
        if e.get('type') == 'web' and _XSS.search(_decode(e.get('path', ''))):
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
        if e.get('type') == 'web' and _CMDI.search(_decode(e.get('path', ''))):
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


# ── Windows rules ────────────────────────────────────────────────────────────

def detect_off_hours_account_creation(events):
    """
    Flag accounts created outside business hours (Event ID 4720).

    Creating an account is normal administration; creating one at 03:00 is the
    classic persistence move after a compromise, because the new account looks
    ordinary the next morning.
    """
    threats = []
    for e in events:
        if e.get('event') != 'account_created':
            continue
        hour = e['timestamp'].hour
        if hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END:
            threats.append(_threat(
                'Off-Hours Account Creation', 'HIGH', e.get('ip', 'local'),
                f'Account "{e.get("user", "?")}" created at '
                f'{e["timestamp"]:%H:%M} on {e.get("computer", "unknown host")} '
                f'by {e.get("subject_user") or "unknown"}',
                e['timestamp']
            ))
    return threats


def detect_unexpected_privilege_assignment(events):
    """
    Flag admin-equivalent rights granted to an account not on the known-admin
    list (Event ID 4672).

    4672 fires on every administrative logon, so on its own it is pure noise.
    It becomes signal only when filtered against an environment-specific
    allowlist, see KNOWN_ADMIN_ACCOUNTS.
    """
    threats = []
    seen = set()
    for e in events:
        if e.get('event') != 'special_privileges':
            continue
        user = (e.get('user') or '').lower()
        # Machine accounts end in $ and legitimately hold privileges.
        if not user or user in KNOWN_ADMIN_ACCOUNTS or user.endswith('$'):
            continue
        if user in seen:
            continue
        seen.add(user)
        threats.append(_threat(
            'Unexpected Privilege Assignment', 'HIGH', e.get('ip', 'local'),
            f'Special privileges assigned to "{e.get("user")}" on '
            f'{e.get("computer", "unknown host")}, which is not on the '
            f'known-admin list',
            e['timestamp']
        ))
    return threats


def detect_account_lockouts(events):
    """
    Flag account lockouts (Event ID 4740).

    A lockout is often the visible end of a brute-force attempt that the
    failed-logon threshold missed because it was spread out deliberately.
    """
    threats = []
    by_user = defaultdict(list)
    for e in events:
        if e.get('event') == 'account_lockout':
            by_user[e.get('user', '?')].append(e['timestamp'])

    for user, times in by_user.items():
        times.sort()
        sev = 'HIGH' if len(times) > 1 else 'MEDIUM'
        threats.append(_threat(
            'Account Lockout', sev, 'local',
            f'Account "{user}" locked out {len(times)} time(s)',
            times[0], len(times)
        ))
    return threats


# ── Master runner ────────────────────────────────────────────────────────────

def run_all_rules(events: list[dict], log_type: str) -> list[dict]:
    """Run all rules for the given log type. Returns threats sorted by severity."""
    threats = []
    if log_type == 'auth':
        threats += detect_brute_force(events)
        threats += detect_credential_stuffing(events)
    elif log_type == 'windows':
        # 4625 maps to 'failed_login', so the auth rules apply unchanged.
        threats += detect_brute_force(events)
        threats += detect_credential_stuffing(events)
        threats += detect_off_hours_account_creation(events)
        threats += detect_unexpected_privilege_assignment(events)
        threats += detect_account_lockouts(events)
    elif log_type == 'web':
        threats += detect_sql_injection(events)
        threats += detect_directory_traversal(events)
        threats += detect_xss(events)
        threats += detect_command_injection(events)
        threats += detect_scanner(events)

    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    threats.sort(key=lambda t: (sev_order.get(t['severity'], 4), t['timestamp']))
    return threats
