"""
feature_extractor.py: Converts raw log events into numerical per-IP
"feature vectors" that the ML model can consume.

ML models only understand numbers, not sentences. This module counts
behaviours per IP (failures, speed, usernames tried, etc.) and puts
them in a pandas DataFrame (a spreadsheet-like table).
"""

from collections import defaultdict
from datetime import datetime
import re
import pandas as pd


def extract_auth_features(events: list[dict]) -> pd.DataFrame:
    """
    SSH auth logs → per-IP feature table.

    Key features (what each column means):
      failure_rate, 1.0 = every attempt failed (attacker); ~0 = normal user
      unique_users, many usernames from one IP = credential stuffing
      attempts_per_minute, very high = automated bot, not a human
      night_attempts, logins at 1 to 5 AM are unusual
    """
    if not events:
        return pd.DataFrame()

    # defaultdict auto-creates a fresh sub-dict for each new IP key
    ip_data = defaultdict(lambda: {
        'total': 0, 'failed': 0, 'success': 0,
        'users': set(), 'timestamps': [],
        'night': 0, 'invalid': 0,
    })

    for e in events:
        ip = e['ip']
        ts = e['timestamp']
        d  = ip_data[ip]

        d['total'] += 1
        d['timestamps'].append(ts)
        d['users'].add(e.get('user', ''))

        if e['event'] == 'failed_login':
            d['failed'] += 1
        elif e['event'] == 'successful_login':
            d['success'] += 1
        elif e['event'] == 'invalid_user':
            d['invalid'] += 1
            d['failed']  += 1   # invalid user = also a failed login

        if ts.hour < 6:         # midnight to 6 AM
            d['night'] += 1

    rows = []
    for ip, d in ip_data.items():
        times = sorted(d['timestamps'])
        # span = total minutes between first and last event for this IP
        span  = (times[-1] - times[0]).total_seconds() / 60.0 if len(times) > 1 else 0.0
        total = d['total']

        rows.append({
            'ip':                ip,
            'total_attempts':    total,
            'failed_attempts':   d['failed'],
            'success_attempts':  d['success'],
            'failure_rate':      d['failed'] / total if total else 0.0,
            'unique_users':      len(d['users']),
            'time_span_minutes': span,
            # If span=0 (only 1 event), use raw count as proxy for rate
            'attempts_per_minute': total / span if span > 0 else float(total),
            'night_attempts':    d['night'],
            'invalid_user_count': d['invalid'],
        })

    return pd.DataFrame(rows)


# Regex to flag URLs containing known attack patterns
_SUSPICIOUS = re.compile(
    r"(\.\./|select\s|union\s|insert\s|drop\s|exec\s|"
    r"script>|<script|etc/passwd|/proc/|cmd=|eval\(|base64_decode)",
    re.IGNORECASE
)


def extract_web_features(events: list[dict]) -> pd.DataFrame:
    """
    Web access logs → per-IP feature table.

    Key features:
      error_rate, high 4xx/5xx rate = probing / attacking
      unique_paths, many unique URLs = scanner crawling
      not_found_count, many 404s = automated directory brute-force
      suspicious_path_count, paths containing SQLi, XSS, traversal strings
    """
    if not events:
        return pd.DataFrame()

    ip_data = defaultdict(lambda: {
        'total': 0, 'errors': 0, 'paths': set(),
        'timestamps': [], 'posts': 0, 'not_found': 0,
        'srv_errors': 0, 'night': 0, 'suspicious': 0,
    })

    for e in events:
        ip     = e['ip']
        ts     = e['timestamp']
        status = e.get('status', 200)
        d      = ip_data[ip]

        d['total'] += 1
        d['timestamps'].append(ts)
        d['paths'].add(e.get('path', ''))

        if status >= 400:            d['errors']    += 1
        if status == 404:            d['not_found'] += 1   # "Not Found", scanner behaviour
        if status >= 500:            d['srv_errors']+= 1   # "Server Error", possible exploit
        if e.get('method') == 'POST':d['posts']     += 1
        if ts.hour < 6:              d['night']     += 1
        if _SUSPICIOUS.search(e.get('path', '')):
            d['suspicious'] += 1

    rows = []
    for ip, d in ip_data.items():
        times = sorted(d['timestamps'])
        span  = (times[-1] - times[0]).total_seconds() / 60.0 if len(times) > 1 else 0.0
        total = d['total']

        rows.append({
            'ip':                    ip,
            'total_requests':        total,
            'error_rate':            d['errors'] / total if total else 0.0,
            'unique_paths':          len(d['paths']),
            'requests_per_minute':   total / span if span > 0 else float(total),
            'post_ratio':            d['posts'] / total if total else 0.0,
            'not_found_count':       d['not_found'],
            'server_error_count':    d['srv_errors'],
            'night_requests':        d['night'],
            'suspicious_path_count': d['suspicious'],
        })

    return pd.DataFrame(rows)
