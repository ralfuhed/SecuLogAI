"""
log_parser.py: Reads raw log files line-by-line and converts each line
into a structured Python dict so the rest of the program can work with it.

Supports:
  - SSH auth logs  (/var/log/auth.log), track login attempts
  - Web access logs (Apache/Nginx), track HTTP requests
  - SSH anomaly CSV (ssh_anomaly_dataset.csv), structured dataset with ground-truth labels
"""

import re
import csv
import xml.etree.ElementTree as ET
from datetime import datetime

# ── Auth log patterns ────────────────────────────────────────────────────────
# (?P<name>...) = named capture group, saves the matched text under that name.
# Example line: Jan 10 03:14:22 srv sshd[12]: Failed password for root from 1.2.3.4 port 22 ssh2

_AUTH_FAILED = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+sshd\[\d+\]:\s+'
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+'
)
_AUTH_ACCEPTED = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+sshd\[\d+\]:\s+'
    r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+'
)
_AUTH_INVALID = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+sshd\[\d+\]:\s+'
    r'Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)'
)

# ── Web log pattern ──────────────────────────────────────────────────────────
# Example: 1.2.3.4 - - [10/Jan/2025:03:14:22 +0000] "GET /path HTTP/1.1" 200 512 "-" "Mozilla"
#
# The path is matched lazily up to the " HTTP/" that closes the request line,
# NOT as \S+. Attack payloads routinely contain raw spaces and quotes, # "?id=1 UNION SELECT ..." or '"><img src=x onerror=alert(1)>', and a \S+
# path silently drops exactly those lines, turning the most interesting
# traffic in the log into a false negative.
_WEB_ACCESS = re.compile(
    r'(?P<ip>[0-9a-fA-F:.]+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>.*?)\s+HTTP/[^"]*"\s+'
    r'(?P<status>\d+)\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

MONTH_MAP = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,  'May': 5,  'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}


def _parse_auth_ts(month, day, time_str):
    """Convert auth log time parts → Python datetime. Assumes current year."""
    now = datetime.now()
    try:
        return datetime(now.year, MONTH_MAP.get(month, 1), int(day),
                        *[int(x) for x in time_str.split(':')])
    except Exception:
        return now


def _parse_web_ts(raw):
    """Convert web log timestamp string → Python datetime."""
    try:
        return datetime.strptime(raw.split()[0], '%d/%b/%Y:%H:%M:%S')
    except Exception:
        return datetime.now()


def parse_auth_log(filepath: str) -> list[dict]:
    """
    Parse SSH auth log → list of event dicts.
    Each dict has: type, event, ip, user, timestamp, raw.
    """
    events = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            m = _AUTH_FAILED.search(line)
            if m:
                events.append({'type': 'auth', 'event': 'failed_login',
                                'ip': m.group('ip'), 'user': m.group('user'),
                                'timestamp': _parse_auth_ts(m.group('month'), m.group('day'), m.group('time')),
                                'raw': line})
                continue

            m = _AUTH_ACCEPTED.search(line)
            if m:
                events.append({'type': 'auth', 'event': 'successful_login',
                                'ip': m.group('ip'), 'user': m.group('user'),
                                'timestamp': _parse_auth_ts(m.group('month'), m.group('day'), m.group('time')),
                                'raw': line})
                continue

            m = _AUTH_INVALID.search(line)
            if m:
                events.append({'type': 'auth', 'event': 'invalid_user',
                                'ip': m.group('ip'), 'user': m.group('user'),
                                'timestamp': _parse_auth_ts(m.group('month'), m.group('day'), m.group('time')),
                                'raw': line})
    return events


def parse_web_log(filepath: str) -> list[dict]:
    """
    Parse Apache/Nginx access log → list of event dicts.
    Each dict has: type, event, ip, method, path, status, size, agent, timestamp, raw.
    """
    events = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = _WEB_ACCESS.match(line)
            if m:
                events.append({
                    'type': 'web', 'event': 'http_request',
                    'ip': m.group('ip'), 'method': m.group('method'),
                    'path': m.group('path'), 'status': int(m.group('status')),
                    'size': int(m.group('size')) if m.group('size') != '-' else 0,
                    'agent': m.group('agent') or '',
                    'timestamp': _parse_web_ts(m.group('timestamp')),
                    'raw': line
                })
    return events


# ── CSV log parser ────────────────────────────────────────────────────────────
# Handles the structured SSH anomaly dataset (ssh_anomaly_dataset.csv).
# Columns: timestamp, source_ip, username, event_type, status, label, detail
#
# The 'label' column is ground truth, 'normal' or an attack category.
# We carry it through as 'label' in each event dict so the dashboard
# can display it and compute a detection-accuracy metric.

_CSV_EVENT_MAP = {
    'Failed password':       'failed_login',
    'Accepted password':     'successful_login',
    'Command executed':      'command_executed',
    'Disconnected':          'disconnected',
    'Connection error':      'connection_error',
    'Configuration Anomaly': 'config_anomaly',
}


def parse_csv_log(filepath: str) -> list[dict]:
    """
    Parse the SSH anomaly CSV dataset into event dicts.

    Each dict has: type, event, ip, user, timestamp, label, status, raw.
    'label' carries the ground-truth attack category from the dataset.
    """
    events = []
    with open(filepath, 'r', errors='ignore', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                # Truncate sub-second precision before parsing
                ts = datetime.strptime(row['timestamp'][:19], '%Y-%m-%d %H:%M:%S')
            except Exception:
                ts = datetime.now()

            event_type = row.get('event_type', '')
            event      = _CSV_EVENT_MAP.get(event_type, event_type.lower().replace(' ', '_'))

            # Reconstruct a human-readable raw line for the log viewer
            raw = (f"{row.get('timestamp','')[:19]}  {row.get('source_ip','')}  "
                   f"{row.get('username','')}  {event_type}  [{row.get('status','')}]")

            events.append({
                'type':      'auth',
                'event':     event,
                'ip':        row.get('source_ip', ''),
                'user':      row.get('username', ''),
                'timestamp': ts,
                'label':     row.get('label', 'normal'),  # ground-truth label
                'status':    row.get('status', ''),
                'raw':       raw,
            })
    return events


# ── Windows Security Event Log parser ─────────────────────────────────────────
# Reads the XML that `wevtutil qe Security /f:xml` produces, a stream of
# <Event> elements with no enclosing root, which is why the content is wrapped
# before parsing.
#
# Most entry-level SOC work happens in Windows and Active Directory
# environments, so these five Event IDs cover far more real ground than SSH:
#
#   4624  An account was successfully logged on
#   4625  An account failed to log on
#   4672  Special privileges assigned to new logon  (admin-equivalent rights)
#   4720  A user account was created
#   4740  A user account was locked out

_WIN_NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

WINDOWS_EVENT_IDS = {
    4624: 'successful_login',
    4625: 'failed_login',
    4672: 'special_privileges',
    4720: 'account_created',
    4740: 'account_lockout',
}

# Logon type 3 is network, 10 is RemoteInteractive (RDP). Both are remote and
# therefore the interesting ones for brute-force analysis.
WINDOWS_LOGON_TYPES = {
    2: 'Interactive', 3: 'Network', 4: 'Batch', 5: 'Service',
    7: 'Unlock', 8: 'NetworkCleartext', 9: 'NewCredentials',
    10: 'RemoteInteractive', 11: 'CachedInteractive',
}


def _parse_windows_ts(raw: str) -> datetime:
    """'2025-01-10T03:00:00.000000000Z' -> datetime, ignoring sub-second digits."""
    try:
        return datetime.strptime(raw[:19], '%Y-%m-%dT%H:%M:%S')
    except (ValueError, TypeError):
        return datetime.now()


def parse_windows_log(filepath: str) -> list[dict]:
    """
    Parse exported Windows Security Event Log XML into event dicts.

    Event dicts use the same shape as the SSH parser, 4625 becomes
    'failed_login', 4624 becomes 'successful_login', so the existing brute
    force and username-spread rules apply to Windows logs without change.
    """
    with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
        content = f.read()
    if not content.strip():
        return []

    # wevtutil emits a bare stream of <Event> elements with no document root.
    try:
        root = ET.fromstring(f'<Events>{content}</Events>')
    except ET.ParseError:
        return []

    events = []
    for node in root.findall('.//e:Event', _WIN_NS):
        system = node.find('e:System', _WIN_NS)
        if system is None:
            continue

        id_node = system.find('e:EventID', _WIN_NS)
        if id_node is None or not (id_node.text or '').strip().isdigit():
            continue

        event_id = int(id_node.text.strip())
        if event_id not in WINDOWS_EVENT_IDS:
            continue

        time_node = system.find('e:TimeCreated', _WIN_NS)
        timestamp = _parse_windows_ts(
            time_node.get('SystemTime', '') if time_node is not None else ''
        )
        computer_node = system.find('e:Computer', _WIN_NS)
        computer = computer_node.text if computer_node is not None else ''

        data = {
            d.get('Name'): (d.text or '')
            for d in node.findall('.//e:EventData/e:Data', _WIN_NS)
        }

        # '-' and '::1' both mean "not a meaningful remote source" in 4625.
        ip = data.get('IpAddress', '').strip()
        if ip in ('-', '::1', '127.0.0.1', ''):
            ip = 'local'

        raw_logon = data.get('LogonType', '').strip()
        logon_type = int(raw_logon) if raw_logon.isdigit() else None

        events.append({
            'type':        'windows',
            'event':       WINDOWS_EVENT_IDS[event_id],
            'event_id':    event_id,
            'ip':          ip,
            'user':        data.get('TargetUserName', '').strip(),
            'subject_user': data.get('SubjectUserName', '').strip(),
            'logon_type':  logon_type,
            'logon_type_name': WINDOWS_LOGON_TYPES.get(logon_type, ''),
            'computer':    computer,
            'timestamp':   timestamp,
            'raw': (f'EventID {event_id} ({WINDOWS_EVENT_IDS[event_id]}) '
                    f'user={data.get("TargetUserName", "")} src={ip} '
                    f'host={computer} time={timestamp:%Y-%m-%d %H:%M:%S}'),
        })
    return events


def auto_parse(filepath: str) -> tuple[list[dict], str]:
    """
    Detect log type and parse accordingly.
    Returns (events, log_type) where log_type is 'auth', 'web' or 'windows'.
    """
    # CSV dataset detected by extension or header line
    if filepath.lower().endswith('.csv'):
        return parse_csv_log(filepath), 'auth'

    with open(filepath, 'r', errors='ignore') as f:
        sample = ''.join(f.readline() for _ in range(5))

    # Check for CSV header row inside the file just in case
    if 'source_ip' in sample and 'event_type' in sample:
        return parse_csv_log(filepath), 'auth'

    # Windows Event Log XML carries its schema URL in the opening element
    if 'schemas.microsoft.com/win/2004/08/events/event' in sample or '<Event' in sample:
        return parse_windows_log(filepath), 'windows'

    if 'sshd[' in sample or 'Failed password' in sample:
        return parse_auth_log(filepath), 'auth'
    elif '"GET ' in sample or 'HTTP/' in sample:
        return parse_web_log(filepath), 'web'
    else:
        a, w = parse_auth_log(filepath), parse_web_log(filepath)
        return (a, 'auth') if len(a) >= len(w) else (w, 'web')
