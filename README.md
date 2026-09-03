# SecuLogAI

**A detection engine for SSH, web and Windows Security logs — signature rules
mapped to MITRE ATT&CK, with unsupervised anomaly detection alongside them.**

<div align="center">

[![CI](https://github.com/ralfuhed/SecuLogAI/actions/workflows/ci.yml/badge.svg)](https://github.com/ralfuhed/SecuLogAI/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v19.2-red.svg)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE)

[Detection Coverage](#detection-coverage) • [Log Sources](#log-sources) • [ATT&CK Mapping](#mitre-attck-coverage) • [Quick Start](#quick-start)

</div>

---

## Detection Coverage

Ten detections across three log sources. Every one carries its ATT&CK
technique through the CLI, dashboard and JSON export.

| Detection | Log source | Technique | Severity |
|---|---|---|---|
| Brute Force Attack | SSH, Windows | `T1110.001` | MEDIUM–CRITICAL |
| Credential Stuffing | SSH, Windows | `T1110` | HIGH |
| Off-Hours Account Creation | Windows | `T1136.001` | HIGH |
| Unexpected Privilege Assignment | Windows | `T1078` | HIGH |
| Account Lockout | Windows | `T1110` | MEDIUM–HIGH |
| SQL Injection | Web | `T1190` | HIGH–CRITICAL |
| Command Injection | Web | `T1190` | CRITICAL |
| Directory Traversal | Web | `T1190` | HIGH |
| Cross-Site Scripting | Web | `T1190` | HIGH |
| Wordlist / Path Scanning | Web | `T1595.003` | MEDIUM–HIGH |

Alongside the signature rules, an Isolation Forest flags per-IP behavioural
outliers that no rule anticipated. Those findings are explicitly **not**
ATT&CK-mapped, because a statistical outlier is not a named adversary
behaviour.

Detections are enriched against a local indicator list, and Sigma-format
equivalents of the core rules live in `rules/sigma/` so the logic is portable
to a real SIEM.

## What it is

A local analysis tool. You point it at a log file, it reconstructs what
happened, and it tells you which technique each finding corresponds to.

Given a Windows Security log, it reports the sequence rather than a pile of
isolated events:

```
[CRITICAL] Brute Force Attack             T1110.001   60 failed logons in 10-min window
[HIGH]     Credential Stuffing            T1110       10 distinct usernames tried
[HIGH]     Unexpected Privilege Assignment T1078      privileges -> "svc_backup" on DC01
[HIGH]     Off-Hours Account Creation     T1136.001   "sysadmin_svc" created 03:04
[MEDIUM]   Account Lockout                T1110       "mwilson" locked out
```

Spray, lockout, breach, escalation, persistence.

There is also a Flask dashboard for drilling into a result by IP, hour or
threat type — but the detection logic is the substance here, and it runs
identically from the CLI.

## Design notes

Three things this project takes a position on:

- **A rule is only half-finished until you know it stays quiet.** The test
  suite asserts benign traffic produces zero alerts, and every threshold rule
  is tested on both sides of its boundary.
- **Weak ATT&CK mappings are labelled `partial` with a reason.** Four of the
  ten are honest approximations, and the tool says so rather than presenting
  ten confident IDs. See [why](#why-some-mappings-say-partial).
- **The tool's own attack surface is documented**, including what has
  deliberately been left unhardened and why. See
  [Security Hardening Notes](#security-hardening-notes).

## Quick Start

### Prerequisites
- Python 3.11+
- pip

### Installation

```bash
# Clone the repo
git clone https://github.com/ralfuhed/SecuLogAI.git
cd SecuLogAI

# Install dependencies
pip install -r requirements.txt
```

### Usage

#### Option 1: Command-Line (Quick Analysis)

```bash
# Generate sample logs with attack scenarios
python generate_sample_logs.py

# Analyze SSH auth logs
python cli.py analyze data/sample_auth.log

# Analyze web server logs
python cli.py analyze data/sample_access.log --type web
```

#### Option 2: Web Dashboard (Interactive)

```bash
# Start the Flask server
python run_web.py

# Open http://localhost:5000 in your browser
```

Then:
1. Upload a log file or use the built-in samples
2. View the threat dashboard with charts and drill-down analysis
3. Export results as JSON

## How It Works

### 1. **Log Parsing**
Regex-based extraction converts raw logs into structured events (IP, timestamp, username, request path, etc.)

```
Input:  "Jan 10 03:14:22 srv sshd[12]: Failed password for root from 1.2.3.4 port 22 ssh2"
Output: {'ip': '1.2.3.4', 'user': 'root', 'event': 'failed_login', 'timestamp': ...}
```

### 2. **Feature Extraction**
Aggregates per-IP statistics for the ML model:
- Login failure rate
- Unique usernames attempted
- Requests per minute
- Night-time activity
- Suspicious path patterns
- Error rates
- ...and more

### 3. **Rule-Based Detection**
Explicit rules flag known attack signatures:

| Attack | Trigger |
|--------|---------|
| 🔓 Brute Force | ≥5 failed logins in 10-min window |
| 🔑 Credential Stuffing | ≥4 unique usernames from one IP |
| 💉 SQL Injection | SQLi keywords or special chars in URLs |
| 🚀 Directory Traversal | `../` sequences in request paths |
| 📜 XSS | `<script>`, `onerror=` in URLs |
| ⚙️ Command Injection | Shell operators (`\|`, `;`, `&&`, backtick) |
| 🤖 Web Scanner | ≥20 HTTP 404 responses from one IP |

### 4. **ML Anomaly Detection**
Isolation Forest identifies statistical outliers (no labeled data required):

```
Algorithm: Randomly partition feature space
Normal IPs:    Hard to isolate (many cuts needed) → low anomaly score
Outliers:      Easy to isolate (few cuts needed) → high anomaly score → flagged
```

### 5. **Results**
Combines rule-based and ML threats, de-duplicates IPs, outputs severity-ranked results.

## Project Structure

```
SecuLogAI/
├── analyzer/
│   ├── log_parser.py          # Parsers: SSH auth, web access, Windows XML, CSV
│   ├── feature_extractor.py   # Events -> per-IP behavioural feature vectors
│   ├── rule_engine.py         # Signature detection + tunable thresholds
│   ├── attack_mapping.py      # MITRE ATT&CK technique mapping, with confidence
│   ├── enrichment.py          # Offline threat-intel annotation
│   └── ml_detector.py         # Isolation Forest anomaly detection
├── rules/sigma/               # Sigma-format equivalents of the core rules
├── tests/                     # 150 tests: parsers, rules, security, pipeline
├── web/
│   ├── app.py                 # Flask routes & analysis pipeline
│   └── templates/             # Jinja2 + Tailwind + Chart.js
├── data/
│   ├── ioc_list.txt           # Local indicator list for enrichment
│   └── ssh_anomaly_dataset.csv # Labeled dataset (ground truth)
├── .github/workflows/ci.yml   # Tests on Python 3.11 and 3.12
├── cli.py                     # Command-line interface
├── run_web.py                 # Flask server entry point
└── generate_sample_logs.py    # Synthetic log generator (SSH, web, Windows)
```

Sample logs are generated rather than committed — run
`python generate_sample_logs.py` after cloning.

## Tech Stack

- **Detection:** Python 3.11+, standard library regex and `xml.etree` for parsing
- **ML:** scikit-learn (Isolation Forest), pandas, numpy
- **Interface:** Flask 3.0+, Jinja2, Tailwind CSS (CDN), Chart.js (CDN)
- **Testing:** pytest, GitHub Actions on Python 3.11 and 3.12
- **No external services.** Analysis is entirely local, including threat-intel
  enrichment — nothing about the logs you analyse leaves the machine.

## Threat Detection Example

```
$ python cli.py analyze data/sample_auth.log

  [1/4] Parsing log file...
        → 1,247 events parsed (auth log)
  [2/4] Extracting features per IP...
        → 42 unique IPs profiled
  [3/4] Running signature-based rules...
        → 7 rule-based threat(s) found
  [4/4] Running ML anomaly detection...
        → 3 ML anomaly/anomalies detected

  ──────────────────────────────────────
  File      : sample_auth.log
  Log type  : AUTH
  Events    : 1,247
  Unique IPs: 42
  Threats   : 10  [CRITICAL: 2  HIGH: 5  MEDIUM: 3]
  ──────────────────────────────────────

  Threats Detected:

  [CRITICAL] Brute Force Attack
    IP        : 192.168.1.105
    Evidence  : 47 failed logins in 10-min window
    First seen: Jan 10 03:14:22

  [HIGH] Credential Stuffing
    IP        : 10.0.0.42
    Evidence  : 12 distinct usernames tried: admin, root, postgres, ...
    First seen: Jan 10 04:22:15

  [HIGH] ML Anomaly Detected
    IP        : 172.16.5.9
    Evidence  : Anomaly score 0.87 — 23 failed logins; 8 unique usernames; 15.2 attempts/min
    First seen: Jan 10 05:33:41

  Tip: run  python run_web.py  for the interactive dashboard.
```

## Running in Docker

```bash
docker compose up --build
# then open http://localhost:5000
```

The container is deliberately constrained, because this is a tool that ingests
untrusted log data:

| Setting | Reason |
|---|---|
| Runs as an unprivileged `seculog` user | A parser bug should not become a container escape |
| `read_only: true` root filesystem | Only `data/results` (bind mount) and `data/uploads` (tmpfs) are writable |
| `no-new-privileges: true` | Blocks privilege escalation via setuid binaries |
| Port published to `127.0.0.1` only | The dashboard has no authentication; binding `0.0.0.0` would expose every analysed log to the network |
| gunicorn, not the Flask dev server | The dev server is single-threaded and explicitly not meant to face anything |

Binding `0.0.0.0` *inside* the container is correct — the container boundary is
what limits reach there, and compose controls what is actually published.

CI builds the image on every pull request and verifies it serves, runs as
non-root, and can execute the analysis code.

## Configuration

Tunable thresholds in `analyzer/rule_engine.py`:

```python
BRUTE_FORCE_THRESHOLD  = 5    # failed logins within window
BRUTE_FORCE_WINDOW_MIN = 10   # sliding window in minutes
CREDENTIAL_STUFF_USERS = 4    # distinct usernames = stuffing
SCAN_404_THRESHOLD     = 20   # 404s from one IP = scanner
```

And in `analyzer/ml_detector.py`:

```python
contamination=0.1  # assume ~10% of IPs are outliers
```

## Log Sources

| Source | Format | Parser |
|---|---|---|
| Linux SSH auth | syslog (`/var/log/auth.log`) | `parse_auth_log` |
| Apache / Nginx access | combined log format | `parse_web_log` |
| **Windows Security** | **XML export (`wevtutil qe Security /f:xml`)** | **`parse_windows_log`** |
| SSH anomaly dataset | CSV with ground-truth labels | `parse_csv_log` |

### Windows Security Event Log

Most entry-level SOC work happens in Windows and Active Directory environments,
so this is the log source that matters most for realism. Five Event IDs are
parsed:

| Event ID | Meaning | Feeds |
|---|---|---|
| 4624 | An account was successfully logged on | baseline, post-breach activity |
| 4625 | An account failed to log on | brute force, password spray |
| 4672 | Special privileges assigned to new logon | privilege escalation |
| 4720 | A user account was created | persistence |
| 4740 | A user account was locked out | spray fallout |

4625 is mapped to the same internal `failed_login` event as an SSH failure, so
the existing brute-force and username-spread rules apply to Windows logs
without modification.

The bundled sample walks a full intrusion chain rather than isolated events —
password spray from an external host, a resulting lockout, a successful logon
on a service account, admin rights assigned to it, then a new account created
at 03:00 for persistence. Running it produces the whole story:

```
$ python cli.py analyze data/sample_security.xml

  [CRITICAL] Brute Force Attack
    ATT&CK    : T1110.001 Brute Force: Password Guessing (Credential Access)
    Evidence  : 60 failed logins in 10-min window

  [HIGH] Unexpected Privilege Assignment
    ATT&CK    : T1078 Valid Accounts (Privilege Escalation)
    Evidence  : Special privileges assigned to "svc_backup" on DC01.corp.local

  [HIGH] Off-Hours Account Creation
    ATT&CK    : T1136.001 Create Account: Local Account (Persistence)
    Evidence  : Account "sysadmin_svc" created at 03:04 by svc_backup
```

**Tuning required before real use.** `KNOWN_ADMIN_ACCOUNTS` in
`analyzer/rule_engine.py` is deliberately near-empty. Event 4672 fires on every
administrative logon, so without an environment-specific allowlist the rule
alerts constantly, gets muted, and then detects nothing. Same for
`BUSINESS_HOURS_START` / `BUSINESS_HOURS_END` in a follow-the-sun IT team.

## MITRE ATT&CK Coverage

Every detection is tagged with its ATT&CK technique, and the tag travels with
the alert through the CLI, the dashboard and the JSON export — not just the
README. Mappings were checked against attack.mitre.org (Enterprise **v19.2**);
three of the first-draft guesses were wrong and are corrected here.

| Detection | Technique | Name | Tactic | Fit |
|---|---|---|---|---|
| Brute Force Attack | `T1110.001` | Brute Force: Password Guessing | Credential Access | confirmed |
| Credential Stuffing | `T1110` | Brute Force | Credential Access | partial |
| SQL Injection Attempt | `T1190` | Exploit Public-Facing Application | Initial Access | confirmed |
| Directory Traversal | `T1190` | Exploit Public-Facing Application | Initial Access | confirmed |
| XSS Attempt | `T1190` | Exploit Public-Facing Application | Initial Access | partial |
| Command Injection Attempt | `T1190` | Exploit Public-Facing Application | Initial Access | partial |
| Path Scanner Detected | `T1595.003` | Active Scanning: Wordlist Scanning | Reconnaissance | confirmed |
| Off-Hours Account Creation | `T1136.001` | Create Account: Local Account | Persistence | confirmed |
| Unexpected Privilege Assignment | `T1078` | Valid Accounts | Privilege Escalation | confirmed |
| Account Lockout | `T1110` | Brute Force | Credential Access | partial |

### Why some mappings say "partial"

Four of these are honest approximations rather than clean matches, and the
tool labels them as such instead of presenting seven confident IDs:

- **Credential Stuffing → parent `T1110`.** An auth log never contains the
  password, so many distinct usernames from one IP cannot be distinguished
  from password spraying (`T1110.003`) or plain user enumeration. Claiming
  `T1110.004` would assert something the log does not show.
- **XSS → `T1190`.** ATT&CK Enterprise has no XSS technique. `T1189` Drive-by
  Compromise is the only page that mentions cross-site scripting, and only for
  stored XSS serving visitors. A reflected probe in an access log is an
  exploitation attempt, so `T1190` is the closest true statement.
- **Command Injection → `T1190`.** A web log proves the payload was *sent*,
  never that it *ran*. Mapping to `T1059` would claim Execution occurred.
- **Four detections share `T1190`.** That is a real property of the framework,
  not lazy mapping: ATT&CK is deliberately coarse about web exploitation.

ML anomalies are explicitly **unmapped**. A statistical outlier is not a named
adversary behaviour, and inventing a technique for it would be the dishonest
kind of coverage.

### Sigma rules

`rules/sigma/` carries Sigma-format equivalents of the core detections, so the
logic is portable to a real SIEM rather than locked inside this codebase. The
Python engine stays authoritative; a test asserts the two never drift to
different technique IDs.

## Threat Intelligence Enrichment

A detection says what happened; enrichment says whether it matters. Detections
whose source IP appears in `data/ioc_list.txt` are annotated with the indicator
category and promoted one severity tier:

```
  [CRITICAL] Brute Force Attack
    IP          : 198.51.100.99
    ATT&CK      : T1110.001 Brute Force: Password Guessing (Credential Access)
    THREAT INTEL: source listed as ssh-brute-source
    Evidence    : 150 failed logins in 10-min window | Source on indicator
                  list as ssh-brute-source, first seen 2026-08-14
```

The same run leaves an attacker who is *not* on the list at its original
severity, so the escalation carries information rather than flattening
everything to CRITICAL.

Indicator file format — one per line, `#` for comments:

```
198.51.100.99   ssh-brute-source   2026-08-14
```

**Lookups are offline by design.** No network calls happen during analysis.
Querying a threat-intel API mid-incident leaks which indicators you are
investigating to a third party, and breaks entirely on an isolated analysis
host. A missing indicator file is not an error — enrichment is optional and
analysis proceeds without it.

The bundled list is illustrative, matching the sample logs so the path is
visible on a fresh clone. It is not real threat intelligence; replace it with
indicators from your own feeds.

### GeoIP: not implemented

Geolocation would slot in at the same point in the pipeline as the indicator
lookup, in `analyzer/enrichment.py`. It is deliberately absent rather than
stubbed: doing it properly needs a MaxMind GeoLite2 database, which requires
an account and a license key, and shipping a fake lookup that returns
plausible-looking countries would be worse than shipping nothing.

## Security Hardening Notes

A tool that reads hostile input should be honest about its own attack surface.
This section documents what has been hardened and, just as importantly, what
has deliberately been left out of scope.

### Hardened

| Issue | Fix |
|---|---|
| Flask `secret_key` was a hardcoded literal in source | Read from `SECULOG_SECRET_KEY`, falling back to a random key generated at startup |
| `app.run(debug=True)` — Werkzeug's debugger is an interactive Python console on any traceback, i.e. RCE for anyone who can reach the port | Off by default; opt in with `SECULOG_DEBUG=1` |
| Uploaded filename used directly in a path, allowing `../../` traversal outside the upload folder | `werkzeug.utils.secure_filename` plus an extension allowlist (`.log`, `.txt`, `.csv`) |
| No upload size limit | `MAX_CONTENT_LENGTH` capped at 50 MB, with a 413 handler |
| An unparseable upload raised `KeyError` and returned a 500 with a stack trace | Errors are surfaced on the upload page instead |

Configuration lives in environment variables — see `.env.example`. The server
binds to `127.0.0.1` by default.

### Deliberately out of scope

**The dashboard has no authentication.** It is designed as a local analysis
tool: you run it on your own machine, point it at your own logs, and read the
results. Adding login screens to a single-user localhost tool would be
security theatre.

The consequence is real, though, so it is stated plainly rather than left for
someone to discover: **do not bind this to `0.0.0.0` or expose it to a
network.** Anyone who can reach the port can read every analysed log. If you
need multi-user access, put an authenticating reverse proxy in front of it —
don't rely on the app.

Analysis results are written unencrypted to `data/results/` as JSON. Log data
is sensitive; treat that directory the way you would treat the logs themselves.

## Accuracy & Ground Truth

If analyzing a labeled CSV dataset (like `ssh_anomaly_dataset.csv`), the web dashboard displays:
- **Detection rate** — % of actual attacks found
- **Ground truth labels** — compare predictions vs. reality
- **Per-IP accuracy** — see which attack types you're catching

## Roadmap

Done:

- [x] Windows Security Event Log (XML) support
- [x] MITRE ATT&CK technique mapping, verified against v19.2
- [x] Sigma rule equivalents for the core detections
- [x] Offline threat-intel enrichment against a local indicator list
- [x] Test suite and CI on Python 3.11 / 3.12

Next:

- [ ] GeoIP enrichment — needs a MaxMind GeoLite2 database; see
      [why it is absent rather than stubbed](#geoip-not-implemented)
- [ ] Sysmon Event ID 1 (process creation) for post-compromise execution
- [ ] Real-time log tailing with WebSocket updates
- [ ] Grafana / OpenSearch export so findings can leave the tool

## Contributing

Pull requests welcome! Areas for contribution:
- Additional log format parsers
- ML model improvements (Random Forest, Isolation Forest tuning)
- More attack signatures
- Frontend enhancements

## License

MIT — See LICENSE file

## About

Built as a portfolio project for **MS Cybersecurity & Trusted Systems** at Purdue University.

---

<div align="center">

Made with ❤️ for security engineers and sysadmins

[Report Bug](https://github.com/ralfuhed/SecuLogAI/issues) • [Request Feature](https://github.com/ralfuhed/SecuLogAI/issues)

</div>
