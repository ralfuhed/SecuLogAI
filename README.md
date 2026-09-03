# SecuLogAI

**Security threat detection in SSH and web logs using rule-based signatures and unsupervised machine learning anomaly detection.**

<div align="center">

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4+-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE)

[Features](#features) • [Quick Start](#quick-start) • [How It Works](#how-it-works) • [Tech Stack](#tech-stack)

</div>

---

## Overview

SecuLogAI is an end-to-end security log analyzer that detects threats using two complementary approaches:

1. **Signature-based rules** — explicit attack patterns (brute force, SQL injection, XSS, etc.)
2. **Unsupervised ML anomaly detection** — statistical outliers using Isolation Forest

No labeled training data needed. Zero external dependencies. Works with SSH auth logs, Apache/Nginx access logs, and structured CSV datasets.

## Features

| Feature | Benefit |
|---------|---------|
| 🔍 **Dual Detection** | Rule-based signatures + ML anomaly detection |
| ⚡ **Zero Training Data** | Unsupervised learning — detects outliers in your own logs |
| 🖥️ **Dual Interface** | CLI for quick analysis + interactive web dashboard |
| 📊 **Rich Visualizations** | Timeline charts, threat tables, IP anomaly scores |
| 🛡️ **8+ Attack Types** | Brute force, credential stuffing, SQLi, XSS, traversal, command injection, scanners, + anomalies |
| 📝 **Multiple Log Formats** | SSH/auth logs, Apache/Nginx, CSV datasets with ground-truth labels |
| 🎯 **Production-Ready** | JSON results export, ground-truth accuracy metrics, configurable thresholds |

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
│   ├── log_parser.py          # Regex parsers for auth, web, CSV logs
│   ├── feature_extractor.py   # Converts events → ML feature vectors
│   ├── rule_engine.py         # Signature-based threat detection
│   └── ml_detector.py         # Isolation Forest anomaly detection
├── web/
│   ├── app.py                 # Flask routes & analysis pipeline
│   └── templates/             # Jinja2 HTML + Tailwind CSS + Chart.js
├── data/
│   ├── sample_auth.log        # SSH log sample with attacks
│   ├── sample_access.log      # Apache/Nginx log sample with attacks
│   ├── ssh_anomaly_dataset.csv # Labeled dataset (ground truth)
│   └── results/               # Saved analysis JSON files
├── cli.py                     # Command-line interface
├── run_web.py                 # Flask development server entry point
├── generate_sample_logs.py    # Synthetic log generator
└── requirements.txt
```

## Tech Stack

- **Backend:** Python 3.11+, Flask 3.0+
- **ML:** scikit-learn (Isolation Forest), pandas, numpy
- **Frontend:** Jinja2 templates, Tailwind CSS (CDN), Chart.js (CDN)
- **No external services** — runs entirely local

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

## Accuracy & Ground Truth

If analyzing a labeled CSV dataset (like `ssh_anomaly_dataset.csv`), the web dashboard displays:
- **Detection rate** — % of actual attacks found
- **Ground truth labels** — compare predictions vs. reality
- **Per-IP accuracy** — see which attack types you're catching

## Roadmap

- [ ] GeoIP enrichment (flag logins from unexpected countries)
- [ ] Real-time log tailing with WebSocket updates
- [ ] PDF report generation
- [ ] Windows Event Log (XML) support
- [ ] Docker container for one-command deployment
- [ ] Grafana integration for dashboards

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
