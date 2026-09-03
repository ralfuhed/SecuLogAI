"""
cli.py — Command-line interface for SecuLog AI.

Usage:
  python cli.py analyze <logfile> [--type auth|web]
  python cli.py generate

Examples:
  python cli.py generate
  python cli.py analyze data/sample_auth.log
  python cli.py analyze data/sample_access.log --type web
"""

import argparse
import sys
import os
from datetime import datetime

# Our own modules
from analyzer.log_parser       import auto_parse, parse_auth_log, parse_web_log, parse_windows_log
from analyzer.feature_extractor import extract_auth_features, extract_web_features
from analyzer.rule_engine      import run_all_rules
from analyzer.ml_detector      import detect_anomalies
from analyzer.enrichment       import enrich_threats

# ── Terminal colour codes (ANSI escape sequences) ─────────────────────────────
# These make the terminal output colour-coded without any extra library.
# \033[  = escape sequence start;  m = end;  \033[0m = reset to default
RED     = '\033[91m'
YELLOW  = '\033[93m'
CYAN    = '\033[96m'
GREEN   = '\033[92m'
BOLD    = '\033[1m'
RESET   = '\033[0m'
DIM     = '\033[2m'

SEV_COLOR = {
    'CRITICAL': RED,
    'HIGH':     YELLOW,
    'MEDIUM':   CYAN,
    'LOW':      GREEN,
}


def colorize(text: str, color: str) -> str:
    """Wrap text in an ANSI colour code (only on real terminals, not in pipes)."""
    if sys.stdout.isatty():   # only colour if output is a real terminal
        return f'{color}{text}{RESET}'
    return text


def print_header():
    print(colorize(BOLD + """
+------------------------------------------+
|         SecuLog AI  --  Log Analyzer     |
|   AI-powered Security Threat Detection   |
+------------------------------------------+
""" + RESET, BOLD))


def print_summary(events, threats, log_type, filepath):
    """Print a quick overview section."""
    unique_ips = len({e['ip'] for e in events})
    sev_counts = {}
    for t in threats:
        sev_counts[t['severity']] = sev_counts.get(t['severity'], 0) + 1

    print(colorize('-' * 50, DIM))
    print(f'  File      : {os.path.basename(filepath)}')
    print(f'  Log type  : {log_type.upper()}')
    print(f'  Events    : {len(events):,}')
    print(f'  Unique IPs: {unique_ips}')
    print(f'  Threats   : {len(threats)}', end='  ')

    # Inline severity breakdown  e.g.  [CRITICAL: 2  HIGH: 3]
    if threats:
        parts = [colorize(f'{sev}: {cnt}', SEV_COLOR.get(sev, ''))
                 for sev, cnt in sorted(sev_counts.items(),
                                        key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x[0],4))]
        print('[' + '  '.join(parts) + ']')
    else:
        print(colorize('[No threats found]', GREEN))
    print(colorize('-' * 50, DIM))


def print_threats(threats):
    """Print each threat with colour-coded severity."""
    if not threats:
        print(colorize('\n  ✓ No threats detected.\n', GREEN))
        return

    print(f'\n{BOLD}  Threats Detected:{RESET}\n')
    for i, t in enumerate(threats, 1):
        sev   = t['severity']
        color = SEV_COLOR.get(sev, '')
        ts    = t['timestamp'].strftime('%b %d %H:%M:%S') if isinstance(t['timestamp'], datetime) else str(t['timestamp'])

        print(f"  {colorize(f'[{sev}]', color)} {BOLD}{t['threat_type']}{RESET}")
        print(f"    IP        : {t['ip']}")
        if t.get('technique'):
            attck = f"{t['technique']} {t['technique_name']} ({t['tactic']})"
            if t.get('mapping_confidence') == 'partial':
                attck += colorize('  [partial fit]', DIM)
            print(f"    ATT&CK    : {attck}")
        if t.get('ioc_match'):
            print(f"    {colorize('THREAT INTEL', RED)}: source listed as "
                  f"{t['ioc_match']['category']}")
        print(f"    Evidence  : {t['evidence']}")
        print(f"    First seen: {ts}")
        if i < len(threats):
            print()   # blank line between threats


def cmd_analyze(args):
    """
    Main 'analyze' command.
    1. Parse the log file
    2. Extract numerical features per IP
    3. Run rule-based detection
    4. Run ML anomaly detection
    5. Merge and display results
    """
    filepath = args.logfile
    if not os.path.isfile(filepath):
        print(colorize(f'[ERROR] File not found: {filepath}', RED))
        sys.exit(1)

    print_header()
    print(f'\n  Analyzing: {filepath}\n')

    # ── Step 1: Parse ─────────────────────────────────────────────────────────
    print('  [1/4] Parsing log file...')
    if args.type == 'auth':
        events, log_type = parse_auth_log(filepath), 'auth'
    elif args.type == 'web':
        events, log_type = parse_web_log(filepath), 'web'
    elif args.type == 'windows':
        events, log_type = parse_windows_log(filepath), 'windows'
    else:
        events, log_type = auto_parse(filepath)   # auto-detect
    print(f'        -> {len(events):,} events parsed ({log_type} log)')

    if not events:
        print(colorize('\n  [!] No parseable events found. Check the file format.\n', YELLOW))
        sys.exit(0)

    # ── Step 2: Feature extraction ────────────────────────────────────────────
    print('  [2/4] Extracting features per IP...')
    if log_type in ('auth', 'windows'):
        features_df = extract_auth_features(events)
    else:
        features_df = extract_web_features(events)
    print(f'        -> {len(features_df)} unique IPs profiled')

    # ── Step 3: Rule-based detection ─────────────────────────────────────────
    print('  [3/4] Running signature-based rules...')
    rule_threats = run_all_rules(events, log_type)
    print(f'        -> {len(rule_threats)} rule-based threat(s) found')

    # ── Step 4: ML anomaly detection ─────────────────────────────────────────
    print('  [4/4] Running ML anomaly detection (Isolation Forest)...')
    ml_threats = detect_anomalies(features_df, log_type)
    print(f'        -> {len(ml_threats)} ML anomaly/anomalies detected')

    # ── Merge results (de-duplicate IPs already caught by rules) ─────────────
    rule_ips   = {t['ip'] for t in rule_threats}
    new_ml     = [t for t in ml_threats if t['ip'] not in rule_ips]
    all_threats = enrich_threats(rule_threats + new_ml)

    # ── Output ────────────────────────────────────────────────────────────────
    print()
    print_summary(events, all_threats, log_type, filepath)
    print_threats(all_threats)

    print(colorize('\n  Tip: run  python run_web.py  for the interactive dashboard.\n', DIM))


def cmd_generate(_args):
    """Run the sample log generator."""
    print_header()
    print('  Generating sample log files...\n')
    import generate_sample_logs   # imports and runs the generator
    generate_sample_logs.gen_auth_log('data/sample_auth.log')
    generate_sample_logs.gen_web_log('data/sample_access.log')


# ── Argument parser setup ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='seculog',
        description='SecuLog AI — AI-powered security log analyzer'
    )
    sub = parser.add_subparsers(dest='command')

    # 'analyze' sub-command
    analyze_p = sub.add_parser('analyze', help='Analyze a log file for threats')
    analyze_p.add_argument('logfile', help='Path to the log file')
    analyze_p.add_argument('--type', choices=['auth', 'web', 'windows', 'auto'], default='auto',
                            help='Log type (default: auto-detect)')

    # 'generate' sub-command
    sub.add_parser('generate', help='Generate sample log files for demo')

    args = parser.parse_args()

    if args.command == 'analyze':
        cmd_analyze(args)
    elif args.command == 'generate':
        cmd_generate(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
