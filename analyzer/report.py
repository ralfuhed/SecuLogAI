"""
report.py: Findings as a portable report, for the dashboard download and the
CLI's --format option.

The report is the analyst's hand-off: into a SIEM, a ticket or a script. Two
formats:

  JSON, the full record, one object per finding plus a summary.
  CSV, one row per finding, for spreadsheets and ticket imports.

Evidence quotes the analysed log, which is attacker-written. A CSV cell that
starts with = + - @ (or a tab / carriage return) is evaluated as a formula by
Excel, LibreOffice and Google Sheets, so a crafted request could run a formula
on the analyst's machine the moment they open the export (CSV injection).
Such cells are prefixed with a single quote, which the spreadsheet shows as
text.
"""

import csv
import io
import json
from datetime import datetime

REPORT_VERSION = 1

# Column order for CSV, and the fields each JSON finding carries.
FIELDS = [
    'severity', 'threat_type', 'ip', 'count', 'first_seen',
    'technique', 'technique_name', 'tactic', 'mapping_confidence',
    'source', 'ioc_category', 'ioc_range', 'evidence',
]

_FORMULA_START = ('=', '+', '-', '@', '\t', '\r')


def _finding(threat: dict) -> dict:
    timestamp = threat.get('timestamp', '')
    if isinstance(timestamp, datetime):
        timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
    ioc = threat.get('ioc_match') or {}
    return {
        'severity':           threat.get('severity', ''),
        'threat_type':        threat.get('threat_type', ''),
        'ip':                 threat.get('ip', ''),
        'count':              threat.get('count', 1),
        'first_seen':         timestamp,
        'technique':          threat.get('technique'),
        'technique_name':     threat.get('technique_name'),
        'tactic':             threat.get('tactic'),
        'mapping_confidence': threat.get('mapping_confidence'),
        'source':             threat.get('source', 'rule'),
        'ioc_category':       ioc.get('category'),
        'ioc_range':          ioc.get('range'),
        'evidence':           threat.get('evidence', ''),
    }


def build_report(threats: list[dict], *, filename: str, log_type: str,
                 total_events: int, unique_ips: int) -> dict:
    """A JSON-safe report of the findings from one analysis."""
    findings = [_finding(t) for t in threats]
    by_severity = {}
    for f in findings:
        by_severity[f['severity']] = by_severity.get(f['severity'], 0) + 1
    return {
        'report_version': REPORT_VERSION,
        'generator':      'SecuLog AI',
        'generated_at':   datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'source': {
            'filename':     filename,
            'log_type':     log_type,
            'total_events': total_events,
            'unique_ips':   unique_ips,
        },
        'summary': {
            'total_findings': len(findings),
            'by_severity':    by_severity,
        },
        'findings': findings,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def _csv_safe(value) -> str:
    text = '' if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def to_csv(report: dict) -> str:
    """One row per finding; every cell is safe to open in a spreadsheet."""
    out = io.StringIO()
    # CRLF, as RFC 4180 specifies. The writer quotes any field holding a
    # line-terminator character, so with '\n' alone a field containing a bare
    # '\r' (log text can) went out unquoted and split the row in two.
    writer = csv.writer(out, lineterminator='\r\n')
    writer.writerow(FIELDS)
    for finding in report['findings']:
        writer.writerow([_csv_safe(finding.get(field)) for field in FIELDS])
    return out.getvalue()
