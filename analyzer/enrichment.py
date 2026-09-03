"""
enrichment.py: Adds threat-intelligence context to detections.

A detection says what happened. Enrichment says whether it matters. An alert
reading "22 failed logons from 203.0.113.4" is a statistic; the same alert
reading "22 failed logons from 203.0.113.4, listed as a known spray source
since 2026-08-14" is something an analyst can act on without pivoting to
another tool.

Indicators are read from a local file with no network calls at analysis time.
Reaching out to a threat-intel API while triaging an incident leaks which
indicators you are investigating, and fails when the analysis host is isolated, both good reasons for the lookup to stay offline.
"""

import ipaddress
import os

DEFAULT_IOC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'ioc_list.txt'
)

# A match promotes the finding one tier. A known-bad source turns a routine
# threshold alert into something worth waking someone for.
_ESCALATION = {'LOW': 'MEDIUM', 'MEDIUM': 'HIGH', 'HIGH': 'CRITICAL', 'CRITICAL': 'CRITICAL'}


def load_iocs(path: str = None) -> dict:
    """
    Load indicators from a flat file.

    Format is one indicator per line, whitespace separated, '#' for comments:

        198.51.100.77   spray-source   2026-08-14

    Returns {ip: {'category': str, 'first_seen': str}}. A missing file is not
    an error, enrichment is optional, and the tool must still analyse logs
    without an indicator list.
    """
    path = path or DEFAULT_IOC_PATH
    iocs = {}
    if not os.path.isfile(path):
        return iocs

    with open(path, 'r', errors='ignore', encoding='utf-8') as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            try:
                ipaddress.ip_address(parts[0])
            except ValueError:
                continue    # not an IP; skip rather than fail the whole load
            iocs[parts[0]] = {
                'category':   parts[1] if len(parts) > 1 else 'unknown',
                'first_seen': parts[2] if len(parts) > 2 else '',
            }
    return iocs


def enrich_threats(threats: list[dict], iocs: dict = None) -> list[dict]:
    """
    Annotate threats whose source IP appears in the indicator list.

    Adds 'ioc_match' and escalates severity one tier. Threats are copied
    rather than mutated so callers keep the raw detection output.
    """
    iocs = load_iocs() if iocs is None else iocs
    if not iocs:
        return threats

    enriched = []
    for threat in threats:
        hit = iocs.get(threat.get('ip'))
        if not hit:
            enriched.append(threat)
            continue

        annotated = dict(threat)
        annotated['ioc_match'] = hit
        annotated['severity'] = _ESCALATION.get(threat['severity'], threat['severity'])
        seen = f", first seen {hit['first_seen']}" if hit['first_seen'] else ''
        annotated['evidence'] = (
            f"{threat['evidence']} | Source on indicator list "
            f"as {hit['category']}{seen}"
        )
        enriched.append(annotated)
    return enriched
