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


def _canonical(ip: str) -> str:
    """
    One spelling per address, so lookups compare addresses rather than text.

    2001:DB8::99 and 2001:db8:0:0:0:0:0:99 are the same host, and dual-stack
    servers log IPv4 clients as ::ffff:198.51.100.7, which an IPv4 indicator
    would otherwise never match. Anything that is not an address is returned
    unchanged, so it simply finds no match.
    """
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return ip
    mapped = getattr(addr, 'ipv4_mapped', None)
    return str(mapped or addr)


def load_iocs(path: str = None) -> dict:
    """
    Load indicators from a flat file.

    Format is one indicator per line, whitespace separated, '#' for comments.
    An indicator is an address or a CIDR range, as threat feeds publish both:

        198.51.100.77     spray-source   2026-08-14
        203.0.113.0/24    scanner-range  2026-09-01

    Returns {indicator: {'category': str, 'first_seen': str}}, where a range
    is keyed by its normalised network ('203.0.113.0/24') and also carries
    'range'. A missing file is not an error, enrichment is optional, and the
    tool must still analyse logs without an indicator list.
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
            entry = {
                'category':   parts[1] if len(parts) > 1 else 'unknown',
                'first_seen': parts[2] if len(parts) > 2 else '',
            }
            if '/' not in parts[0]:
                try:
                    ipaddress.ip_address(parts[0])
                except ValueError:
                    continue    # not an IP; skip rather than fail the whole load
                iocs[_canonical(parts[0])] = entry
                continue
            network = _parse_range(parts[0])
            if network is not None:
                iocs[str(network)] = {**entry, 'range': str(network)}
    return iocs


# A typo or a sloppy feed line such as 0.0.0.0/0 would otherwise mark every
# source as known-bad and escalate every alert in the log. Ranges broader than
# these are refused; real feeds list far narrower blocks.
_MIN_PREFIX = {4: 8, 6: 32}


def _parse_range(text: str):
    """A CIDR range as an ip_network, or None if malformed or implausibly wide."""
    try:
        network = ipaddress.ip_network(text, strict=False)   # 10.1.2.3/24 -> 10.1.2.0/24
    except ValueError:
        return None
    if network.prefixlen < _MIN_PREFIX[network.version]:
        return None
    return network


def _lookup(iocs: dict, networks: list, ip: str):
    """Exact address first, then the most specific listed range holding it."""
    canonical = _canonical(ip)
    if canonical in iocs:
        return iocs[canonical]
    try:
        addr = ipaddress.ip_address(canonical)
    except ValueError:
        return None
    holding = [n for n in networks if n.version == addr.version and addr in n]
    if not holding:
        return None
    return iocs[str(max(holding, key=lambda n: n.prefixlen))]


def enrich_threats(threats: list[dict], iocs: dict = None) -> list[dict]:
    """
    Annotate threats whose source IP appears in the indicator list.

    Adds 'ioc_match' and escalates severity one tier. Threats are copied
    rather than mutated so callers keep the raw detection output.
    """
    iocs = load_iocs() if iocs is None else iocs
    if not iocs:
        return threats

    networks = [n for n in (_parse_range(k) for k in iocs if '/' in k) if n is not None]

    enriched = []
    for threat in threats:
        hit = _lookup(iocs, networks, threat.get('ip', ''))
        if not hit:
            enriched.append(threat)
            continue

        annotated = dict(threat)
        annotated['ioc_match'] = hit
        annotated['severity'] = _ESCALATION.get(threat['severity'], threat['severity'])
        seen  = f", first seen {hit['first_seen']}" if hit['first_seen'] else ''
        where = f"in listed range {hit['range']}" if hit.get('range') else 'on indicator list'
        annotated['evidence'] = (
            f"{threat['evidence']} | Source {where} "
            f"as {hit['category']}{seen}"
        )
        enriched.append(annotated)
    return enriched
