"""
attack_mapping.py — Maps each detection to MITRE ATT&CK.

Every mapping here was checked against attack.mitre.org (ATT&CK Enterprise
v19.2) rather than assumed. Three of the original guesses were wrong and are
corrected below; the reasoning is kept inline because a technique ID with no
justification is just a plausible-looking string.

Each entry carries a `confidence`:

  confirmed — ATT&CK describes this behaviour directly.
  partial   — the technique is the closest available fit, but the framework
              does not cleanly cover this detection, or the log cannot prove
              what the technique asserts. The `note` says why.

Labelling the weak mappings honestly is the point. A coverage table where
everything is 'confirmed' is a table nobody checked.
"""

UNMAPPED = {
    'technique': None,
    'technique_name': None,
    'tactic': None,
    'confidence': 'unmapped',
    'note': 'Statistical outlier, not a named adversary behaviour.',
}

ATTACK_TECHNIQUES = {
    'Brute Force Attack': {
        'technique': 'T1110.001',
        'technique_name': 'Brute Force: Password Guessing',
        'tactic': 'Credential Access',
        'confidence': 'confirmed',
        'note': '',
    },
    'Credential Stuffing': {
        # Mapped to the PARENT technique on purpose. An auth log never contains
        # the password, so many distinct usernames from one IP cannot be told
        # apart from password spraying (T1110.003) or plain user enumeration.
        # Claiming T1110.004 would assert knowledge the log does not contain.
        'technique': 'T1110',
        'technique_name': 'Brute Force',
        'tactic': 'Credential Access',
        'confidence': 'partial',
        'note': 'Auth logs cannot distinguish stuffing from password spraying '
                '(T1110.003), so the parent technique is used.',
    },
    'SQL Injection Attempt': {
        'technique': 'T1190',
        'technique_name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
        'confidence': 'confirmed',
        'note': '',
    },
    'Directory Traversal': {
        # Corrected from T1083 File and Directory Discovery, which is a
        # Discovery-tactic technique describing host-local enumeration by an
        # adversary already on the machine. A traversal string in an HTTP
        # request is a remote exploit attempt against an internet-facing app.
        'technique': 'T1190',
        'technique_name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
        'confidence': 'confirmed',
        'note': '',
    },
    'XSS Attempt': {
        # Corrected from T1059.007 JavaScript, which is an Execution technique
        # about running JS on a system, and whose description never mentions
        # XSS. ATT&CK Enterprise has no XSS technique at all: T1189 Drive-by
        # Compromise is the only page that says "cross-site scripting", and
        # only for stored XSS used to serve visitors.
        'technique': 'T1190',
        'technique_name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
        'confidence': 'partial',
        'note': 'ATT&CK Enterprise has no XSS technique. Reflected probes are '
                'exploitation attempts (T1190); stored XSS serving visitors '
                'would be T1189 Drive-by Compromise.',
    },
    'Command Injection Attempt': {
        # An access log shows the payload was sent, never that it ran. Mapping
        # to T1059 Command and Scripting Interpreter would claim Execution
        # occurred, which the evidence does not support.
        'technique': 'T1190',
        'technique_name': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access',
        'confidence': 'partial',
        'note': 'Web logs show the attempt, not execution. Successful command '
                'execution would additionally be T1059.004 Unix Shell.',
    },
    'Path Scanner Detected': {
        # Corrected from T1595.002 Vulnerability Scanning. This rule counts 404
        # volume, which is wordlist-driven directory enumeration (dirb,
        # gobuster) rather than vulnerability signature probing.
        'technique': 'T1595.003',
        'technique_name': 'Active Scanning: Wordlist Scanning',
        'tactic': 'Reconnaissance',
        'confidence': 'confirmed',
        'note': '',
    },
    # ── Windows Security Event Log ───────────────────────────────────────────
    'Off-Hours Account Creation': {
        # MITRE's own detection guidance for T1136.001 cites Event ID 4720.
        'technique': 'T1136.001',
        'technique_name': 'Create Account: Local Account',
        'tactic': 'Persistence',
        'confidence': 'confirmed',
        'note': '4720 logged on a domain controller is domain account creation, '
                'which would be T1136.002 instead.',
    },
    'Unexpected Privilege Assignment': {
        'technique': 'T1078',
        'technique_name': 'Valid Accounts',
        'tactic': 'Privilege Escalation',
        'confidence': 'confirmed',
        'note': 'Sub-techniques .002 Domain and .003 Local would be more precise, '
                'but 4672 alone does not say which.',
    },
    'Account Lockout': {
        # A lockout is the consequence of repeated failed authentication, so
        # the parent technique is the honest choice — 4740 says an account
        # locked, not which guessing strategy caused it.
        'technique': 'T1110',
        'technique_name': 'Brute Force',
        'tactic': 'Credential Access',
        'confidence': 'partial',
        'note': '4740 records the lockout, not the attempts behind it. Lockouts '
                'also occur benignly from stale cached credentials.',
    },
    'ML Anomaly Detected': dict(UNMAPPED),
}


def technique_for(threat_type: str) -> dict:
    """Return the ATT&CK mapping for a threat type, or the unmapped default."""
    return ATTACK_TECHNIQUES.get(threat_type, UNMAPPED)


def coverage() -> list[dict]:
    """Every mapped technique, for the README coverage table and the dashboard."""
    return [
        {'threat_type': name, **mapping}
        for name, mapping in ATTACK_TECHNIQUES.items()
        if mapping['technique']
    ]
