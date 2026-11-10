"""
run_web.py: Start the SecuLog AI web server.

Run:  python run_web.py
Then open your browser to:  http://localhost:5000
"""

import ipaddress
import sys
import os

# Make sure the project root is on the Python path so Flask can find 'analyzer'
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web.app import app


def server_config() -> dict:
    """
    Resolve server settings from the environment.

    Werkzeug's debugger exposes an interactive Python console on any traceback,
    which is remote code execution for anyone who can reach the port. It stays
    off unless explicitly requested, and the bind address defaults to localhost
    because the dashboard has no authentication of its own.
    """
    return {
        'debug': os.environ.get('SECULOG_DEBUG') == '1',
        'host':  os.environ.get('SECULOG_HOST', '127.0.0.1'),
        'port':  int(os.environ.get('SECULOG_PORT', '5000')),
    }


def _is_loopback(host: str) -> bool:
    if host == 'localhost':
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False    # a hostname or 0.0.0.0-style wildcard: assume reachable


def check_config(config: dict) -> list[str]:
    """
    Refuse the one combination that is remote code execution on the network,
    and return warnings for the merely risky ones.

    Debug on a loopback address is a local developer's choice. Debug on any
    other address hands Werkzeug's Python console to everyone who can reach
    the port, so it is refused rather than warned about. A non-loopback bind
    without debug still exposes every analysed log, since the dashboard has no
    authentication; that is allowed, but said out loud.
    """
    if _is_loopback(config['host']):
        return []
    if config['debug']:
        raise ValueError(
            f"Refusing to start: SECULOG_DEBUG=1 with SECULOG_HOST={config['host']} "
            'would expose the interactive debugger, which runs arbitrary Python, '
            'to the network. Use debug only on 127.0.0.1.'
        )
    return [
        f"Listening on {config['host']}, not localhost. The dashboard has no "
        'authentication: anyone who can reach this port can read every analysed '
        'log. Put an authenticating reverse proxy in front of it.'
    ]


if __name__ == '__main__':
    config = server_config()
    try:
        warnings = check_config(config)
    except ValueError as refusal:
        print(f'\n  [!] {refusal}\n')
        sys.exit(1)

    print('\n  SecuLog AI - Web Dashboard')
    print(f"  Open:  http://{config['host']}:{config['port']}")
    print('  Stop:  Ctrl + C')
    if config['debug']:
        print('\n  [!] DEBUG MODE - the interactive debugger is exposed.')
        print('      Never use this on a network you do not control.')
    for warning in warnings:
        print(f'\n  [!] {warning}')
    print()

    app.run(**config)
