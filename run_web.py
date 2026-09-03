"""
run_web.py — Start the SecuLog AI web server.

Run:  python run_web.py
Then open your browser to:  http://localhost:5000
"""

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


if __name__ == '__main__':
    config = server_config()

    print('\n  SecuLog AI - Web Dashboard')
    print(f"  Open:  http://{config['host']}:{config['port']}")
    print('  Stop:  Ctrl + C')
    if config['debug']:
        print('\n  [!] DEBUG MODE - the interactive debugger is exposed.')
        print('      Never use this on a network you do not control.')
    print()

    app.run(**config)
