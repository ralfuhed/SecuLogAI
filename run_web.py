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

if __name__ == '__main__':
    print('\n  SecuLog AI - Web Dashboard')
    print('  Open:  http://localhost:5000')
    print('  Stop:  Ctrl + C\n')
    # debug=True reloads the server automatically when you save a .py file
    # Set debug=False before deploying to a real server
    app.run(debug=True, port=5000)
