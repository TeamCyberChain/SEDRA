"""SEDRA: a local, reproducible insider-risk and AI-transfer laboratory."""

import sys
if sys.version_info[:2] != (3, 12):
    raise RuntimeError('SEDRA requires Python 3.12 (pinned Unicode profile). On Windows run .venv\\Scripts\\python.exe; create it with py -3.12 -m venv .venv.')

__version__ = "0.14.0"
