"""`python -m edge.auth <command>`: staff account and API key administration (see edge/auth/cli.py)."""

import sys

from edge.auth.cli import main

if __name__ == "__main__":
    sys.exit(main())
