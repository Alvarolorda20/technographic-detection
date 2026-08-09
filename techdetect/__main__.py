"""Allow `python -m techdetect`."""

import sys

from techdetect.cli import main

if __name__ == "__main__":
    sys.exit(main())
