"""Allow `python -m secret_scanner`."""

import sys

from secret_scanner.cli.main import main

sys.exit(main())
