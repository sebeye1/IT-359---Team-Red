"""python3 -m webrecon [target] [options] works the same as python3 main.py."""

import sys

from webrecon import bootstrap

bootstrap.ensure_dependencies()

from webrecon.cli import main  # noqa: E402

sys.exit(main())
