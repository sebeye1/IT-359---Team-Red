"""
main.py - Start WebRecon:  python3 main.py [target] [options]

A thin launcher. It first makes sure the packages WebRecon needs are installed (switching to the project's
.venv, or offering to create one), then hands over to webrecon.cli. Run python3 main.py --help for usage.
"""

import sys

from webrecon import bootstrap

bootstrap.ensure_dependencies()  # before anything imports requests or beautifulsoup4

from webrecon.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
