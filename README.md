# WebRecon

WebRecon looks at a web application from the outside and reports security misconfigurations: missing headers, weak
cookies, certificate problems, exposed files, outdated libraries and more. It never submits forms and never tries to
exploit anything.

**Only scan systems you own or have written permission to test.**

## Quick start

You need Python 3.9 or newer. From this folder:

```
./run.sh                               # macOS / Linux: sets itself up on first run, then starts the walkthrough
run.bat                                # Windows

./run.sh https://yoursite.com --open   # scan a site and open the report
./run.sh --help                        # the short list of commands
```

Optional: `--ai` adds an AI-estimated CVSS score and MITRE ATT&CK techniques to each finding; see
[AI risk context](docs/USAGE.md#ai-risk-context-optional). Your API key is kept outside the project (`python3 main.py --ai-setup`), and a
pre-commit hook blocks any commit that contains something shaped like a key (`git config core.hooksPath .githooks`).

The first run creates a private `.venv` and installs what WebRecon needs. Reports are saved in `reports/`.
Every command is explained in [docs/USAGE.md](docs/USAGE.md).

## What's in the folder

```
main.py              the launcher: python3 main.py ...  (checks packages, then starts the CLI)
run.sh, run.bat      one-step launchers that set up .venv on first use
webrecon/            the program
  scanning/            collects data from a target (crawl, headers, cookies, TLS, probes)
  analysis/            turns that data into findings; one module per kind of check
  ai/                  optional AI-estimated CVSS and MITRE ATT&CK context (--ai)
  reporting/           HTML, JSON, CSV and Markdown output
  results/             compare scans, filter findings, remember earlier scans
  cli/                 the command line: options, workflow, console output
  interactive/         the walkthrough and the short menu
  lab/                 a deliberately vulnerable practice site (safe: 127.0.0.1 only)
tests/               one folder per package, plus integration tests against the practice lab
docs/                USAGE.md (every command) and ARCHITECTURE.md (how it works, how to extend it)
scripts/, .githooks/ the secret scanner and the pre-commit hook that keeps API keys out of git
samples/             example reports
```

## For developers

```
pytest -q                 run the tests (about 10 seconds; no outside network)
pip install -e ".[dev]"   optional: gives you a `webrecon` command and pytest
python3 -m webrecon.lab   run the practice site by hand
```

Start with [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): it shows how a scan flows through the packages and how to add
a check.
