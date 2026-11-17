# WebRecon

Scans a web application from the outside and reports security misconfigurations: missing headers, weak
cookies, TLS problems, exposed files, risky methods. It never tries to exploit anything.
**Only scan systems you own or have written permission to test.**

## Setup

The easiest way: run the launcher. The first run creates a virtual environment and installs what WebRecon needs;
every later run starts straight away. It needs Python 3.9 or newer.

```
./run.sh                 # macOS / Linux
run.bat                  # Windows
```

Anything you type after it is passed on, so `./run.sh https://example.com` scans a site. If you run `python main.py`
without setting anything up, it notices, uses the project's `.venv` if there is one, and otherwise offers to create it
and install the requirements for you. Prefer to do it by hand?

```
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

## Ways to start it

`python3 main.py`, `./run.sh`, and `python3 -m webrecon` all do the same thing. If you install it with
`pip install -e .` (inside a virtual environment), you also get a `webrecon` command, so `webrecon https://example.com`
works from anywhere.

## Start here

| You run | What happens |
| --- | --- |
| `python main.py` | A **walkthrough**: checks your setup, explains each part, and runs a live before/after demo against the practice lab |
| `python main.py https://example.com` | Scans straight away. The report and its JSON results are saved in `reports/` |
| `python main.py --compare` | Compares your last two scans of a site, no file names needed |
| `python main.py --list-scans` | Lists the scans saved in `reports/`, newest first |
| `python main.py --auto-lab` (options but no target) | A short **menu** asks what to scan and keeps the options you typed |
| `python main.py --quick` | The same menu with no options |
| `python main.py --help` | A short help. `--help-all` lists every option |

The menu offers: the practice lab (vulnerable), the practice lab (hardened), the full before/after demo with a
comparison, or your own target(s). Press Enter to accept a default, and Enter at the target question to cancel.
Menu scans open the report in your browser when they finish. Every run prints the equivalent command line, so you
can copy it next time. After a scan from the command line you also get a two-line "next steps" tip.

## Common tasks

```
python main.py example.com --open                        # bare host: tries HTTPS, then HTTP
python main.py https://a.example https://b.example       # several targets, plus a summary page
python main.py --targets-file sites.txt                   # one target per line, # comments allowed
python main.py https://app.example --cookie 'session=abc123'      # scan as a signed-in user
python main.py https://app.example --proxy http://127.0.0.1:8081  # through Burp or ZAP
python main.py <target> --ignore WR-091 --min-severity Low        # hide noise
python main.py https://example.com --plan                         # show what it would send, send nothing
python main.py <target> --baseline last --fail-on Low            # only what is NEW since your last scan
python main.py <target> --profile gentle                         # go easy on a fragile server
python main.py <target> --also csv,md                            # spreadsheet and Markdown copies
```

Reports are saved as `reports/<host>_<date-time>.html`, with the raw results beside them as `.json`, so scans never
overwrite each other (use `-o` to choose a name for a single target). Scanning several targets also writes
`reports/summary_<date-time>.html`.

### Profiles

`--profile gentle` is for fragile servers (5 pages, 1 second between requests, a longer timeout), `standard` is the
default (10 pages, 0.2 seconds), and `thorough` crawls up to 50 pages with a 15-minute limit. Any option you give
explicitly, such as `--max-pages 20`, overrides the profile.

### Comparing two scans

Every scan saves its results, so after you fix things and scan again:

```
python main.py --compare                       # your last two scans of the most recently scanned site
python main.py --compare old.json new.json     # or name the two files yourself
```

Lists what was **fixed**, **new**, **still open**, and any severity change, in the console and as an HTML report.
Exits with code 2 if the second scan has findings the first did not, so it can fail a CI job on regressions.

### Only what's new

Accept today's findings and hear only about regressions: `--baseline last` hides every finding that was already in your
previous scan of the same site, and `--fail-on` counts only the new ones, so a CI job fails only when something gets
worse. You can also give a specific saved result: `--baseline results.json`. The previous scan is looked up in `reports/`.
The saved JSON always records the complete set of findings, even the ones a baseline hid from the report, so you can
repeat `--baseline last` scan after scan and compare any two scans later.

### Hiding noise

`--ignore WR-091` hides a check you have accepted, and `--min-severity Medium` hides everything below Medium.
Hidden findings are left out of the console, report, JSON and `--fail-on`, and the report notes how many were
hidden. `--list-checks` prints every ID.

## Reports

Each report is a single self-contained HTML file: an overall risk rating, a "Since your previous scan: 18 fixed,
0 new, 3 still open" line whenever you have scanned the site before (no options needed), a "Fix these first" box, a key to what the
ratings mean, severity filters, and for every finding a description, evidence, recommendation and reference links
(CWE, MDN, OWASP). Add `--also csv,md` to write copies next to it: a CSV for spreadsheets and a Markdown
summary for pasting into a write-up. CSV cells that start with `=`, `+`, `-` or `@` get a leading quote so a scanned
site cannot plant a formula in your spreadsheet.

## Options

| Option | What it does |
| --- | --- |
| `--targets-file` | Read targets from a file |
| `-o`, `--output` | HTML report path (single target) |
| `--output-dir` | Folder for automatic report names, default `reports` |
| `--json` | Path for the JSON results (single target); by default they sit next to the report |
| `--also` | Also write `csv` and/or `md` next to every report, e.g. `--also csv,md` |
| `--open` | Open the report (or summary page) in your browser |
| `-h`, `--help-all` | Short help / every option |
| `-q`, `-v` | Quieter output / verbose logging with technical error details |
| `--profile` | `gentle`, `standard` or `thorough`: presets for the options below |
| `--max-pages` | Same-origin pages to crawl, default 10 |
| `--timeout`, `--delay` | Request timeout (default 10 s) and pause between requests (default 0.2 s) |
| `--max-time` | Stop a target's scan after this many seconds and keep the partial results, default 300 (0 = no limit) |
| `--retries` | Retries on 429 or 5xx, default 2 (honors `Retry-After`) |
| `--no-probes` | Skip the sensitive path probes |
| `--respect-robots` | Do not crawl paths robots.txt disallows |
| `--insecure` | Skip TLS certificate checks (self-signed certs) |
| `--cookie`, `--header`, `--user-agent`, `--proxy` | Authenticated scans and networking |
| `--ignore`, `--min-severity`, `--list-checks` | Filtering, see above |
| `--baseline` | `last`, or a saved result: hide findings already in it, so only new ones are reported |
| `--compare` | Compare two saved results, or with no files your last two scans of a site |
| `--list-scans` | List the scans saved in `reports/`, newest first |
| `--fail-on` | Exit with code 2 if any finding is at or above a severity |
| `--plan` | Show exactly what a scan would send, without sending anything |
| `-y` | Confirm authorization for non-local targets without the prompt |
| `--ai`, `--ai-provider`, `--ai-url`, `--ai-model`, `--ai-timeout` | AI-estimated CVSS and ATT&CK context (see AI risk context) |
| `--ai-setup` | Save your API key once, safely, outside your project |
| `--attack-update` | Download MITRE's ATT&CK technique list so suggested IDs can be verified |
| `--auto-lab`, `--hardened-lab` | Start the practice lab automatically |
| `--walkthrough`, `--quick` | The two interactive modes |
| `--version` | Print the version |

Exit codes: `0` success, `1` a target could not be reached, a scan stopped early, or the run was cancelled, `2` a finding met `--fail-on`
(or, with `--compare`, the second scan has new findings). Non-local targets ask once for confirmation that you are
authorized, however many there are.

## Practice lab

`webrecon/lab/vulnerable_lab.py` is a deliberately misconfigured app that only listens on 127.0.0.1. The easiest way to use it
is `python main.py` (walkthrough) or the menu. By hand:

```
python main.py http://127.0.0.1:8080 --auto-lab -o before.html                   # starts and stops it for you
python main.py http://127.0.0.1:8080 --auto-lab --hardened-lab -o after.html     # the fixed version
```

The before scan reports 21 findings and the after scan 3. The remaining 3 are expected because the lab runs over plain
HTTP, which is a good talking point for the demo. To run the lab yourself instead: `python3 -m webrecon.lab`
(add `--hardened` for the fixed version) in one terminal and scan it from another.

## AI risk context (optional)

`--ai` asks an AI server to add two things to every finding: an **estimated CVSS v3.1 score**, and the
**MITRE ATT&CK techniques** an attacker could use because of that weakness. It is off unless you ask for it, and a scan
never depends on it: if the server is down or the key is wrong, you get the normal report plus a note.

**A word on CVSS and ATT&CK.** MITRE ATT&CK catalogues attacker *techniques*; it does not publish CVSS scores. CVSS comes
from a scoring formula (FIRST) and, for specific vulnerabilities, from the NVD. So WebRecon works like this: the AI
suggests a CVSS vector for each *kind* of finding, **WebRecon calculates the score itself** from that vector (so an
invented number can never appear), and every technique ID the AI suggests is checked against MITRE's own list, with the
technique's name and tactics taken from MITRE. Everything is labelled as an estimate for the kind of weakness, not a
measurement of your site. For findings tied to a real CVE (WR-023), the report's reference links go to the NVD entry,
which is the authoritative score.

### Set it up

```
python3 main.py --ai-setup                       # once: type your key (hidden); it is saved outside your project
python3 main.py --attack-update                  # once: download MITRE's technique list (about 55 MB)
python3 main.py https://yoursite.com --ai --open
```

`--attack-update` is optional but recommended: without it, technique IDs are only checked for the right format and are
shown as "not checked against MITRE's list".

### Keeping your API key out of GitHub

Your key is never part of the code, and WebRecon never writes it into a report, the JSON results, the cache, or the
console. The only question is where *you* keep it, and these are the choices, safest first:

| Where the key lives | Can it be committed by accident? |
| --- | --- |
| **`python3 main.py --ai-setup`**: saved in `~/.config/webrecon/env` (Windows: `%APPDATA%\webrecon\env`), readable only by you | No. It is outside your project, so git never sees it. |
| An environment variable: `WEBRECON_AI_KEY` (or `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`) | No. Nothing is stored in the project. |
| A `.env` file in the project folder (copy `.env.example` to `.env` and fill it in) | Only if `.gitignore` stops protecting it. `.env` is already listed there, and WebRecon warns you if git is not ignoring it, if git is tracking it, or if other users can read it. |
| A command-line option, or typed into the source code | Not supported, on purpose: it would be saved in your shell history, and in your repository. |

A real environment variable always wins over a file. The files WebRecon reads can only set its own `WEBRECON_AI_*` and
the two provider key variables, so a file can never quietly change proxy or certificate settings.

**A safety net for commits.** `scripts/check_secrets.py` looks for things shaped like API keys (Anthropic and OpenAI-style
keys, GitHub tokens, AWS key IDs, private key blocks, long values assigned to `api_key`, `secret`, `token` or `password`).
Turn on the pre-commit hook once in your clone and a commit that contains one is refused:

```
git config core.hooksPath .githooks              # blocks the commit; nothing is committed
python3 scripts/check_secrets.py                 # or scan the whole project by hand
```

A finding shows the file, the line, the kind of secret and its length, never the secret. For a deliberate example, add
`secret-scan: allow` to that line. The test suite also scans the project, so a key that slips in fails the tests. This is
a net, not a guarantee, so also switch on GitHub's own secret scanning and push protection in your repository's security
settings.

**If a key is ever committed or shared,** treat it as exposed: revoke it with your AI provider first and create a new
one, then run `--ai-setup` again. Removing the file in a later commit, or rewriting history, does not make a key that was
public safe again. The same goes for pasting a key into a chat, an issue, or a screenshot.

### Choosing the server

| You want | Use |
| --- | --- |
| Anthropic's API (the default) | `--ai` (model defaults to `claude-haiku-5-5`; change it with `--ai-model`) |
| OpenAI | `--ai --ai-provider openai --ai-model MODEL-NAME` |
| Your own or a local server that speaks the OpenAI API (Ollama, vLLM, LM Studio and similar) | `--ai --ai-url http://localhost:11434/v1 --ai-model MODEL-NAME` (no key needed for localhost) |
| Another company's OpenAI-compatible service | `--ai --ai-url https://their.server/v1 --ai-model MODEL-NAME` |

Everything can also be set with environment variables, which options override: `WEBRECON_AI_KEY`, `WEBRECON_AI_URL`,
`WEBRECON_AI_MODEL`, `WEBRECON_AI_PROVIDER` (`anthropic` or `openai`). A URL that is not `anthropic.com` is treated as
OpenAI-style unless you say otherwise. WebRecon refuses to send a key over plain `http://` to any machine other than
localhost.

### What is sent, and what is not

Only generic descriptions of the *kinds* of finding: a check ID, the check's general title, its category and its usual
severity. **Never** the site's address, evidence, cookies, headers, page content, or the results. Run
`python3 main.py <site> --plan --ai` to see the setup before anything is sent. If you use a hosted service, that company
does see which kinds of weakness your scan found (for example "missing Content-Security-Policy"), just not where.

### Cost and caching

One request covers up to ten kinds of finding, so a first scan usually needs two to four requests. Answers are saved in
`~/.cache/webrecon/ai-cache.json` (Windows: `%LOCALAPPDATA%\webrecon`; change the folder with `WEBRECON_CACHE_DIR`), so
later scans send nothing. A different model, or a newer WebRecon prompt, asks again. Delete the file to refresh by hand.

### Where it shows up

The console shows `(CVSS ~3.7)` next to a finding; the HTML report adds an **AI-estimated risk context** line to each
finding with the score, vector and linked ATT&CK techniques, plus a "Highest AI-estimated CVSS" line in the summary; the
JSON keeps an `enrichment` object per finding; `--also csv,md` adds `ai_cvss_score`, `ai_cvss_vector` and
`ai_attack_techniques` columns and a Markdown line.

## Real-world notes

- **Know what it sends:** `--plan` lists every kind of request, the probe paths, the most requests a scan can make
  and the minimum time it takes, and shows which headers are attached (never their values). Nothing is sent.
  Useful when asking for permission to test a system. Each report also records how many requests were actually sent.
- **Time limit and Ctrl+C:** a scan stops after `--max-time` seconds (default 300), and Ctrl+C stops it cleanly.
  Either way you get a report of what was collected, marked partial, and the exit code is 1. Ctrl+C also skips any
  remaining targets in a multi-target run.
- **Pages nothing links to:** if the site has a `sitemap.xml`, its same-origin pages are added to the crawl.

- **Signed-in scans:** copy your session cookie from the browser's developer tools and pass it with `--cookie`.
  `--header` values go on every request, including redirects, so only use them on targets you trust.
- **Single-page apps:** sites that return the same page for every URL are detected, and path probes that match that
  page are ignored. The report says so.
- **Busy or protective servers:** try `--delay 1` and a smaller `--max-pages`, or a different `--user-agent`.
- **TLS:** the scan checks that the certificate validates and how long it has left. If it fails on a self-signed
  certificate, the error tells you to add `--insecure`.

## Checks

Run `python main.py --list-checks` for the live list. Summary:

| ID | Check | Severity |
| --- | --- | --- |
| WR-001 to WR-004 | HTTP instead of HTTPS, bad or expiring TLS certificate, HTTP not redirecting to HTTPS | Low to Medium |
| WR-010 to WR-017 | Missing or weak security headers, including a weak CSP | Info to Medium |
| WR-020 to WR-022 | Server version, technology header and generator-tag disclosure | Low |
| WR-023 | Outdated jQuery, Bootstrap or AngularJS with known vulnerabilities, recognised by the version in the script's URL | Low to Medium |
| WR-030 | Cookies missing Secure, HttpOnly or SameSite | Low to Medium |
| WR-040, WR-041 | Wildcard CORS (High with credentials), and a CORS policy that echoes back any Origin | Medium to High |
| WR-050, WR-051 | TRACE enabled, risky methods allowed | Low to Medium |
| WR-060 to WR-066 | Exposed .git, .env, server-status, phpinfo, directory listing, config files, Spring Actuator | Medium to High |
| WR-070 to WR-074 | Password over HTTP, forms posting to HTTP, password via GET, missing CSRF token, autocomplete | Info to High |
| WR-080 | robots.txt disallowed paths | Info |
| WR-090, WR-091 | Mixed content, third-party scripts without Subresource Integrity | Low to Medium |

## Tests

`pytest -q` runs the offline tests (no real network). The project layout, and how to add a check or an option, are in
[ARCHITECTURE.md](ARCHITECTURE.md).
