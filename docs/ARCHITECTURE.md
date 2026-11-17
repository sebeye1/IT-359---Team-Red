# How WebRecon is put together

## How a scan flows

```
python3 main.py https://site.example --open
        |
        v
   cli/options.py     reads and checks what you typed
   cli/app.py         decides what to do (scan, compare, list, walkthrough, menu)
        |
        v
   cli/workflow.py    for each target:
        |
        |  scanning.Scanner.run()            collects data              -> ScanResult
        |  analysis.analyze(result)          runs every check           -> findings, worst first
        |  results.filters                   --ignore, --min-severity, --baseline
        |  results.history.trend()           "since your previous scan"
        |  reporting.write_html / write_json / write_csv / write_markdown
        v
   reports/site.example_<time>.html  and  .json
```

The scanner only collects. The analyzer only judges. The reports only display. Keeping those three apart is what
makes each one easy to test.

## The packages

| Package | What it does | May import |
| --- | --- | --- |
| `scanning` | Crawls and probes a target, records what it sees in a `ScanResult` | nothing else in webrecon |
| `analysis` | One small function per check; `engine.analyze` runs them all | `scanning` |
| `ai` | Optional AI estimates: a CVSS vector (score calculated locally) and ATT&CK techniques, per kind of finding | `analysis`, `scanning` |
| `reporting` | Builds HTML pages and the JSON, CSV and Markdown exports | `analysis`, `scanning` |
| `results` | Compares saved scans, filters findings, finds earlier scans | `analysis`, `reporting`, `scanning` |
| `cli` | The command line | everything above, plus `lab` and `interactive` |
| `interactive` | The walkthrough and the short menu (they build ordinary command lines and hand them to a runner) | `reporting`, `results`, `bootstrap` |
| `lab` | The practice site | nothing else in webrecon |

Imports only point downward in that table. `tests/test_architecture.py` fails if one points the wrong way, so the
structure cannot drift unnoticed.

Two files sit outside the packages on purpose:

- `webrecon/bootstrap.py` uses only the standard library and runs *before* anything imports `requests` or
  `beautifulsoup4`. It is what lets `python3 main.py` fix a missing environment instead of showing a traceback.
- `webrecon/__init__.py` has no imports for the same reason.

## Adding a check

1. Write a function in the matching module under `webrecon/analysis/checks/` (or a new module). It takes the
   `ScanResult` and returns a list of `Finding`s:

   ```python
   def check_something(result: ScanResult) -> list[Finding]:
       if not <problem present>:
           return []
       return [Finding("WR-0xx", "Title", "Medium", "Category", "What is wrong and why it matters.",
                       "The evidence you saw", "How to fix it")]
   ```
2. Add it to `ALL_CHECKS` in `webrecon/analysis/engine.py`.
3. Add its ID, typical severity and title to `CHECK_CATALOG` in `webrecon/analysis/catalog.py`, and reference links
   to `REFERENCES` if there are good ones. A test fails if an ID used in a check is missing from the catalog.
4. If the check needs data the scanner does not collect yet, add a field to `ScanResult`
   (`scanning/models.py`) and fill it in `scanning/scanner.py`.
5. Add a test in `tests/analysis/test_checks.py`, and update the table in `docs/USAGE.md`.

Everything that comes from the scanned site (headers, page text, URLs) is untrusted. Reports escape it, the CSV export
neutralises formulas, and the Markdown export escapes it. Keep it that way for new output.

## Adding a command-line option

1. Add the argument in `build_parser()` in `webrecon/cli/options.py` (in the group where it belongs).
2. Validate it in `options.py` if it needs checking (see `parse_ignore` and `parse_also`).
3. Use it in `cli/workflow.py` (scanning and output) or `cli/app.py` (routing).
4. Add a test under `tests/cli/`, and a line in `docs/USAGE.md`. Options people use every day also belong in
   `SHORT_HELP`, which is the screen `--help` shows.

## The AI feature

`webrecon/ai/` is optional and isolated: nothing else imports it except the command line. The flow is
`prompt.py` (build a request from generic check descriptions only) -> `client.py` (send it) -> `enrich.py` (parse and
check the answer, cache it, attach it to the findings as `Finding.enrichment`). Two rules keep it trustworthy:

- **Scores are never taken from the AI.** `cvss.py` validates the vector and calculates the score with the CVSS v3.1
  formula. An invalid vector is dropped.
- **Nothing about the scanned site is sent.** `prompt.items_for` builds each item from the check catalog, not from the
  finding, and a test scans the practice lab and fails if any of its details appear in a request.

Keys never touch the project: `ai/envfile.py` reads private settings files (the per-user one lives outside any repo, and only an
allow-list of names can be set from a file) and `ai/setup.py` writes them with owner-only permissions. `scripts/check_secrets.py`
and the hook in `.githooks/` stop a key-shaped string from being committed, and `tests/test_secrets_guard.py` runs the same scan
over the whole project, so a leaked key fails the tests.

To support another kind of server, add its URL path, headers, request body and reply parsing to `client.py` (the
`_endpoint`, `_headers`, `_body` and `_text` methods), add its name to `PROVIDERS` in `config.py`, and extend
`tests/fake_ai.py` so the tests can exercise it. The reports read `finding.enrichment` as plain data and only make
`attack.mitre.org` links clickable, so they do not import `ai`.

## Tests

`tests/` mirrors the packages: `ai/`, `analysis/`, `scanning/`, `reporting/`, `results/`, `cli/`, `interactive/`, `lab/`.
`tests/helpers.py` holds the shared builders (a sample `ScanResult`, a fake HTTP response, a saved scan file),
`tests/fake_ai.py` is a fake AI server that speaks both API styles, and
`tests/conftest.py` runs every test in an empty temporary folder so nothing leaks into the project.

`tests/integration/test_lab_scans.py` scans the practice lab for real and pins the demo numbers (21 findings in the
vulnerable version, 3 in the hardened one). If a change moves those numbers, that test fails on purpose.
