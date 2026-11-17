"""
webrecon.cli - The command line.

    options.py        every option, the scan profiles, the short help, checking what you typed
    app.py            the entry point (main) that decides what to do
    workflow.py       scanning one target or many, output file names, exit codes
    console.py        everything printed: banner, results, summaries, tips
    authorization.py  the permission question for non-local targets
    plan.py           --plan
"""

from webrecon.cli.app import main

__all__ = ["main"]
