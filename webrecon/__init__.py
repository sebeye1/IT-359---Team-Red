"""
WebRecon - web application reconnaissance and security misconfiguration scanner.

Only scan systems you own or have written permission to test.

    scanning/      collects data from a target
    analysis/      turns that data into findings
    ai/            optional AI-estimated CVSS and ATT&CK context
    reporting/     HTML, JSON, CSV and Markdown output
    results/       comparing, filtering and remembering earlier scans
    cli/           the command line
    interactive/   the walkthrough and the short menu
    lab/           a deliberately vulnerable practice site

This file stays free of imports on purpose: the launcher checks that requests and beautifulsoup4
are installed before importing anything that needs them.
"""

__version__ = "1.10.1"
