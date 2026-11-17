"""
webrecon.reporting - Everything that turns results into files.

    assessment.py   the per-target HTML report
    exports.py      JSON, CSV and Markdown copies
    pages.py        the multi-target summary and the before/after comparison pages
    components.py   badges, tables, the page shell, writing files, opening the browser
    style.py        colours, stylesheet (dark mode, print), filter script
"""

from webrecon.reporting.assessment import build_html, write_html
from webrecon.reporting.components import open_in_browser
from webrecon.reporting.exports import build_csv, build_markdown, write_csv, write_json, write_markdown
from webrecon.reporting.pages import build_compare_html, build_index_html, write_index

__all__ = ["build_compare_html", "build_csv", "build_html", "build_index_html", "build_markdown", "open_in_browser",
           "write_csv", "write_html", "write_index", "write_json", "write_markdown"]
