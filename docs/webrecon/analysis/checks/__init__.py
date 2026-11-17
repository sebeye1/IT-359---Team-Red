"""
webrecon.analysis.checks - One module per kind of check. Every check is a small function that takes the
ScanResult and returns a list of Findings, so each can be tested on its own.

    transport.py   HTTPS, TLS certificate, HTTP to HTTPS redirect
    headers.py     security headers, CSP quality, information disclosure, generator tag
    cookies.py     Secure, HttpOnly, SameSite
    cors.py        wildcard and reflected origins
    methods.py     TRACE and other risky HTTP methods
    exposure.py    exposed files and directory listings, robots.txt
    forms.py       password forms and CSRF tokens
    content.py     mixed content, subresource integrity, outdated libraries
"""
