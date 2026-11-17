"""
catalog.py - Every check WebRecon can report, and where to read more about each one.
"""

# Every check ID WebRecon can report. Keep in sync with the modules in analysis/checks (a test enforces it).
CHECK_CATALOG = [
    ("WR-001", "Medium", "Site served over unencrypted HTTP"),
    ("WR-002", "Medium", "TLS certificate failed validation"),
    ("WR-003", "Low-Medium", "TLS certificate expires soon"),
    ("WR-004", "Medium", "HTTP version of the site does not redirect to HTTPS"),
    ("WR-010", "Medium", "Missing Content-Security-Policy header"),
    ("WR-011", "Medium", "No clickjacking protection"),
    ("WR-012", "Low", "Missing X-Content-Type-Options header"),
    ("WR-013", "Low", "Missing Referrer-Policy header"),
    ("WR-014", "Info", "Missing Permissions-Policy header"),
    ("WR-015", "Medium", "Missing Strict-Transport-Security header (HTTPS only)"),
    ("WR-016", "Low", "Weak HSTS max-age"),
    ("WR-017", "Low", "Weak Content-Security-Policy"),
    ("WR-020", "Low", "Server version disclosed"),
    ("WR-021", "Low", "Technology disclosed in a response header"),
    ("WR-022", "Low", "Software version disclosed in the page's generator tag"),
    ("WR-023", "Low-Medium", "Outdated JavaScript library with known vulnerabilities"),
    ("WR-030", "Low-Medium", "Insecure cookie attributes"),
    ("WR-040", "Medium-High", "Overly permissive CORS policy"),
    ("WR-041", "Medium-High", "CORS policy reflects any Origin"),
    ("WR-050", "Low", "HTTP TRACE method enabled"),
    ("WR-051", "Medium", "Potentially dangerous HTTP methods allowed"),
    ("WR-060", "High", "Git repository exposed"),
    ("WR-061", "High", "Environment file exposed"),
    ("WR-062", "Medium", "Apache server-status page exposed"),
    ("WR-063", "Medium", "phpinfo page exposed"),
    ("WR-064", "Medium", "Directory listing enabled"),
    ("WR-065", "Medium", "Sensitive file exposed (.htaccess, web.config, composer.json, .DS_Store)"),
    ("WR-066", "Medium-High", "Spring Boot Actuator exposed"),
    ("WR-070", "High", "Password submitted over HTTP"),
    ("WR-071", "Medium", "HTTPS page posts form data to HTTP"),
    ("WR-072", "Medium", "Password form uses GET"),
    ("WR-073", "Medium", "POST form with no visible CSRF token"),
    ("WR-074", "Info", "Password field without autocomplete guidance"),
    ("WR-080", "Info", "robots.txt lists hidden paths"),
    ("WR-090", "Low-Medium", "Mixed content: insecure resources on HTTPS pages"),
    ("WR-091", "Low", "Third-party scripts or styles without Subresource Integrity"),
]


def _cwe(number: int) -> str:
    return f"https://cwe.mitre.org/data/definitions/{number}.html"


_MDN = "https://developer.mozilla.org/en-US/docs/Web/"
_HSTS = _MDN + "HTTP/Headers/Strict-Transport-Security"
_CORS = [_MDN + "HTTP/CORS", _cwe(942)]

# Where to read more about each check: CWE entries, MDN pages, OWASP pages.
REFERENCES = {
    "WR-001": [_cwe(319), _MDN + "Security/Transport_Layer_Security"],
    "WR-002": [_cwe(295)],
    "WR-004": [_HSTS, _cwe(319)],
    "WR-010": [_MDN + "HTTP/CSP"],
    "WR-011": [_MDN + "HTTP/Headers/X-Frame-Options", _cwe(1021)],
    "WR-012": [_MDN + "HTTP/Headers/X-Content-Type-Options"],
    "WR-013": [_MDN + "HTTP/Headers/Referrer-Policy"],
    "WR-014": [_MDN + "HTTP/Headers/Permissions-Policy"],
    "WR-015": [_HSTS],
    "WR-016": [_HSTS],
    "WR-017": [_MDN + "HTTP/CSP"],
    "WR-020": [_cwe(200)],
    "WR-021": [_cwe(200)],
    "WR-022": [_cwe(200)],
    "WR-030": ["https://owasp.org/www-community/controls/SecureCookieAttribute", _MDN + "HTTP/Cookies"],
    "WR-040": _CORS,
    "WR-041": _CORS,
    "WR-050": ["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
    "WR-051": [_MDN + "HTTP/Methods"],
    "WR-060": [_cwe(527)],
    "WR-061": [_cwe(538)],
    "WR-062": [_cwe(200)],
    "WR-063": [_cwe(200)],
    "WR-064": [_cwe(548)],
    "WR-065": [_cwe(538)],
    "WR-066": [_cwe(200)],
    "WR-070": [_cwe(319)],
    "WR-071": [_cwe(319)],
    "WR-072": [_cwe(598)],
    "WR-073": ["https://owasp.org/www-community/attacks/csrf", _cwe(352)],
    "WR-090": [_MDN + "Security/Mixed_content"],
    "WR-091": [_MDN + "Security/Subresource_Integrity"],
}
