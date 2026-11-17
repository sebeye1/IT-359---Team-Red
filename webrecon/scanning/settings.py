"""
settings.py - Fixed values the scanner uses: what it calls itself, which paths it probes, and its limits.
"""

USER_AGENT = "WebRecon/1.0 (IT 359 Team Red - authorized testing only)"

# Low-impact GET probes. Each one is checked for a content signature in
# webrecon/analysis/checks/exposure.py so a custom 200 "not found" page does not cause a false positive.
PROBE_PATHS = [
    "/robots.txt",
    "/.git/HEAD",
    "/.env",
    "/server-status",
    "/phpinfo.php",
    "/uploads/",
    "/backup/",
    "/images/",
    "/.htaccess",
    "/web.config",
    "/composer.json",
    "/.DS_Store",
    "/actuator",
    "/actuator/env",
]

MAX_BODY_BYTES = 2_000_000          # never read more than this from one response
RETRY_STATUS = {429, 502, 503, 504}  # the server is busy or rate limiting us
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
CORS_PROBE_ORIGIN = "https://webrecon-probe.example"  # an origin no real site should trust
