"""
vulnerable_lab.py - Local practice target for WebRecon.

Runs a deliberately misconfigured web app on 127.0.0.1 so the scanner can be
tested safely. Start it with --hardened to serve the fixed version, which is
used for the remediation and retest part of the project.

    python3 -m webrecon.lab              # vulnerable mode, port 8080
    python3 -m webrecon.lab --hardened   # remediated mode

Never expose this to a real network.
"""

import argparse
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HARDENED = False

HOME = """<!DOCTYPE html><html><head><title>Team Red Lab Store</title></head><body>
<h1>Team Red Lab Store</h1>
<ul>
  <li><a href="/login">Login</a></li>
  <li><a href="/about">About</a></li>
  <li><a href="/contact">Contact</a></li>
  {uploads_link}
  <li><a href="https://example.com/partner">Partner site</a></li>
</ul></body></html>"""

LOGIN_VULN = """<!DOCTYPE html><html><head><title>Login</title></head><body>
<h1>Login</h1>
<form action="/login" method="POST">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" value="Sign in">
</form></body></html>"""

LOGIN_HARDENED = """<!DOCTYPE html><html><head><title>Login</title></head><body>
<h1>Login</h1>
<form action="/login" method="POST">
  <input type="hidden" name="csrf_token" value="3f9a1c7e5b2d4a60">
  <input type="text" name="username" autocomplete="username">
  <input type="password" name="password" autocomplete="current-password">
  <input type="submit" value="Sign in">
</form></body></html>"""

ABOUT = "<!DOCTYPE html><html><head><title>About</title></head><body><h1>About us</h1><a href='/'>Home</a></body></html>"

CONTACT = """<!DOCTYPE html><html><head><title>Contact</title></head><body>
<h1>Contact</h1>
<form action="/contact" method="POST">
  {csrf}
  <input type="email" name="email"><textarea name="message"></textarea>
  <input type="submit">
</form></body></html>"""

UPLOADS_LISTING = """<!DOCTYPE html><html><head><title>Index of /uploads/</title></head><body>
<h1>Index of /uploads/</h1><ul><li><a href="invoice_2026.pdf">invoice_2026.pdf</a></li>
<li><a href="db_backup.sql">db_backup.sql</a></li></ul></body></html>"""

ROBOTS = "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n"


class LabHandler(BaseHTTPRequestHandler):
    def version_string(self):
        return "WebServer" if HARDENED else "Apache/2.4.29 (Ubuntu)"

    def _common_headers(self):
        if HARDENED:
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        else:
            self.send_header("X-Powered-By", "PHP/7.2.24")
            self.send_header("Access-Control-Allow-Origin", "*")

    def _send(self, status, body, content_type="text/html; charset=utf-8", cookie=False):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self._common_headers()
        if cookie:
            if HARDENED:
                self.send_header("Set-Cookie", "sessionid=a81b2c; Path=/; Secure; HttpOnly; SameSite=Strict")
            else:
                self.send_header("Set-Cookie", "sessionid=a81b2c; Path=/")
                self.send_header("Set-Cookie", "theme=dark; Path=/")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            link = "" if HARDENED else '<li><a href="/uploads/">Files</a></li>'
            return self._send(200, HOME.format(uploads_link=link), cookie=True)
        if path == "/login":
            return self._send(200, LOGIN_HARDENED if HARDENED else LOGIN_VULN, cookie=True)
        if path == "/about":
            return self._send(200, ABOUT)
        if path == "/contact":
            csrf = '<input type="hidden" name="csrf_token" value="3f9a1c7e5b2d4a60">' if HARDENED else ""
            return self._send(200, CONTACT.format(csrf=csrf))
        if path == "/robots.txt":
            return self._send(200, ROBOTS, "text/plain")
        if not HARDENED:
            if path == "/uploads/":
                return self._send(200, UPLOADS_LISTING)
            if path == "/.git/HEAD":
                return self._send(200, "ref: refs/heads/main\n", "text/plain")
            if path == "/.env":
                return self._send(200, "DB_HOST=localhost\nDB_PASSWORD=Summer2026!\nAPI_KEY=lab-not-a-real-key\n", "text/plain")
        return self._send(404, "<html><head><title>404</title></head><body>Not found</body></html>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._send(200, "<html><body>Thanks!</body></html>")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS, HEAD" if HARDENED else "GET, POST, PUT, DELETE, OPTIONS, TRACE")
        self._common_headers()
        self.end_headers()

    def do_TRACE(self):
        if HARDENED:
            return self._send(405, "Method Not Allowed", "text/plain")
        echo = f"TRACE {self.path} {self.request_version}\r\n{self.headers}"
        self._send(200, echo, "message/http")

    def log_message(self, fmt, *args):
        print(f"[lab] {self.address_string()} {fmt % args}")


def start_background(port: int = 8080, hardened: bool = False) -> ThreadingHTTPServer:
    """Start the lab on 127.0.0.1 in a daemon thread and return the server."""
    global HARDENED
    HARDENED = hardened
    server = ThreadingHTTPServer(("127.0.0.1", port), LabHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    global HARDENED
    parser = argparse.ArgumentParser(prog="python3 -m webrecon.lab", description="WebRecon practice lab")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--hardened", action="store_true", help="Serve the remediated configuration")
    args = parser.parse_args()
    HARDENED = args.hardened
    mode = "HARDENED" if HARDENED else "VULNERABLE"
    print(f"[lab] {mode} mode on http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", args.port), LabHandler).serve_forever()


if __name__ == "__main__":
    main()
