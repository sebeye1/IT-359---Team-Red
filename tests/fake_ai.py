"""A fake AI server for tests. Speaks both the Anthropic Messages style and the OpenAI chat style on 127.0.0.1."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"   # scores 3.7


class FakeAi:
    def __init__(self):
        self.requests = []        # every request received: path, lower-cased headers, parsed JSON body
        self.status = 200         # status for replies once the queue below is empty
        self.statuses = []        # statuses for the next replies, consumed in order (for example [429, 429])
        self.texts = []           # model texts for the next replies, consumed in order
        self.text = None          # model text for every other reply (default: a good answer for each check asked)
        self.results_for = {}     # check_id -> fields that replace the default answer for that check
        self.error_message = "boom"
        self.delay = 0.0
        self.big = False          # send a huge body
        self.wrong_shape = False  # answer 200 with JSON that is in neither API's format
        self.raw_body = None      # answer 200 with exactly these bytes (for example not JSON)
        self.reject = []          # parameter names that cause a 400, like newer OpenAI models do
        self._server = None

    # ------------------------------------------------------------------ what the fake says

    def good_text(self, checks):
        results = []
        for check in checks:
            answer = {"check_id": check["check_id"], "cvss_vector": VECTOR,
                      "attack": [{"id": "T1190", "reason": "Reachable service."}], "rationale": "Typical."}
            answer.update(self.results_for.get(check["check_id"], {}))
            results.append(answer)
        return json.dumps({"results": results})

    def _reply(self, path, body):
        for name in list(self.reject):
            if name in body:
                hint = " Use 'max_completion_tokens' instead." if name == "max_tokens" else ""
                return 400, {"error": {"message": f"Unsupported parameter: '{name}'.{hint}"}}
        if self.statuses:
            status = self.statuses.pop(0)
        else:
            status = self.status
        if status != 200:
            return status, {"type": "error", "error": {"type": "x", "message": self.error_message}}
        content = body["messages"][-1]["content"]
        try:
            checks = json.loads(content.split("\n\n")[0])["checks"]
        except (ValueError, KeyError):
            checks = []
        text = self.texts.pop(0) if self.texts else (self.text if self.text is not None else self.good_text(checks))
        if path.endswith("/messages"):
            return 200, {"content": [{"type": "text", "text": text}]}
        return 200, {"choices": [{"message": {"content": text}}]}

    # ------------------------------------------------------------------ the server

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    @property
    def asked(self) -> list:
        """The check IDs in each request, in order."""
        out = []
        for request in self.requests:
            content = request["body"]["messages"][-1]["content"]
            out.append([c["check_id"] for c in json.loads(content.split("\n\n")[0])["checks"]])
        return out

    def start(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                fake.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                                      "body": body})
                if fake.delay:
                    time.sleep(fake.delay)
                if fake.big:
                    payload = b"x" * 3_000_000
                elif fake.raw_body is not None:
                    payload = fake.raw_body
                elif fake.wrong_shape:
                    payload = json.dumps({"unexpected": True}).encode()
                else:
                    status, data = fake._reply(self.path, body)
                    payload = json.dumps(data).encode()
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        return self

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
