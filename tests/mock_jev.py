"""A stand-in for an OpenJev helper / Jev API: POST /v1/systemone with the same
request and response shapes (batched: one noul question per client). It
"decides" with a keyword check on each client's signature hits, so jevban can
be run end to end without a GPU. Usage: mock_jev.py [port]"""
import json, re, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

BAD = ("env-file", "vcs-dir", "traversal", "log4shell", "sqli", "php-rce", "scanner-agent",
       "binary-request", "config-file")

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        clients = req["state"]["clients"]
        answers = {}
        for key, q in req["questions"].items():
            ip = re.search(r"client (\S+) \(state", q["instructions"]).group(1)
            bad = any(t in clients[ip]["signature_hits"] for t in BAD)
            if q["type"] == "noul":
                answers[key] = {"type": "noul", "noul": 0.99 if bad else 0.08}
            else:
                choice = "vulnerability_scanner" if bad else "legitimate_visitor"
                answers[key] = {"type": "choice", "choice": choice, "probabilities": {}, "confidence": 0.9}
        sys.stderr.write("mock-jev: 1 request, %d clients, %d questions: %s\n" % (
            len(clients), len(req["questions"]), ", ".join(clients)))
        body = json.dumps({"id": "shim-1", "model": "mock", "answers": answers,
                           "usage": {"input_tokens": 0, "output_tokens": 0}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 3000), H).serve_forever()
