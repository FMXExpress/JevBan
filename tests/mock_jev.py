"""A stand-in for a Jev-style decision API, so jevban can be run end to end without a GPU or a key.

- POST /v1/systemone: the Jev / OpenJev helper shape ("state" + "questions").
- POST /v1beta/decisions: Google's Decisions API shape ("input" text + "questions", key in
  x-goog-api-key), checked as strictly as the documentation states it: a request it would
  reject gets HTTP 400 here too. An input containing MOCK_SAFETY gets the documented safety block.

It "decides" with a keyword check on each client's signature hits. Usage: mock_jev.py [port]"""
import json, os, re, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer

# MOCK_DELAY=seconds per client: stand in for a slow model (bench/live.py)
DELAY = float(os.environ.get("MOCK_DELAY", "0"))
# MOCK_KEY: the key the Decisions API endpoint expects in x-goog-api-key (any non-empty key if unset)
KEY = os.environ.get("MOCK_KEY", "")

BAD = ("env-file", "vcs-dir", "traversal", "log4shell", "sqli", "php-rce", "scanner-agent",
       "binary-request", "config-file")


class H(BaseHTTPRequestHandler):
    def reply(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def gemini_problem(self, req):
        """What the Decisions API would reject in this request, or None."""
        key = self.headers.get("x-goog-api-key", "")
        if not key or (KEY and key != KEY):
            return "missing or wrong x-goog-api-key"
        if set(req) - {"model", "input", "questions"}:
            return "unknown request fields: %s" % sorted(set(req) - {"model", "input", "questions"})
        if req.get("model") != "gemini-decision-1":
            return "model must be gemini-decision-1"
        if not isinstance(req.get("input"), str) or not req["input"]:
            return "input must be non-empty text here"
        qs = req.get("questions")
        if not isinstance(qs, dict) or not 1 <= len(qs) <= 1000:
            return "questions: 1 to 1,000"
        for k, q in qs.items():
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", k):
                return "question key %r" % k
            if set(q) - {"type", "instructions", "criteria"} or not q.get("instructions"):
                return "question %s fields" % k
            if q["type"] == "noul":
                if "criteria" in q and set(q["criteria"]) - {"true_description", "false_description"}:
                    return "noul criteria are true_description / false_description, got %s" % sorted(q["criteria"])
            elif q["type"] == "choice":
                c = q.get("criteria")
                if not isinstance(c, dict) or not 2 <= len(c) <= 255 or not all(isinstance(v, str) for v in c.values()):
                    return "choice criteria: a map of 2 to 255 option ids to descriptions"
            else:
                return "question type %r" % q["type"]
        return None

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        gemini = self.path.endswith("/v1beta/decisions")
        if gemini:
            problem = self.gemini_problem(req)
            if problem:
                return self.reply(400, {"error": {"code": "invalid_argument", "message": problem}})
            if "MOCK_SAFETY" in req["input"]:
                return self.reply(400, {"error": {"code": "safety", "message": "Request blocked due to safety "
                                                  "violations (harmful content). Please modify your input and retry."}})
            clients = json.loads(req["input"])["clients"]
        else:
            clients = req["state"]["clients"]
        time.sleep(DELAY * len(clients))
        answers = {}
        for key, q in req["questions"].items():
            ip = re.search(r"client (\S+) \(", q["instructions"]).group(1)
            bad = any(t in clients[ip]["signature_hits"] for t in BAD)
            if q["type"] == "noul":
                p = 0.99 if bad else 0.08
                answers[key] = {"type": "noul", "noul": p}
                if gemini:
                    answers[key]["confidence"] = max(p, 1 - p)
            else:
                choice = "vulnerability_scanner" if bad else "legitimate_visitor"
                answers[key] = {"type": "choice", "choice": choice, "probabilities": {}, "confidence": 0.9}
        sys.stderr.write("mock-%s: 1 request, %d clients, %d questions: %s\n" % (
            "gemini" if gemini else "jev", len(clients), len(req["questions"]), ", ".join(clients)))
        if gemini:
            self.reply(200, {"answers": answers, "usage": {"total_input_tokens": len(req["input"]) // 4,
                                                          "total_output_tokens": 0}})
        else:
            self.reply(200, {"id": "shim-1", "model": "mock", "answers": answers,
                             "usage": {"input_tokens": 0, "output_tokens": 0}})

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 3000), H).serve_forever()
