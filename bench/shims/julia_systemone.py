"""POST /v1/systemone over Julia 1's reference package (SupersonicLabs/Julia-1 ships no server).
Run from the folder that holds the Julia-1 checkout: python julia_systemone.py PORT. One request at a time."""
import json, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
import torch
from julia import load_model
torch.set_num_threads(4)
engine = load_model("Julia-1", device="cpu", strict_encoding=True, max_length=8192, head_length=512)

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        t = time.time()
        try:
            res = engine.predict(state=req["state"], questions=req["questions"])
            ans = res.get("answers", res)
            body, status = {"answers": ans}, 200
        except Exception as e:
            body, status = {"error": {"message": "%s: %s" % (type(e).__name__, e)}}, 400
        sys.stderr.write("julia: %d question(s) in %.0f ms\n" % (len(req["questions"]), 1000 * (time.time() - t)))
        b = json.dumps(body, default=float).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
