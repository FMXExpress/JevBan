"""A stand-in for the parts of Cloudflare's API jevban uses, checked as the documentation states them,
so the cloudflare action can be tested without an account:

- GET/POST /accounts/{id}/rules/lists, PUT .../lists/{id}/items (asynchronous: an operation id, then
  GET .../rules/lists/bulk_operations/{op} is "pending" once and then "completed"; one pending
  operation per account, as documented);
- GET /zones?account.id=..&per_page=..&page=..;
- GET /zones/{id}/rulesets/phases/http_request_firewall_custom/entrypoint (404 when the zone has
  no custom rules), POST /zones/{id}/rulesets, POST /zones/{id}/rulesets/{rid}/rules (5 rules
  per zone, as on the free plan).

GET /_state returns the lists and rules for a test to check. Usage: mock_cloudflare.py PORT TOKEN
ACCOUNT_ID [zone.name ...] (a zone named with a leading + already has custom rules)."""
import json, re, sys, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PORT, TOKEN, ACCOUNT = int(sys.argv[1]), sys.argv[2], sys.argv[3]
LISTS = {}          # id -> {"name", "kind", "items": [...]}
OPS = {}            # op id -> remaining polls before "completed"
ZONES = []          # {"id", "name", "ruleset": None | {"id", "rules": [...]}}
for name in sys.argv[4:]:
    z = {"id": uuid.uuid4().hex, "name": name.lstrip("+"), "ruleset": None}
    if name.startswith("+"):
        z["ruleset"] = {"id": uuid.uuid4().hex, "rules": [{"id": uuid.uuid4().hex, "action": "block",
                                                            "expression": "ip.src.country eq \"XX\""}]}
    ZONES.append(z)
IP = re.compile(r"^[0-9a-fA-F:.]+(/\d+)?$")


def ok(result):
    return 200, {"success": True, "errors": [], "messages": [], "result": result}


def err(status, code, message):
    return status, {"success": False, "errors": [{"code": code, "message": message}], "messages": [],
                    "result": None}


class H(BaseHTTPRequestHandler):
    def handle_any(self, method):
        u = urlparse(self.path)
        p, q = u.path, parse_qs(u.query)
        if p == "/_state":
            return self.reply(200, {"lists": LISTS, "zones": ZONES})
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self.reply(*err(403, 10000, "Authentication error"))
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n)) if n else None
        acc = "/client/v4/accounts/" + ACCOUNT
        if p == acc + "/rules/lists" and method == "GET":
            return self.reply(*ok([{"id": i, "name": l["name"], "kind": l["kind"], "num_items": len(l["items"])}
                                   for i, l in LISTS.items()]))
        if p == acc + "/rules/lists" and method == "POST":
            if body.get("kind") != "ip" or not re.fullmatch(r"[a-z0-9_]{1,50}", body.get("name", "")):
                return self.reply(*err(400, 10001, "invalid list"))
            if LISTS:
                return self.reply(*err(400, 10030, "limit reached: 1 custom list on this plan"))
            i = uuid.uuid4().hex
            LISTS[i] = {"name": body["name"], "kind": "ip", "items": []}
            return self.reply(*ok({"id": i, "name": body["name"], "kind": "ip", "num_items": 0}))
        m = re.fullmatch(acc + r"/rules/lists/(\w+)/items", p)
        if m and method == "PUT":
            if m.group(1) not in LISTS:
                return self.reply(*err(404, 10000, "list not found"))
            if any(v > 0 for v in OPS.values()):
                return self.reply(*err(400, 10050, "another bulk operation is pending"))
            if not isinstance(body, list) or not all(isinstance(x, dict) and set(x) <= {"ip", "comment"}
                                                     and IP.match(x.get("ip", "")) for x in body):
                return self.reply(*err(400, 10021, "invalid items"))
            if len(body) > 10000:
                return self.reply(*err(400, 10022, "too many items"))
            LISTS[m.group(1)]["items"] = [x["ip"] for x in body]
            op = uuid.uuid4().hex
            OPS[op] = 1
            return self.reply(*ok({"operation_id": op}))
        m = re.fullmatch(acc + r"/rules/lists/bulk_operations/(\w+)", p)
        if m and method == "GET":
            if m.group(1) not in OPS:
                return self.reply(*err(404, 10000, "operation not found"))
            if OPS[m.group(1)] > 0:
                OPS[m.group(1)] -= 1
                return self.reply(*ok({"id": m.group(1), "status": "pending"}))
            return self.reply(*ok({"id": m.group(1), "status": "completed", "completed": "2026-11-15T00:00:00Z"}))
        if p == "/client/v4/zones" and method == "GET":
            if q.get("account.id") != [ACCOUNT]:
                return self.reply(*err(400, 10000, "filter by account.id"))
            per, page = int(q.get("per_page", ["20"])[0]), int(q.get("page", ["1"])[0])
            if not 5 <= per <= 50:
                return self.reply(*err(400, 10000, "per_page: 5 to 50"))
            part = ZONES[(page - 1) * per:page * per]
            return self.reply(*ok([{"id": z["id"], "name": z["name"]} for z in part]))
        m = re.fullmatch(r"/client/v4/zones/(\w+)/rulesets/phases/http_request_firewall_custom/entrypoint", p)
        if m and method == "GET":
            z = next((z for z in ZONES if z["id"] == m.group(1)), None)
            if z is None or z["ruleset"] is None:
                return self.reply(*err(404, 10003, "could not find entrypoint ruleset"))
            return self.reply(*ok({"id": z["ruleset"]["id"], "phase": "http_request_firewall_custom",
                                   "rules": z["ruleset"]["rules"]}))
        m = re.fullmatch(r"/client/v4/zones/(\w+)/rulesets", p)
        if m and method == "POST":
            z = next((z for z in ZONES if z["id"] == m.group(1)), None)
            if z is None or z["ruleset"] is not None:
                return self.reply(*err(400, 20000, "entrypoint exists"))
            if body.get("kind") != "zone" or body.get("phase") != "http_request_firewall_custom":
                return self.reply(*err(400, 20001, "kind zone, phase http_request_firewall_custom"))
            z["ruleset"] = {"id": uuid.uuid4().hex, "rules": [dict(r, id=uuid.uuid4().hex) for r in body["rules"]]}
            return self.reply(*ok({"id": z["ruleset"]["id"], "rules": z["ruleset"]["rules"]}))
        m = re.fullmatch(r"/client/v4/zones/(\w+)/rulesets/(\w+)/rules", p)
        if m and method == "POST":
            z = next((z for z in ZONES if z["id"] == m.group(1)), None)
            if z is None or z["ruleset"] is None or z["ruleset"]["id"] != m.group(2):
                return self.reply(*err(404, 10000, "ruleset not found"))
            if len(z["ruleset"]["rules"]) >= 5:
                return self.reply(*err(400, 20200, "exceeded maximum number of rules in the phase"))
            if body.get("action") != "block" or "$" not in body.get("expression", ""):
                return self.reply(*err(400, 20201, "unexpected rule"))
            z["ruleset"]["rules"].append(dict(body, id=uuid.uuid4().hex))
            return self.reply(*ok({"id": z["ruleset"]["id"], "rules": z["ruleset"]["rules"]}))
        return self.reply(*err(404, 7003, "no route for %s %s" % (method, p)))

    def reply(self, status, obj):
        b = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def do_PUT(self):
        self.handle_any("PUT")

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", PORT), H).serve_forever()
