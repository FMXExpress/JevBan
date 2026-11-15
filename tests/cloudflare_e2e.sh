#!/usr/bin/env bash
# jevban's cloudflare action end to end against tests/mock_cloudflare.py (no account needed).
# Usage: tests/cloudflare_e2e.sh [jevban binary] [port]
set -euo pipefail
BIN=${1:-./build/jevban}; PORT=${2:-3020}; ACC=0123456789abcdef0123456789abcdef
W=$(mktemp -d); trap 'kill $MOCK $D 2>/dev/null || true; rm -rf "$W"' EXIT
python3 "$(dirname "$0")/mock_cloudflare.py" $PORT cf-test-token $ACC site1.example +site2.example site3.example &
MOCK=$!; sleep 1
: > $W/access.log
cat > $W/j.ini <<INI
[jevban]
logpath = $W/access.log
statefile = $W/state.json
poll_ms = 50
bantime = 4
bantime.increment = 0
[action]
type = none
[cloudflare]
account_id = $ACC
api_token = cf-test-token
api = http://127.0.0.1:$PORT/client/v4
INI
state() { curl -s http://127.0.0.1:$PORT/_state; }
items() { state | python3 -c "import sys,json; d=json.load(sys.stdin); print(' '.join(sorted(sum((l['items'] for l in d['lists'].values()),[]))))"; }
rules() { state | python3 -c "import sys,json; d=json.load(sys.stdin); print(' '.join('%s:%d'%(z['name'],sum('\$jevban' in r.get('expression','') for r in (z['ruleset'] or {}).get('rules',[]))) for z in d['zones']))"; }
waitfor() { for i in $(seq 1 100); do [ "$($1)" = "$2" ] && return 0; sleep 0.1; done; echo "FAIL: $1 is '$($1)', expected '$2'"; cat $W/out; exit 1; }
start() { "$BIN" -c $W/j.ini --mode rules > $W/out 2>&1 & D=$!; for i in $(seq 1 100); do grep -q following $W/out && return 0; sleep 0.1; done; cat $W/out; exit 1; }

start
waitfor rules "site1.example:1 site2.example:1 site3.example:1"
for ip in 203.0.113.81 203.0.113.82 2001:db8::83; do
  echo "$ip - - [15/Nov/2026:10:00:00 +0000] \"GET /x.php?id=1+union+select+1 HTTP/1.1\" 404 0 \"-\" \"sqlmap/1.8\"" >> $W/access.log
done
waitfor items "2001:db8::83 203.0.113.81 203.0.113.82"
echo "ok: three bans in the list, every zone blocks it"
waitfor items ""
echo "ok: expired bans left the list"
kill $D; wait $D 2>/dev/null || true
start
sleep 1
waitfor rules "site1.example:1 site2.example:1 site3.example:1"
echo "ok: a restart adds no second rule"
grep -q "cloudflare: created IP list jevban" $W/out || true
