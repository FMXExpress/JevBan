#!/usr/bin/env bash
# Benchmark a decision model served over POST /v1/systemone (its own server, llama-server, or a shim):
#   bench/server_eval.sh LABEL URL "SPLITS" [THRESHOLD [REVIEW_THRESHOLD]] [OUTDIR]
# e.g. bench/server_eval.sh tinyjev http://127.0.0.1:8077/v1/systemone "wordpress-dev static-dev app-dev"
# One client per request (batch_clients = 1), as small models were benchmarked by their authors; the
# corpus .ini's own [decider] section is edited (a second one would be ignored). Pick the threshold on
# the dev splits with bench/pdist.py, then run the test splits once at that threshold.
set -euo pipefail
cd "$(dirname "$0")/.."
LABEL=$1; URL=$2; SPLITS=$3; T=${4:-}; RV=${5:-}; OUT=${6:-bench/results/server-$LABEL}
mkdir -p "$OUT"
for c in $SPLITS; do
  p=${c%-*}
  python3 - "bench/corpus/$p.ini" "$OUT/$LABEL-$p.ini" "$T" "$RV" <<'PY'
import sys
src, dst, t, rv = sys.argv[1:5]
s = open(src).read()
extra = 'batch_clients = 1\ntimeout_ms = 600000\n'
if t:
    extra += 'threshold = %s\n' % t
if rv:
    extra += 'review_threshold = %s\n' % rv
s = s.replace('[decider]', '[decider]\n' + extra, 1) if '[decider]' in s else s + '\n[decider]\n' + extra
open(dst, 'w').write(s)
PY
  start=$(date +%s)
  ./build/jevban -c "$OUT/$LABEL-$p.ini" --eval "bench/corpus/$c.log" --jev-url "$URL" \
    --eval-json "$OUT/$LABEL-$c.json" > "$OUT/$LABEL-$c.log" 2>&1 || true
  rm -f "$OUT/$LABEL-$p.ini"
  python3 -c "
import json; d = json.load(open('$OUT/$LABEL-$c.json')); c = d['clients']; m = d['model']
print('$LABEL $c: benign %d/%d attackers %d/%d leaked %d | model clients %d errors %d reviews %d | %ds' % (
    c['benign_banned'], c['benign'], c['attack_banned'], c['attack'], c['leaked_attack_requests'],
    m['clients'], m['errors'], m['reviews'], $(date +%s) - $start))"
done
