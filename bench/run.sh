#!/usr/bin/env bash
# jevban benchmark: quality on the labelled corpora, and prefilter throughput.
#
#   bench/run.sh [label]              rules-only quality + throughput (a few seconds; CI runs this)
#   MODEL=flash-9b bench/run.sh [l]   also the local model on the test splits (slow on a CPU)
#   PROVIDER=typesafe bench/run.sh    ... or a hosted provider (needs its API key)
#   SPLITS="dev test" ...             which splits the model runs on (default: test)
#
# Results go to bench/results/<label>/ as JSON, and a table to bench/results/<label>/SUMMARY.md.
set -euo pipefail
cd "$(dirname "$0")/.."
LABEL="${1:-$(git rev-parse --short HEAD 2>/dev/null || echo local)}"
OUT="bench/results/$LABEL"
BIN=./build/jevban
mkdir -p "$OUT"
make -s >/dev/null
[ -f bench/corpus/wordpress-dev.log ] || python3 bench/gen_corpus.py >/dev/null
# real traffic: the LogarX/Zodiarc labelled shop log, downloaded (not redistributable); optional offline
[ -f bench/corpus/logarx-small.log ] || python3 bench/fetch_logarx.py small >/dev/null 2>&1 || \
  echo "bench: LogarX not available (offline?), skipped" >&2

for log in bench/corpus/*-dev.log bench/corpus/*-test.log bench/corpus/logarx-*.log; do
  [ -f "$log" ] || continue
  name=$(basename "$log" .log); profile=${name%-*}
  "$BIN" -c "bench/corpus/$profile.ini" --eval "$log" --mode rules --eval-json "$OUT/rules-$name.json" >/dev/null 2>&1
done

if [ -n "${MODEL:-}${PROVIDER:-}" ]; then
  for split in ${SPLITS:-test}; do
    for log in bench/corpus/*-"$split".log; do
      name=$(basename "$log" .log); profile=${name%-*}
      if [ -n "${PROVIDER:-}" ]; then args=(--provider "$PROVIDER"); tag="$PROVIDER"; else args=(--model "$MODEL"); tag="$MODEL"; fi
      echo "bench: $tag on $name ..." >&2
      "$BIN" -c "bench/corpus/$profile.ini" --eval "$log" "${args[@]}" --eval-json "$OUT/$tag-$name.json" \
        > "$OUT/$tag-$name.log" 2>&1
    done
  done
fi

# prefilter throughput: typical traffic and a flood of new addresses
python3 bench/gen_load.py "$OUT/.load" >/dev/null
for kind in typical flood; do
  start=$(date +%s.%N)
  "$BIN" --test "$OUT/.load/$kind.log" --mode rules > "$OUT/.load/$kind.out" 2>&1 &
  pid=$!; peak=0
  while kill -0 $pid 2>/dev/null; do
    r=$(awk '/VmHWM/{print $2}' /proc/$pid/status 2>/dev/null || true); [ -n "$r" ] && peak=$r; sleep 0.1
  done
  wait $pid || true
  secs=$(echo "$(date +%s.%N) - $start" | bc)
  lines=$(wc -l < "$OUT/.load/$kind.log")
  printf '{"kind": "%s", "lines": %d, "seconds": %.3f, "lines_per_second": %.0f, "peak_rss_kb": %d}\n' \
    "$kind" "$lines" "$secs" "$(echo "$lines / $secs" | bc -l)" "$peak" > "$OUT/throughput-$kind.json"
done
rm -rf "$OUT/.load"

python3 bench/summarize.py "$OUT" | tee "$OUT/SUMMARY.md"
