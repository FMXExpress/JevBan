#!/usr/bin/env python3
"""Per-client highest model probability, benign vs attack, from bench/server_eval.sh logs: where a
threshold could separate them (choose it on dev splits, report test splits once).

    python3 bench/pdist.py OUTDIR LABEL split [split ...]
"""
import gzip, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
out, label = sys.argv[1], sys.argv[2]
for c in sys.argv[3:]:
    lab = {}
    for line in open(os.path.join(HERE, 'corpus', c + '.log'), errors='replace'):
        if '\t' in line:
            a, b = line.split('\t', 1)
            lab.setdefault(b.split()[0], a)
    top = {}
    log = os.path.join(out, '%s-%s.log' % (label, c))
    f = open(log, errors='replace') if os.path.exists(log) else gzip.open(log + '.gz', 'rt', errors='replace')
    for line in f:
        m = re.search(r'jevban: (\S+) (?:BAN|strike \d+/\d+|REVIEW|pass) .* p=([0-9.]+)', line)
        if m:
            top[m.group(1)] = max(top.get(m.group(1), 0), float(m.group(2)))
    ben = sorted(p for ip, p in top.items() if lab.get(ip, '').startswith('benign'))
    att = sorted(p for ip, p in top.items() if lab.get(ip, '').startswith('attack'))
    q = [round(att[int(f * (len(att) - 1))], 2) for f in (0, .25, .5, .75, 1)] if att else '-'
    print('%s %s: benign judged %d, highest p %s | attackers judged %d, p quartiles %s' % (
        label, c, len(ben), [round(x, 2) for x in ben[-3:]], len(att), q))
