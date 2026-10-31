#!/usr/bin/env python3
"""A small fixed model benchmark: from a corpus, every request of the first client of each
category that reaches the decider (not settled by hard rules). Used to measure model
latency and check verdicts while optimizing the local model.

    python3 bench/make_micro.py bench/corpus/wordpress-dev.log bench/corpus/micro.log
"""
import sys

CATS = ['attack:credential', 'attack:stealth', 'attack:injection', 'attack:wp-plugins', 'attack:variant',
        'benign:owner', 'benign:monitor', 'benign:linkchecker']

src, dst = sys.argv[1], sys.argv[2]
lines = [l for l in open(src) if '\t' in l]
chosen = {}
for l in lines:
    cat, rest = l.split('\t', 1)
    ip = rest.split(' ', 1)[0]
    if cat in CATS and cat not in chosen.values() and ip not in chosen:
        chosen[ip] = cat
with open(dst, 'w') as f:
    f.write('# micro benchmark from %s: %s\n' % (src, ', '.join(sorted(chosen.values()))))
    for l in lines:
        if l.split('\t', 1)[1].split(' ', 1)[0] in chosen:
            f.write(l)
print('%d clients, %d lines' % (len(chosen), sum(1 for l in lines if l.split('\t', 1)[1].split(' ', 1)[0] in chosen)))
