#!/usr/bin/env python3
"""A markdown table from bench/run.sh's JSON results.

    python3 bench/summarize.py bench/results/<label> [bench/results/<baseline>]
"""
import glob
import json
import os
import sys


def load(d):
    runs = {}
    for f in sorted(glob.glob(os.path.join(d, '*.json'))):
        if os.path.basename(f) == 'formats.json':
            continue
        with open(f) as fh:
            runs[os.path.basename(f)[:-5]] = json.load(fh)
    return runs


def pct(x):
    return '-' if x is None or x < 0 else '%.1f%%' % (100 * x)


def main():
    runs = load(sys.argv[1])
    print('## Quality\n')
    print('| run | benign clients banned | attackers banned | attack requests caught | recall | precision '
          '| leaked/attacker | model clients | wall s |')
    print('|---|---|---|---|---|---|---|---|---|')
    cats = {}
    for name, r in runs.items():
        if name.startswith('throughput'):
            continue
        c, live = r['clients'], r['requests']['live']
        print('| %s | **%d/%d** | %d/%d | %d/%d | %s | %s | %.1f | %d | %.0f |' % (
            name, c['benign_banned'], c['benign'], c['attack_banned'], c['attack'],
            live['tp'], live['tp'] + live['fn'], pct(live['recall']), pct(live['precision']),
            c['leaked_per_banned_attacker_median'], r['model']['clients'], r['model']['wall_seconds']))
        for cat, v in r.get('categories', {}).items():
            cats.setdefault(cat, {})[name] = v
    print('\n## Clients banned per category\n')
    names = [n for n in runs if not n.startswith('throughput')]
    print('| category | ' + ' | '.join(names) + ' |')
    print('|---|' + '---|' * len(names))
    for cat in sorted(cats):
        row = []
        for n in names:
            v = cats[cat].get(n)
            row.append('%d/%d' % (v['banned'], v['clients']) if v else '')
        print('| %s | %s |' % (cat, ' | '.join(row)))
    print('\n## Prefilter throughput (rules, one core)\n')
    print('| log | lines | lines/s | peak RSS |')
    print('|---|---|---|---|')
    for name, r in runs.items():
        if name.startswith('throughput'):
            print('| %s | %d | %.0f | %.0f MB |' % (r['kind'], r['lines'], r['lines_per_second'], r['peak_rss_kb'] / 1024))
    fpath = os.path.join(sys.argv[1], 'formats.json')
    formats = json.load(open(fpath)) if os.path.exists(fpath) else None
    if formats:
        print('\n## Log formats: the same requests as Apache, nginx JSON and IIS W3C\n')
        print('| format | lines/s | suspicious | strikes | bans |')
        print('|---|---|---|---|---|')
        for kind, r in formats.items():
            print('| %s | %d | %s | %s | %s |' % (kind, r['lines_per_second'], r.get('suspicious'), r.get('strikes'),
                                               r.get('bans')))


if __name__ == '__main__':
    main()
