#!/usr/bin/env python3
"""Fetch the LogarX / Zodiarc labelled access log and convert it for jevban --eval.

The dataset (github.com/FRTX045/LogarX-Dataset, builds published as releases of
FRTX045/Zodiarc-Dataset) is real Apache combined-format output of a shop that was browsed and
attacked with real tools (dirb, gobuster, sqlmap, ...), with a ground-truth category for every
line. It has no licence file, so it is downloaded at benchmark time and never committed; the
checksums pin the exact bytes.

Categories map to labels as the dataset defines them: browsing, static_asset, api_call,
authentication and crawling are benign; reconnaissance, enumeration, injection,
path_traversal, access_control, credential_attack, ssrf and exploitation are attacks;
unknown lines are fed without a label (context, not scored).

    python3 bench/fetch_logarx.py [small|medium|large] [--out bench/corpus]
"""
import argparse
import hashlib
import json
import lzma
import os
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RELEASE = 'https://github.com/FRTX045/Zodiarc-Dataset/releases/download/2026-10-06-%s/%s'
# sha256 of the decompressed files, from the release's SHA256SUMS (2026-10-06 builds)
PINNED = {
    'small': {'access.log': '3b42d1ed0f14a2a18554176e332f7c96b11a6865c596c863f1dd37d4b8e6486b',
              'truth.jsonl': '19cd892701be7b7512bfe2793037d5aa8134a7099986f5323645d02df5e00d11'},
}
BENIGN = {'browsing', 'static_asset', 'api_call', 'authentication', 'crawling'}
ATTACK = {'reconnaissance', 'enumeration', 'injection', 'path_traversal', 'access_control',
          'credential_attack', 'ssrf', 'exploitation'}
SITE = ('An online DIY and hardware shop at shop.test: category pages under /c/, product pages, '
        'search, a cart and checkout, customer accounts with a login at /login, and a JSON API under '
        '/api/ (stock, cart, autocomplete) that its own pages call. Search engines and feed readers '
        'crawl it.')


def fetch(build, name, cache):
    path = os.path.join(cache, name)
    if not os.path.exists(path):
        url = RELEASE % (build, name + '.xz')
        print('downloading', url)
        with urllib.request.urlopen(url) as r, open(path + '.part', 'wb') as f:
            f.write(lzma.decompress(r.read()))
        os.replace(path + '.part', path)
    want = PINNED.get(build, {}).get(name)
    if want:
        got = hashlib.sha256(open(path, 'rb').read()).hexdigest()
        if got != want:
            raise SystemExit('%s: sha256 %s, expected %s' % (path, got, want))
    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('build', nargs='?', default='small', choices=['small', 'medium', 'large'])
    ap.add_argument('--out', default=os.path.join(HERE, 'corpus'))
    args = ap.parse_args()
    cache = os.path.join(args.out, '.logarx-' + args.build)
    os.makedirs(cache, exist_ok=True)
    log = fetch(args.build, 'access.log', cache)
    truth = fetch(args.build, 'truth.jsonl', cache)

    labels = {}
    with open(truth) as f:
        for line in f:
            r = json.loads(line)
            if 'line_no' in r:
                labels[r['line_no']] = r['category']
    counts = {'attack': 0, 'benign': 0, 'unlabelled': 0}
    out = os.path.join(args.out, 'logarx-%s.log' % args.build)
    with open(log, encoding='utf-8', errors='replace') as src, open(out, 'w') as dst:
        dst.write('# LogarX/Zodiarc %s build (2026-10-06), labels from truth.jsonl; not redistributable\n' % args.build)
        for n, line in enumerate(src, 1):
            line = line.rstrip('\n')
            cat = labels.get(n, 'unknown')
            if cat in BENIGN:
                dst.write('benign:%s\t%s\n' % (cat, line))
                counts['benign'] += 1
            elif cat in ATTACK:
                dst.write('attack:%s\t%s\n' % (cat, line))
                counts['attack'] += 1
            else:
                dst.write(line + '\n')
                counts['unlabelled'] += 1
    with open(os.path.join(args.out, 'logarx.ini'), 'w') as f:
        f.write('[decider]\nsite = %s\n' % SITE)
    print('%s: %d attack, %d benign, %d unlabelled lines' % (out, counts['attack'], counts['benign'],
                                                              counts['unlabelled']))


if __name__ == '__main__':
    main()
