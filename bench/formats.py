#!/usr/bin/env python3
"""Format equivalence: the same requests written as Apache combined, nginx JSON and IIS W3C must
get the same decisions, at what speed each parses.

    python3 bench/formats.py APACHE_LOG OUT_DIR [--bin build/jevban]

Writes OUT_DIR/formats.json; exits 1 if the formats disagree.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RX = re.compile(r'(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\S+) "([^"]*)" "([^"]*)"')
MON = {m: i + 1 for i, m in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split())}


def convert(src, out):
    paths = {k: os.path.join(out, 'formats-%s.log' % k) for k in ('apache', 'json', 'iis')}
    with open(paths['apache'], 'w') as ap, open(paths['json'], 'w') as js, open(paths['iis'], 'w') as ii:
        ii.write('#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n'
                 '#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query cs-version sc-status sc-bytes '
                 'cs(User-Agent) cs(Referer)\n')
        for line in open(src):
            m = RX.match(line)
            if not m:
                continue
            ip, t, req, st, b, ref, ua = m.groups()
            parts = req.split(' ')
            # W3C has no room for spaces or a malformed request line; keep what all three can say
            if len(parts) != 3 or not parts[1].startswith('/') or '\\' in req or ' ' in ref:
                continue
            ap.write(line)
            js.write(json.dumps({'time_local': t, 'remote_addr': ip, 'request': req, 'status': st,
                                 'body_bytes_sent': b, 'http_referer': ref, 'http_user_agent': ua}) + '\n')
            stem, _, q = parts[1].partition('?')
            d, mo, rest = t.split('/')
            y, hh, mm, ss = rest.split(' ')[0].split(':')
            ii.write('%s-%02d-%s %s:%s:%s %s %s %s %s %s %s %s %s %s\n' % (
                y, MON[mo], d, hh, mm, ss, ip, parts[0], stem, q or '-', parts[2], st,
                b if b != '-' else 0, ua.replace(' ', '+') or '-', ref or '-'))
    return paths


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('src')
    ap.add_argument('out')
    ap.add_argument('--bin', default=os.path.join(os.path.dirname(HERE), 'build', 'jevban'))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    res = {}
    for kind, path in convert(args.src, args.out).items():
        lines = sum(1 for _ in open(path))
        t = time.time()
        out = subprocess.run([args.bin, '--test', path, '--mode', 'rules'], capture_output=True, text=True).stdout
        secs = time.time() - t
        summary = out.strip().splitlines()[-1].split('jevban: ', 1)[-1]
        nums = dict((k, int(v)) for v, k in re.findall(r'(\d+) (parsed|suspicious|strikes|bans)\b', summary))
        res[kind] = dict(lines=lines, lines_per_second=round(lines / secs), **nums)
        os.remove(path)
    with open(os.path.join(args.out, 'formats.json'), 'w') as f:
        json.dump(res, f, indent=2)
    keys = ('parsed', 'suspicious', 'strikes', 'bans')
    same = len({tuple(r.get(k) for k in keys) for r in res.values()}) == 1
    for kind, r in res.items():
        print('%-6s %8d lines/s  %s' % (kind, r['lines_per_second'], ', '.join('%s %s' % (k, r.get(k)) for k in keys)))
    if not same:
        sys.exit('formats disagree')


if __name__ == '__main__':
    main()
