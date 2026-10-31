#!/usr/bin/env python3
"""Throughput logs for bench/run.sh: 200,000 lines of typical traffic (2,000 visitors,
5% probes) and 100,000 lines where every line is a new address (a flood).

    python3 bench/gen_load.py OUTDIR
"""
import os
import random
import sys

UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36'
PAGES = ['/', '/blog/', '/blog/hello-world/', '/blog/tuning-apache/', '/css/site.css', '/js/app.js',
         '/img/logo.png', '/about/', '/feed/']
PROBES = ['/.env', '/wp-login.php', '/phpinfo2.php', '/.git/config', '/xmlrpc.php', '/backup.sql',
          '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '/admin/config.php']


def line(ip, i, path, status):
    return '%s - - [31/Oct/2026:%02d:%02d:%02d +0000] "GET %s HTTP/1.1" %d 512 "-" "%s"\n' % (
        ip, 10 + i // 216000, (i // 3600) % 60, (i // 60) % 60, path, status, UA)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    rng = random.Random(1)
    ips = ['10.0.%d.%d' % (rng.randint(0, 30), rng.randint(1, 254)) for _ in range(2000)]
    with open(os.path.join(out, 'typical.log'), 'w') as f:
        for i in range(200000):
            if rng.random() < 0.05:
                f.write(line(rng.choice(ips), i, rng.choice(PROBES), 404))
            else:
                f.write(line(rng.choice(ips), i, rng.choice(PAGES), 200))
    with open(os.path.join(out, 'flood.log'), 'w') as f:
        for i in range(100000):
            ip = '10.%d.%d.%d' % (rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 254))
            if rng.random() < 0.5:
                f.write(line(ip, i, rng.choice(PROBES), 404))
            else:
                f.write(line(ip, i, rng.choice(PAGES), 200))


if __name__ == '__main__':
    main()
