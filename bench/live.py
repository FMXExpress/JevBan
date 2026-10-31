#!/usr/bin/env python3
"""Live benchmark: wall-clock seconds from a client's first request to its ban, with the
daemon tailing a log that is written in real time.

The scenario: ambiguous clients (password guessers) arrive first and give the decider
work; a few seconds later an obvious scanner probes one known-bad path a second. A
daemon that stops reading while the model thinks lets the scanner run its whole list;
one that keeps reading bans it at its third probe. Also reports how long the ambiguous
clients wait for their verdicts (the model's latency under load).

    python3 bench/live.py [--model flash-9b | --provider NAME | --jev-url URL | --rules]
                          [--guessers 6] [--probes 30] [--json FILE]
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0'
SCAN = ['/.env', '/.git/config', '/.aws/credentials', '/wp-config.php.bak', '/backup.sql', '/.env.prod',
        '/config.php.old', '/phpinfo.php', '/.git/HEAD', '/server-status', '/.DS_Store', '/id_rsa',
        '/database.sql', '/.htpasswd', '/web.config', '/.svn/entries', '/dump.sql', '/.npmrc',
        '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '/adminer.php', '/phpmyadmin/',
        '/.env.local', '/.env.backup', '/settings.py', '/config.json', '/.vscode/sftp.json',
        '/wp-config.php~', '/.bash_history', '/credentials.json', '/.git/index']


def line(ip, path, method='GET', status=404, ua=UA):
    ts = datetime.now(timezone.utc).strftime('[%d/%b/%Y:%H:%M:%S +0000]')
    return '%s - - %s "%s %s HTTP/1.1" %d 300 "-" "%s"\n' % (ip, ts, method, path, status, ua)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument('--model')
    g.add_argument('--provider')
    g.add_argument('--jev-url')
    g.add_argument('--rules', action='store_true')
    ap.add_argument('--guessers', type=int, default=6)
    ap.add_argument('--probes', type=int, default=30)
    ap.add_argument('--json')
    ap.add_argument('--bin', default=os.path.join(REPO, 'build', 'jevban'))
    args = ap.parse_args()

    work = tempfile.mkdtemp(prefix='jevban-live-')
    log = os.path.join(work, 'access.log')
    open(log, 'w').close()
    with open(os.path.join(work, 'jevban.ini'), 'w') as f:
        f.write('[jevban]\nlogpath = %s\nstatefile = %s/state.json\npoll_ms = 100\n'
                '[decider]\nsite = A WordPress blog. Only its owner logs in, a few times a week.\n'
                '[action]\ntype = none\n' % (log, work))
    cmd = [args.bin, '-c', os.path.join(work, 'jevban.ini'), '-v']
    if args.model:
        cmd += ['--model', args.model]
    elif args.provider:
        cmd += ['--provider', args.provider]
    elif args.jev_url:
        cmd += ['--jev-url', args.jev_url]
    else:
        cmd += ['--mode', 'rules']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    out_lines = []
    bans = {}
    verdicts = {}   # ip -> time of the decider's first verdict on it (ban, strike, review or pass)

    def drain(until):
        """Read the daemon's output until time `until` (non-blocking-ish via os.set_blocking)."""
        while time.time() < until:
            try:
                l = proc.stdout.readline()
            except BlockingIOError:
                l = ''
            if not l:
                time.sleep(0.02)
                continue
            out_lines.append((time.time(), l.rstrip()))
            m = re.search(r'jevban: Ban (\S+) for', l)
            if m and m.group(1) not in bans:
                bans[m.group(1)] = time.time()
            m = re.search(r'jevban: (\S+) (?:BAN|strike \d+/\d+|REVIEW|pass) .* via (?!rules|hard rule)', l)
            if m and m.group(1) not in verdicts:
                verdicts[m.group(1)] = time.time()

    os.set_blocking(proc.stdout.fileno(), False)
    # wait for the daemon (and a local model) to be ready
    deadline = time.time() + 300
    while time.time() < deadline and not any('following' in l for _, l in out_lines):
        drain(time.time() + 0.5)
    if not any('following' in l for _, l in out_lines):
        proc.kill()
        sys.exit('daemon did not start:\n' + '\n'.join(l for _, l in out_lines[-20:]))

    first = {}
    guessers = ['198.51.100.%d' % (10 + i) for i in range(args.guessers)]
    scanner = '203.0.113.66'
    t0 = time.time()
    with open(log, 'a', buffering=1) as f:
        # the guessers: three password posts each, a second apart
        for rnd in range(3):
            for ip in guessers:
                first.setdefault(ip, time.time())
                f.write(line(ip, '/wp-login.php', 'POST', 200))
            drain(time.time() + 1)
        drain(time.time() + 4)
        # the scanner: one known-bad path a second
        sent_before_ban = 0
        for i in range(args.probes):
            if scanner in bans:
                break
            first.setdefault(scanner, time.time())
            f.write(line(scanner, SCAN[i % len(SCAN)]))
            sent_before_ban += 1
            drain(time.time() + 1)
    # wait for the guessers' verdicts (the model's latency), at most 15 minutes
    deadline = time.time() + 900
    while time.time() < deadline and not all(ip in verdicts for ip in guessers) and proc.poll() is None:
        drain(time.time() + 1)
        if not args.model and not args.provider and not args.jev_url:
            break
    proc.terminate()
    try:
        proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()

    res = {
        'decider': (args.model or args.provider or args.jev_url or 'rules'),
        'scanner_seconds_to_ban': round(bans[scanner] - first[scanner], 1) if scanner in bans else None,
        'scanner_requests_before_ban': sent_before_ban,
        'scanner_probes': args.probes,
        'guessers': len(guessers),
        'guessers_banned': sum(1 for ip in guessers if ip in bans),
        'guesser_seconds_to_ban': sorted(round(bans[ip] - first[ip], 1) for ip in guessers if ip in bans),
        'guesser_seconds_to_verdict': sorted(round(verdicts[ip] - first[ip], 1) for ip in guessers if ip in verdicts),
        'wall_seconds': round(time.time() - t0, 1),
    }
    print(json.dumps(res, indent=2))
    if args.json:
        with open(args.json, 'w') as f:
            json.dump(res, f, indent=2)


if __name__ == '__main__':
    main()
