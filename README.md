# jevban

**fail2ban for web attackers, with an AI judge.** jevban follows your web server's access logs,
spots clients probing for security holes, asks a decision model whether each one is really
attacking, and bans the ones that are in your firewall.

[![build](https://github.com/FMXExpress/JevBan/actions/workflows/release.yml/badge.svg)](https://github.com/FMXExpress/JevBan/actions/workflows/release.yml)
![platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20Windows-informational)
![language](https://img.shields.io/badge/Free%20Pascal-3.2.2-blue)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

```
$ jevban --eval tests/labeled_access.log        # excerpt, timestamps and user agents trimmed
203.0.113.66 strike 1/3 score=16 [env-file,known-bad-path] via hard rule: "GET /.env HTTP/1.1" 404
192.0.2.77 BAN score=3 [near-known-bad] p=0.98 via local batch of 1: "GET /phpinfo2.php HTTP/1.1" 404
192.0.2.88 strike 1/3 score=3 [wordpress] p=0.92 via local batch of 1: "GET /wp-content/plugins/revslider/..." 404
192.0.2.99 strike 1/3 score=3 [wordpress] p=0.94 via local batch of 1: "POST /wp-login.php HTTP/1.1" 200
192.0.2.150 pass score=3 [wordpress] p=0.38 via local (cached): "POST /wp-login.php HTTP/1.1" 200
```

Regex filters can't tell the last two apart: both are `POST /wp-login.php`, one from a password
guesser and one from the site's owner. jevban's model sees each client's recent requests and a
plain-words description of your site, and decides.

---

- [Why jevban](#why-jevban)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Deciders: local model, hosted API, or rules](#deciders)
- [What it catches](#what-it-catches)
- [Rolling it out safely](#rolling-it-out-safely)
- [Configuration](#configuration)
- [Command line](#command-line)
- [Firewall actions](#firewall-actions)
- [Requirements and performance](#requirements-and-performance)
- [Security notes](#security-notes)
- [Building from source](#building-from-source)
- [License and credits](#license-and-credits)

## Why jevban

Every public web server is crawled around the clock by bots that try `/.env`, `/.git/config`,
`/wp-config.php.bak`, `/phpmyadmin/` and hundreds of other paths, looking for a leaked secret
or an unpatched app. A typical bot tries 20–50 URLs before moving on. fail2ban can stop them
with regex filters, but regexes can't weigh context: `/wp-login.php` is an attack on a static
site and an everyday login on a WordPress blog.

jevban keeps the fast, predictable parts of fail2ban and adds judgement where it is needed:

- **Triage, not a black box.** Cheap checks decide the clear cases instantly. Only the
  ambiguous ones go to the model, and the model can never overrule a hard rule.
- **Runs the model itself.** By default jevban runs [OpenJev](https://huggingface.co/openjev/OpenJev-Flash-9B),
  an open decision model, in-process on llama.cpp. The first start downloads it; there is
  nothing else to install, no Python, and no data leaves the server.
- **Or uses a hosted API.** One line selects the [Jev API](https://docs.typesafe.ai/introduction)
  or a compatible provider (Perplexity, Liquid, DigitalOcean, Abacus, Vercel) at a few cents per
  thousand decisions.
- **Catches variants, not just exact strings.** Requests are decoded before matching, and a
  list of 2,454 known-bad paths is matched exactly and within 1–2 edits, so `/%2e%65%6e%76`,
  `/phpinfo2.php` and `/wp-config.php.save1` are caught without a rule for each.
- **Measurable.** `--eval` replays a labelled log and reports precision and recall for the
  rules alone and for the full pipeline; `--shadow` runs the model on live traffic without
  letting it ban.
- **fail2ban semantics.** `findtime`, `maxretry`, `bantime`, increasing bans for repeat
  offenders, `ignoreip`, bans that survive restarts, and actions for iptables, nftables, ufw,
  firewalld, fail2ban itself, the Windows firewall, or your own command.
- **One small binary** for Linux and Windows, written in Free Pascal.

## How it works

```
access.log ─▶ decode + normalize ─▶ score: signatures + known-bad paths
                                         │
            ┌────────────────────────────┼─────────────────────────────┐
         score 0                score ≥ 10 (hard rule)            in between
      nothing to judge        strike now, no model call      queued for the model
                                         │                            │
                                         │              one batched request every few seconds
                                         │                p ≥ 0.97 ban · p ≥ 0.80 strike
                                         │                p ≥ 0.50 REVIEW (logged, no strike)
                                         ▼                            │
                           3 strikes within 10 minutes  ◀─────────────┘
                                         │
                                         ▼
                         ban in the firewall for 1 hour (doubling for repeat offenders)
```

1. **Decode and normalize.** Apache's `\xhh` escapes and URL encoding (twice, to undo double
   encoding) are reversed, and the path is lowercased with `//` and `/./` collapsed.
2. **Score.** About 30 weighted signatures (secrets, traversal, injection, scanner tools…) and
   the known-bad path list add up to a score. Most traffic scores 0 and is only kept as
   context.
3. **Hard rules.** A score of 10 or more (`/.env`, `../`, `${jndi:`, `union select`, sqlmap…)
   is a strike immediately, so an obvious scanner is banned by its third probe, while it is
   still probing.
4. **The model judges the middle ground.** Flagged clients are queued and sent in one batch
   every 5 seconds (or 1,000 lines, or 8 clients). The model sees the client's flagged
   requests, its other recent requests, and your `site =` description, and returns the
   probability that the client is attacking. A verdict is reused for 60 seconds, so a scanner
   firing 200 probes costs one question.
5. **Ban.** `maxretry` strikes within `findtime` ban the client in the firewall for
   `bantime`. Bans are saved and restored across restarts, and lifted when they expire.

## Quick start

### Linux

Download `jevban-<version>-linux-x64.tar.gz` from the [Releases page](https://github.com/FMXExpress/JevBan/releases).
It needs glibc 2.35 or newer (Ubuntu 22.04, Debian 12, Fedora 36 and later) and a CPU with AVX2.

```bash
sudo mkdir -p /opt/jevban && sudo tar -C /opt/jevban --strip-components=1 -xzf jevban-*-linux-x64.tar.gz
sudo install -D -m 644 /opt/jevban/jevban.ini /etc/jevban/jevban.ini
```

Edit `/etc/jevban/jevban.ini`: set `logpath` to your access logs and describe your site in
`site =` (see [Configuration](#configuration)). Then see what it would do, without banning
anything:

```bash
sudo /opt/jevban/jevban --test /var/log/apache2/access.log
```

The first run downloads the model (5.6 GB, once) into `/var/lib/jevban/models`. When you're
happy with the decisions, run it as a service:

```bash
sudo /opt/jevban/jevban --dry-run        # live, but only log the firewall commands
sudo install -m 644 /opt/jevban/jevban.service /etc/systemd/system/
sudo systemctl enable --now jevban
sudo /opt/jevban/jevban --list           # active bans
```

### Windows

Download `jevban-<version>-windows-x64.zip` from the [Releases page](https://github.com/FMXExpress/JevBan/releases)
and unzip it. Its `jevban.ini` is set up for Apache Lounge (`C:\Apache24\logs\access.log`) and
the Windows firewall (`netsh`). From an elevated (Administrator) prompt:

```bat
jevban.exe --test C:\Apache24\logs\access.log
jevban.exe --dry-run
jevban.exe
```

The model is kept in `models\` next to `jevban.exe`. jevban runs as a console program; to start
it at boot, use Task Scheduler with "run with highest privileges".

### Without the local model

To try jevban without the 5.6 GB download, use the signatures alone, or a hosted API:

```bash
jevban --test access.log --mode rules
TYPESAFE_API_KEY=... jevban --test access.log --provider typesafe
```

<a id="deciders"></a>
## Deciders: local model, hosted API, or rules

| `mode` | What decides | Needs |
|---|---|---|
| `local` (default) | OpenJev in-process on llama.cpp | ~7 GB of RAM; the model downloads on first start |
| `jev` | A hosted decision API (`provider =`) or any Jev-compatible server (`url =`) | An API key, or your server |
| `rules` | The signatures alone | Nothing |

If the model can't be loaded or the API fails, jevban logs why and the signatures decide, so
protection never stops.

### Local models

| `local_model` | Size | RAM | Accuracy, model card |
|---|---|---|---|
| `flash-9b` (default) | 5.6 GB | ~7 GB | 79.3% (16-bit: 80.0%) |
| `flash-9b-q5`, `flash-9b-q6` | 6.5, 7.4 GB | ~8–9 GB | |
| `flash-9b-q8` | 9.5 GB | ~11 GB | 79.7% |
| `27b` | 16.5 GB | ~18 GB | 82.8% (16-bit: 83.2%) |
| `27b-q5`, `27b-q6`, `27b-q8` | 19.2, 22.1, 28.6 GB | ~21–30 GB | Q8: 82.6% |

You can also give the path to any `.gguf` file. Accuracy figures are from the OpenJev model
cards' validation set; on their 10,000-question benchmark the 27B scores 84.1% and Flash 9B
79.4%. The OpenJev weights are licensed CC BY-NC 4.0, free for non-commercial use; a
commercial licence is available from their authors.

jevban reproduces OpenJev's reference readout: the same prompt and chat template, the scores
of the option letters at the first output position, and the calibration constants published
for each model family (overridable with `readout_t`, `noul_t` and `noul_bias`).

### Hosted providers

```ini
[decider]
provider = typesafe          ; the key comes from api_key = or TYPESAFE_API_KEY
```

| `provider` | Service | Model | Key variable | Input, per 1M tokens |
|---|---|---|---|---|
| `typesafe` | [Jev API](https://docs.typesafe.ai/api) | `jev-latest` | `TYPESAFE_API_KEY` | $0.042 |
| `perplexity` | [Perplexity decisions](https://docs.perplexity.ai/docs/decisions/quickstart.md) | `pplx-decider-latest` | `PERPLEXITY_API_KEY` | $0.02 |
| `perplexity-flash` | same | `pplx-decider-flash-latest` | `PERPLEXITY_API_KEY` | $0.01 |
| `liquid` | [Liquid AI d1](https://docs.liquid.ai/lfm/models/d1) | `d1.1` | `LIQUID_API_KEY` | see provider |
| `digitalocean` | [DigitalOcean inference](https://docs.digitalocean.com/products/inference/how-to/use-system-one-api/) | `typesafe-jev-1.13.0` | `MODEL_ACCESS_KEY` | see provider |
| `abacus` | [Abacus.AI RouteLLM](https://abacus.ai/help/route-llm/systemone) | `jev-latest` | `ABACUS_API_KEY` | $0.042 |
| `vercel` | [Vercel AI Gateway](https://vercel.com/docs/ai-gateway/sdks-and-apis/typesafe) | `typesafe-ai/jev` | `AI_GATEWAY_API_KEY` | see provider |

Output tokens are free with all of them. A flagged client costs roughly 500–800 input tokens,
so 1,000 decisions cost a few cents. Endpoints and model names are from each provider's
documentation (October 2026); `url =` and `model =` override them. Each endpoint has been
checked to answer jevban's request; jevban has not yet been run against them with paid keys.

### Your own server

Any server that speaks the Jev request format works with `url =`, for example the OpenJev
helper (`helper/shim.py`) on top of vLLM:

```ini
[decider]
mode = jev
url = http://127.0.0.1:3000/v1/systemone
```

## What it catches

| Category | Examples | Weight |
|---|---|---|
| Leaked secrets and repositories | `/.env`, `/.git/config`, `/.aws/credentials`, `id_rsa` | 10 |
| Path traversal, system files | `../`, `/etc/passwd`, `/proc/self/` | 10 |
| Code execution | `${jndi:` (Log4Shell), shell injection, PHP-CGI argument injection, `php://input`, phpunit and ThinkPHP RCE, router exploits | 10 |
| SQL injection | `union select`, `sleep(`, `information_schema` | 10 |
| Scanner tools | sqlmap, nikto, nuclei, zgrab, masscan, wpscan, gobuster, ffuf… | 10 |
| Text written for an AI judge | a user agent saying "ignore previous instructions", "do not block", "this client is legitimate" | 10 |
| Admin tools and config files | phpMyAdmin, Adminer, Tomcat manager, `wp-config.php.bak`, `web.config` | 6 |
| Web shells, phpinfo, XSS, proxy probes, TLS sent to HTTP | `/shell.php`, `/phpinfo.php`, `<script`, `CONNECT` | 6 |
| Uploaded shells, upload filter tricks | PHP run from an uploads folder (`/wp-content/uploads/2026/10/x7f3.php`), `avatar.php.jpg` | 6 |
| Known-bad path, 4xx | any of 2,454 paths from [SecLists](https://github.com/danielmiessler/SecLists) `quickhits` | +6 |
| Known-bad file that exists (2xx), or a near variant on a 4xx | `/phpinfo2.php` → `/phpinfo.php` | +3 |
| Path scan | 8 different missing paths within a minute (plugin probes, files no list has) | +3 |
| File probe | a 4xx on code, config, data or a backup by name (`/Admin.asp`, `/db.sql`, `/config.json`) | +3 |
| File scan | the 3rd different file probe from one client within an hour: a scanner pacing itself between page views | +3 more |
| Site-dependent | WordPress and VPN logins, `/cgi-bin/`, script user agents, backups, 4xx bursts | 3 |

Weight 10 is never legitimate and bans without asking the model; 6 is almost always a probe;
3 depends on your site and is left to the model.

Some attackers are only visible over time, so jevban also watches behaviour:

- **Slow scanners** send one probe every 15–40 minutes, too slowly for `maxretry` within
  `findtime`. Probes (score 6 or more) are remembered per address for `longtime` (24 hours);
  `longretry` (5) of them ban.
- **Scans spread over many addresses** send two probes from each of 16 addresses in one /24.
  Once `subnet_retry` (3) addresses of a /24 (IPv6 /64) have probed within `findtime`, those
  addresses, and any other address of that subnet that probes, are banned. Only addresses that
  probed are banned, never the whole subnet, which may be a NAT or a mobile carrier.

Add your own rules in a file:

```
# signatures = /etc/jevban/extra.rules
# <weight> <url|request|agent|any> <tag> <regex>
10 url   secret-admin  ^/my-hidden-admin
6  agent bad-bot       BadBot/\d
```

## Rolling it out safely

A ban that hits a real customer is worse than a missed scanner, so jevban gives you three ways
to check its judgement before trusting it:

- **`--test FILE`** replays a log and prints every decision without banning anything.
- **`--shadow`** (or `shadow = 1`) runs live, asks the model and logs its verdict next to each
  decision, but only the signatures ban. Run it for a week and compare.
- **`--eval FILE`** replays a labelled log (`attack<TAB>line` or `benign<TAB>line`) and
  reports, for the signatures alone and for the full pipeline: true and false positives,
  precision, recall, attackers banned, and benign clients banned.

On the included synthetic WordPress set (`tests/labeled_access.log`, 73 requests from 13
clients), with Flash 9B on a 4-core CPU:

| | Attack requests caught | Missed | Benign requests flagged | Benign clients banned |
|---|---|---|---|---|
| Signatures alone | 7 | 6 | 0 | 0 of 6 |
| Hard rules + Flash 9B | 13 | 0 | 0 | 0 of 6 |

The model caught a WordPress plugin prober and a password guesser that the signatures can't
separate from the site's owner, whom it let through. This set is synthetic; label a day of
your own traffic and run `--eval` before relying on the numbers.

Model verdicts between 0.5 and the strike threshold are logged as `REVIEW` for you to audit.

## Benchmark

`bench/run.sh` measures quality and speed; every change to the detection is checked against it,
and benign clients banned must not go up.

- **Synthetic corpora** (`bench/gen_corpus.py`): three site types (a WordPress blog, a static
  site, a web app with an API and an admin panel), each with a dev split to tune on and a
  held-out test split to report on. The benign traffic includes what trips cheap checks (API
  clients with script user agents, link checkers, SEO crawlers, monitors, the owner logging
  in); the attacks include what dodges them (path variants, encodings, slow scanners, scans
  spread over a subnet, scanners hiding between page views, prompt-injecting user agents).
- **Real traffic**: the [LogarX/Zodiarc](https://github.com/FRTX045/LogarX-Dataset) labelled
  shop log (63,000 lines of real Apache output, real tools, a label on every line), downloaded
  at benchmark time and checksum-pinned (`bench/fetch_logarx.py`).
- **Live**: `bench/live.py` measures wall-clock time to a ban with the daemon tailing a log
  written in real time.

Signatures and behaviour rules alone (no model), held-out test splits and LogarX:

| | Benign clients banned | Attackers banned | Attack requests that reached the server |
|---|---|---|---|
| WordPress test | 0 of 73 | 44 of 51 | 196 |
| Static site test | 0 of 72 | 48 of 52 | 170 |
| Web app test | 0 of 79 | 43 of 51 | 216 |
| LogarX (real) | 0 of 789 | 126 of 126 | 536 |

The attackers the rules still miss are the ones that look like ordinary use (password
guessing, plugin probing, stealthy scanning between page views); those are the model's job.
Adding Flash 9B on the same held-out test splits (4-core CPU, measured before the file-probe
rules):

| | Benign clients banned | Attackers banned, rules alone | Attackers banned, rules + Flash 9B |
|---|---|---|---|
| WordPress test | 0 of 73 | 44 of 51 | 47 of 51 |
| Static site test | 0 of 72 | 43 of 52 | 46 of 52 |
| Web app test | 0 of 79 | 41 of 51 | 43 of 51 |

The model adds the password guessers on the WordPress and static sites and a few plugin and
exploit probers, and bans no one the rules spared. Scanners hidden between ordinary page views
(`stealth`, 3 per split) were missed by both; the file-probe rules now catch some of them.

### What the model decides, and what it doesn't

The work is split by how certain a request is. Weight-10 matches are hard rules: never
legitimate, decided without the model. Requests that score below 3 never reach it. Everything
in between (a WordPress login, a plugin path that 404s, a path scan, a file probe, a script
user agent) is the model's call, judged per client with its recent requests and your `site`
description. On the WordPress test split that was 137 model calls: 35 strikes and 292 passes,
against 34 hard-rule decisions. Rules alone never strike these clients, so every password
guesser the model banned (3 of 3 on WordPress) is one the rules let through, and every pass
is a site-dependent request that a stricter rule would have had to ban or ignore blindly.

## Configuration

Settings live in `/etc/jevban/jevban.ini` (or `jevban.ini` next to the binary); the shipped file
documents every key. The ones you'll want to look at:

| Key | Default | Meaning |
|---|---|---|
| `[jevban] logpath` | `/var/log/apache2/access.log` | Logs to follow; comma separated, wildcards allowed |
| `ignoreip` | `127.0.0.0/8 ::1` | Addresses and CIDR ranges never judged or banned |
| `findtime` / `maxretry` / `bantime` | `600` / `3` / `3600` | Strikes within seconds, strikes for a ban, ban seconds |
| `bantime.increment` / `bantime.maxtime` | `1` / `604800` | Double the ban for repeat offenders, up to a week |
| `[decider] site` | a generic public site | What your server runs, in plain words: **the most important setting** |
| `mode` | `local` | `local`, `jev` or `rules` |
| `local_model` | `flash-9b` | Which OpenJev model, or a `.gguf` path |
| `provider` | | A hosted API: `typesafe`, `perplexity`, `liquid`, … |
| `threshold` / `instant_threshold` | `0.80` / `0.97` | Model probability for a strike / an instant ban |
| `override_score` | `10` | Score that strikes without asking the model (0 = model decides all) |
| `review_threshold` | `0.5` | Model probability logged as REVIEW |
| `batch_interval` | `5` | Seconds between model batches |
| `shadow` | `0` | Log the model's verdicts, ban on the rules only |
| `[action] type` | `iptables` (Linux), `netsh` (Windows) | Firewall backend |
| `port` | `80,443` | Ports the ban applies to |
| `dry_run` | `0` | Log firewall commands instead of running them |

A good `site =` makes a large difference. For example:

```ini
site = A WordPress blog at example.com. The owner logs in at /wp-login.php and edits posts in
       /wp-admin/; an uptime monitor checks /health with curl. It runs no phpMyAdmin or other
       PHP apps, and serves no backups or config files.
```

## Command line

```
jevban [options]
  -c, --config FILE      settings (default /etc/jevban/jevban.ini, else next to the binary)
  -l, --log FILE         access log or wildcard pattern to follow (repeatable)
      --from-start       read the logs from their start, not just new lines
  -t, --test FILE        read FILE once, print each decision, ban nothing
      --eval FILE        replay a labelled log and score the decisions
      --shadow           ask the model and log its verdicts, but let the signatures ban
  -n, --dry-run          log the firewall commands instead of running them
  -m, --mode MODE        local | jev | rules
      --model NAME       local model, or a .gguf path
  -p, --provider NAME    a hosted decision API
  -u, --jev-url URL      a Jev-compatible server
  -a, --action TYPE      iptables | nftables | ufw | firewalld | fail2ban | netsh | command | none
  -b, --batch SECONDS    seconds between model batches
      --list             print the active bans and exit
  -v, --verbose          log every flagged request and verdict
```

## Firewall actions

| `type` | How a ban is applied |
|---|---|
| `iptables` (Linux default) | A `jevban` chain hooked into INPUT for the web ports; IPv6 through `ip6tables` |
| `ipset` | iptables with the bans in a hash set (IPv4 `jevban`, IPv6 `jevban6`) behind one rule: use it when bans run into the thousands |
| `nftables` | A `jevban` table with IPv4 and IPv6 address sets |
| `ufw` | `ufw prepend deny from <ip> to any port <port>` |
| `firewalld` | A runtime rich rule |
| `fail2ban` | `fail2ban-client set <jail> banip <ip>`: hand the ban to an existing jail |
| `netsh` (Windows default) | A Windows Firewall block rule |
| `command` | Your own `actionban` / `actionunban` commands |
| `none` | Log only |

The `iptables`, `ipset` and `nftables` presets have been tested for real: ban, unban on expiry,
and cleanup on stop, for IPv4 and IPv6. The `iptables` preset adds one rule per address, which
the kernel checks one by one for every packet, and adding a ban gets slower too (50 bans took
191 ms with no bans in place, 419 ms with 20,000); `ipset` and `nftables` keep the addresses in
a hash set, where both stay flat.

Actions follow fail2ban's lifecycle (`actionstart`, `actionban`, `actionunban`, `actionstop`),
and any of the four commands can be overridden in `[action]` with tags such as `<ip>`,
`<port>`, `<name>` and `<bantime>`.

## Requirements and performance

- **Linux:** x86-64 with AVX2, glibc 2.35+ (Ubuntu 22.04, Debian 12, Fedora 36 and later); root
  or `CAP_NET_ADMIN` to change the firewall.
- **Windows:** x64; an Administrator prompt for the Windows firewall.
- **Logs:** Apache `common`, `combined` and `vhost_combined`, and nginx's default format, IPv4
  and IPv6. Rotation by rename or copytruncate is followed. Behind a reverse proxy, log the real
  client address (`mod_remoteip`).
- **Memory:** about 1 GB more than the model file in local mode (~7 GB for Flash 9B); a few MB
  with a hosted API or rules only.
- **Speed:** the parser, signatures and known-bad paths handle about 16,000 lines a second on
  one core with typical traffic, and about 7,500 in a flood where every line is a new address
  (measured with `--test` on 200,000 lines). In local mode on a 4-core
  CPU, Flash 9B reads about 20 prompt tokens a second, about 20 seconds per flagged client; batching, verdict caching and
  hard rules keep the queue small, and the log is caught up afterwards. With a GPU, use
  llama.cpp libraries built with CUDA or Vulkan (`llama_lib_dir`) and set `gpu_layers = 999`.
  A hosted API answers in well under a second.

## Security notes

- **Bans come after the fact.** jevban reads the log after the server has answered, so a
  client's first probes reach your application. It shortens attacks; it does not replace
  patching, input validation, or a web application firewall.
- **Log lines are attacker-controlled.** They reach the model only as quoted data, never as
  instructions, and the model's answer is a single letter, so a crafted request can at most
  argue its own probability down. Hard rules don't depend on the model at all.
- **Nothing from a log reaches a shell.** Firewall commands only ever receive an address that
  parsed as IPv4 or IPv6 and was re-printed.
- **Local mode keeps logs on the server.** With a hosted API, flagged clients' requests and
  your `site` description are sent to that provider.

## Building from source

```bash
make              # build/jevban, with badpaths.txt (Free Pascal 3.2.2)
make llama        # llama.cpp libraries next to it, for local mode (git, cmake, a C++ compiler)
make test         # unit tests and a replay of the sample log
```

To install a source build, copy the contents of `build/` (the binary, `badpaths.txt` and the
`lib*.so*` files) to `/opt/jevban` with `jevban.ini` and `jevban.service`, as in
[Quick start](#quick-start).

<details>
<summary>Project layout</summary>

| File | Purpose |
|---|---|
| `jevban.lpr` | Main loop, signals, `--test` and `--eval` |
| `Ban.Config.pas` | `jevban.ini`, command line, provider presets |
| `Ban.Tail.pas` | `tail -F` with rotation and wildcards |
| `Ban.Apache.pas` | Access-log parser and decoding |
| `Ban.Signatures.pas` | Weighted regex signatures |
| `Ban.BadPaths.pas` | Known-bad paths: exact, and near (bounded Levenshtein over a BK-tree) |
| `Ban.Engine.pas` | Triage, batching, strikes, bans, state, evaluation |
| `Ban.Jev.pas` | Decider interface and the Jev API client |
| `Ban.Local.pas` | OpenJev in-process: download, prompt, readout, calibration |
| `Ban.Llama.pas` | llama.cpp C API, loaded at run time |
| `Ban.Firewall.pas` | Firewall action presets and command runner |
| `Ban.Net.pas` | IPv4/IPv6 addresses and CIDR ranges |
| `Ban.Https.pas` | HTTP(S) client with verified TLS and proxy support |
| `data/badpaths.txt` | Known-bad path list |
| `tests/` | Unit tests, sample and labelled logs, a mock decision server |

</details>

## License and credits

jevban is released under the [MIT License](LICENSE).

- [OpenJev](https://huggingface.co/openjev/OpenJev-Flash-9B) model weights: CC BY-NC 4.0,
  downloaded at first use, not bundled.
- [llama.cpp](https://github.com/ggml-org/llama.cpp): MIT, bundled in the releases.
- Known-bad paths from [SecLists](https://github.com/danielmiessler/SecLists) by Daniel
  Miessler: MIT (`data/LICENSE.seclists`).
- `Ban.Https.pas` comes from [memagent](https://github.com/FMXExpress/Short-Long-Memory-LLM).
- Jev and the System One API are by [TypeSafe](https://docs.typesafe.ai/introduction); jevban
  is an independent project and not affiliated with them or with OpenJev's authors.
