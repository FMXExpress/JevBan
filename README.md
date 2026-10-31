# jevban: fail2ban for web attackers, judged by a Jev-style decision AI

**One binary, nothing else to install.** jevban runs [OpenJev](https://huggingface.co/openjev/OpenJev-Flash-9B)
inside itself on llama.cpp; the first start downloads the model (Flash 9B, 5.6 GB). Or point it at
the hosted Jev API, or at your own OpenJev server.

A Free Pascal command-line daemon. It follows Apache access logs, spots clients that are
hunting for security holes, and bans them in the firewall, the way fail2ban does. The
difference from a fail2ban filter: a regex is only the **prefilter**. A **decision model**
(OpenJev, or the hosted Jev API) decides whether a client is attacking. It sees the client's
recent requests and a plain-words description of your site.

```
access.log ──tail -F──▶ parse ──▶ signatures (cheap) ──suspicious──▶ POST /v1/systemone
                                                                         │ P(malicious), intent
                     firewall ◀── ban ◀── maxretry strikes in findtime ◀──┘
```

Why a model: `GET /wp-login.php` is a probe on a static site and a normal login on a WordPress
site. You write that in `site =` and the model weighs it. A regex can't.

## Download

Linux x64 and Windows x64 builds are on the [Releases page](https://github.com/FMXExpress/jevban/releases).
Both include the llama.cpp libraries (CPU, AVX2) for the local model. The Windows zip also has
the OpenSSL DLLs and `cacert.pem` for `https://`, and its `jevban.ini` uses the `netsh` action.

## Build and try it

```bash
make                   # -> build/jevban   (FPC 3.2.2; OpenSSL only for https://)
make llama             # llama.cpp libraries next to it, for mode = local (git, cmake, a C++ compiler)
make test              # unit tests + a replay of tests/sample_access.log
```

```bash
./build/jevban --test /var/log/apache2/access.log --mode rules       # what would be banned, bans nothing
./build/jevban --test /var/log/apache2/access.log -u http://127.0.0.1:3000/v1/systemone   # asking a server
./build/jevban --test /var/log/apache2/access.log --model flash-9b    # OpenJev in-process (downloads 5.6 GB once)
python3 tests/mock_jev.py 3000 &                              # a fake /v1/systemone server, for --jev-url
```

A run over `tests/sample_access.log` (`--mode rules`):

```
203.0.113.66 strike 1/3 score=10 [env-file] via rules: "GET /.env HTTP/1.1" 404 ...
203.0.113.66 strike 2/3 score=10 [vcs-dir] via rules: "GET /.git/config HTTP/1.1" 404 ...
203.0.113.66 strike 3/3 score=9 [config-file,backup-file] via rules: "GET /wp-config.php.bak HTTP/1.1" 404 ...
Ban 203.0.113.66 for 3600s (ban #1): config-file,backup-file, score 9
192.0.2.44 BAN score=20 [sqli,scanner-agent] via rules: "GET /?id=1%20UNION%20SELECT..." ua="sqlmap/1.8..."
198.51.100.7 pass score=3 [wordpress] via rules: "GET /wp-login.php HTTP/1.1" 200 ...
15 lines, 15 parsed, 1 ignored, 9 suspicious, 0 decider calls (0 failed), 8 strikes, 2 bans, 0 unbans
```

## Run it for real

```bash
sudo install -m 755 build/jevban /usr/local/bin/
sudo install -D -m 644 jevban.ini /etc/jevban/jevban.ini     # edit logpath, site, action
sudo jevban --dry-run                                                # watch the firewall commands it would run
sudo install -m 644 jevban.service /etc/systemd/system/ && sudo systemctl enable --now jevban
sudo jevban --list                                                   # active bans
```

It has to run as root (or with `CAP_NET_ADMIN`) to change the firewall.

## How it scans, and how often it calls the model

Every log line goes through the cheap steps. Only the leftovers reach the model, and they go
in batches:

1. **Every line** is parsed and scored by the signatures: about 30 regexes, microseconds per
   line. Most traffic scores 0 and stops here. The line is still kept as context: the last
   `context_lines` requests of each client.
2. **A flagged line** (score >= `suspicious_score`) from a client with a fresh verdict (younger
   than `cache_secs`) reuses that verdict. No model call.
3. **Otherwise the client is queued.** More flagged lines from a queued client join the same
   entry; they don't add new questions.
4. **The queue is flushed as one request** when any of these happens first:
   - the oldest client has waited `batch_interval` seconds (default 5);
   - `batch_lines` log lines went by (default 1000);
   - `batch_clients` clients are queued (default 8).

   That one `POST /v1/systemone` holds every queued client in `state.clients` and asks one
   yes/no question per client (`c1`, `c2`, ...). The decision server reads the shared state
   once (prefix cache) and answers all of them.
5. Each flagged request of a client gets that client's probability. With the default
   `maxretry`, a scanner that sent 3 probes inside the window comes out of one batch banned.

Example: a scanner firing 200 probes in 10 seconds costs 2 questions, not 200 calls. 50
scanners in the same 5 seconds cost 7 requests (8 clients each). `max_per_minute` caps the
requests; past it, the signatures decide. `batch_interval = 0` with `batch_clients = 1`
asks about each client at once, if you'd rather have the lowest latency.

## Deciders

| `mode` | What answers | Setup |
|---|---|---|
| `local` (default) | OpenJev in-process on llama.cpp | none: the model downloads on first start |
| `jev` | a `/v1/systemone` server: the [hosted Jev API](https://docs.typesafe.ai/introduction) (`https://api.typesafe.ai/v1/systemone`, `api_key`) or OpenJev's helper | the server |
| `rules` | the signatures alone | none |

### Local models (`local_model` / `--model`)

| Name | File | Size | Accuracy (model card) |
|---|---|---|---|
| `flash-9b` (default) | OpenJev-Flash-9B-Q4_K_M.gguf | 5.6 GB | 79.3% on the card's 1,789-question check (16-bit: 80.0%) |
| `flash-9b-q5`, `-q6` | Q5_K_M, Q6_K | 6.5, 7.4 GB | |
| `flash-9b-q8` | Q8_0 | 9.5 GB | 79.7% on the same check |
| `27b` | OpenJev-Q4_K_M.gguf | 16.5 GB | 82.8% on its check (16-bit: 83.2%) |
| `27b-q5`, `-q6`, `-q8` | Q5_K_M, Q6_K, Q8_0 | 19.2, 22.1, 28.6 GB | Q8_0: 82.6% |

Or a path to any `.gguf`. On the 10,000-question benchmark of the model cards the 27B scores
84.1% and Flash 9B 79.4% (vLLM, 16-bit).

The local readout is OpenJev's helper (`helper/shim.py`) redone in Pascal:
- the same prompt, the same chat template with thinking off;
- the logits of the option letters at the first output position;
- `softmax(logit / T)` over the options, and for yes/no `sigmoid(logit(p) / noul_t + noul_bias)`;
- the family's calibration from the model card: Flash `T = 1.07, noul_t = 1.074766`; 27B
  `T = 0.85, noul_t = 1.829074`.

The model cards publish these for the vLLM helper. Applying them to GGUF logits is the same
readout, but the cards don't separately validate it. Override them with `readout_t`, `noul_t`
and `noul_bias`.

Speed: a decision is one prompt of a few hundred tokens per client. On a 4-core CPU, Flash 9B
takes tens of seconds per client, so a batch of flagged clients can take minutes. The tail keeps
its place in the file and catches up afterwards. With a GPU, put llama.cpp libraries built with
CUDA or Vulkan in `llama_lib_dir` and set `gpu_layers = 999`.

Licence: the OpenJev weights are CC BY-NC 4.0 (non-commercial; a commercial licence from
support@loopai.com). jevban itself is MIT, and llama.cpp is MIT.

## The decider API (Jev compatible)

`mode = jev` (the default) sends batches as described above to `url`. The request shape is the
hosted Jev API's, which [OpenJev](https://huggingface.co/openjev/openjev)'s helper
(`helper/shim.py`, port 3000 in its SERVE.md) serves on top of vLLM. Point `url` at either
one. Set `api_key` or `JEV_API_KEY` if the server wants a bearer token.

```json
{"model": "openjev",
 "state": {"server": "<site>",
           "clients": {
             "203.0.113.66": {"signature_hits": "env-file,vcs-dir",
                              "flagged_requests": ["... \"GET /.env HTTP/1.1\" 404 ...",
                                                   "... \"GET /.git/config HTTP/1.1\" 404 ..."],
                              "other_recent_requests": []},
             "198.51.100.7": {"signature_hits": "wordpress", "flagged_requests": ["..."],
                              "other_recent_requests": ["... \"GET /blog/ HTTP/1.1\" 200 ..."]}}},
 "questions": {
   "c1": {"type": "noul", "instructions": "Is this client probing for or exploiting ...? Judge only client 203.0.113.66 (state.clients[\"203.0.113.66\"]) ...",
          "criteria": {"true": "...", "false": "..."}},
   "c2": {"type": "noul", "instructions": "... Judge only client 198.51.100.7 ..."}}}
```

With `ask_intent = 1`, each client also gets an `i<n>` choice question (`legitimate_visitor`,
`search_crawler`, `vulnerability_scanner`, `exploit_attempt`, `credential_attack`,
`abusive_scraper`); the answer goes in the log.

`answers.c<n>.noul` (a calibrated probability) is the decision for client n, per flagged request:

- `>= threshold` (0.80) is a strike;
- `>= instant_threshold` (0.97) bans at once.

If the API is down, `on_error = rules` falls back to the signatures for that batch.
`mode = rules` never calls a model.

All the clients in a batch share one `state`. A client's log lines could try to talk about
another client, but only clients that already tripped a signature are in a batch.
`batch_clients = 1` keeps every client in a request of its own.

Log lines are written by the attacker. They go to the model as quoted data in `state`, never
as instructions, and the model's answer is a single option letter. The worst a crafted line can
do is argue its own probability down. `override_score = 10` makes the strong signatures (`.env`,
`../`, `${jndi:`, `union select`, sqlmap) count as strikes whatever the model says.

## Signatures (the prefilter)

There are about 30 built-in rules, in `Ban.Signatures.pas`:

- secrets in the web root: `.env`, `.git/`, `.aws/`, `id_rsa`, `wp-config.php.bak`
- path traversal and system files: `../`, `/etc/passwd`
- code execution: log4shell `${jndi:`, shell injection, ThinkPHP and phpunit RCE, webshell names,
  router exploits (`/HNAP1`, `/boaform`, `GponForm`)
- SQL injection, XSS
- admin panels: phpMyAdmin, Tomcat manager, actuator
- WordPress and VPN login probes
- `CONNECT` and proxy probes, TLS bytes sent to plain HTTP
- scanner user agents: sqlmap, nikto, nuclei, zgrab, masscan
- a burst of 4xx responses (`flood_4xx`)

Weights: 10 means never legitimate, 6 means almost always a probe, 3 depends on the site. Add
your own rules with `signatures = /etc/jevban/extra.rules`:

```
# <weight> <url|request|agent|any> <tag> <regex>   (case-insensitive; url is decoded path+query)
10 url  secret-admin  ^/my-hidden-admin
6  agent bad-bot      BadBot/\d
```

## Firewall actions

| `type` | ban | notes |
|---|---|---|
| `iptables` (default) | `-I jevban -s <ip> -j DROP` | own chain hooked on INPUT for `port`; also `ip6tables` |
| `nftables` | `add element inet jevban v4 { <ip> }` | own table with v4/v6 sets |
| `ufw` | `prepend deny from <ip> to any port <port> proto tcp` | |
| `firewalld` | rich rule `drop` | runtime rules only |
| `fail2ban` | `fail2ban-client set <jail> banip <ip>` | hands the ban to an existing fail2ban jail |
| `netsh` | `advfirewall firewall add rule ... action=block` | Windows default |
| `command` | your `actionban`/`actionunban` | tags: `<ip> <v> <family> <fwfamily> <iptables> <name> <port> <jail> <bantime>` |
| `none` | log only | |

How the actions run, and how bans are kept:

- Actions use fail2ban's lifecycle: `actionstart`, then `actionban`/`actionunban`, then
  `actionstop`.
- Bans are kept in `statefile` and re-applied at startup.
- `bantime.increment` doubles a repeat offender's ban, up to `bantime.maxtime`.
- `<ip>` is always an address that parsed as IPv4 or IPv6 and was re-printed, so log text
  never reaches a shell.

## Log formats

The parser reads these formats; it anchors on the `[time]` field, so a vhost prefix needs no
setting:

- Apache `common`, `combined` and `vhost_combined`
- nginx's default `combined`

IPv4 and IPv6 clients are both handled. Behind a reverse proxy, log the real client
(`mod_remoteip`) so `%h` is the client and not the proxy.

`logpath` takes wildcards in the file name. jevban follows logrotate's rename-and-create and its
copytruncate, and it reads whatever was still written to the old file after a rename. Don't
let a pattern match the rotated files (`*.log.1`, `*.gz`).

## Files

| File | |
|---|---|
| `jevban.lpr` | main loop, signals, `--test` |
| `Ban.Config.pas` | `jevban.ini` + command line |
| `Ban.Tail.pas` | tail -F with rotation and wildcards |
| `Ban.Apache.pas` | access-log parser |
| `Ban.Signatures.pas` | the weighted regex prefilter |
| `Ban.Jev.pas` | `/v1/systemone` client, the decider interface |
| `Ban.Local.pas` | OpenJev in-process: model download, prompt, letter readout, calibration |
| `Ban.Llama.pas` | the llama.cpp C API, loaded at run time |
| `Ban.Engine.pas` | per-client context, strikes, bans, state file |
| `Ban.Firewall.pas` | action presets and command runner |
| `Ban.Net.pas` | IPv4/IPv6 + CIDR |
| `Ban.Https.pas` | HTTP(S) client from [memagent](https://github.com/FMXExpress/Short-Long-Memory-LLM): verified TLS, HTTPS_PROXY tunnel, JSON POST |
