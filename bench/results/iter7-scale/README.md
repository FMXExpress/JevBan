# Iteration 7: scale

Branch `scale`, from `main` at `cab6cc3`. The gate for every CPU change: each decision line
identical to `main` (a `-v` diff on the flood and typical load files, all synthetic corpora and
LogarX), not only the totals. All identical.

## Prefilter (callgrind, then measured)

40,000 flood lines: 38.0 → 3.4 billion instructions.

| Change | Flood lines/s | Typical lines/s |
|---|---|---|
| `main` | 6,000 | 28,000–39,000 |
| clients in a hash map (`Ban.Hash`), not a sorted string list | 6,150 | 38,800 |
| near-known-bad: BK-tree distances bounded at MaxKid + allowance, Levenshtein rows on the stack, results cached per path | 8,600 | 41,400 |
| signature results cached per field value (bit set of matched rules; tags rebuilt in rule order) | 21,200 | 86,500 |
| slow-scanner and subnet tables in hash maps; Apache tokens as spans; decode fast paths; time parsed once per second | 33,400 | 175,600 |
| summaries by concatenation, the log summary only for logged lines; range checks off again in `Ban.Hash` | 35,000–36,000 | 200,000–208,000 |

The caches are bounded: values over 512 characters are not cached, the signature caches start
over at 20,000 values per field and the near-miss cache at 50,000 paths.

Clients (500,000 distinct addresses, `--test`):

| `max_clients` | `main` | this branch |
|---|---|---|
| 20,000 | 10,500 lines/s, 87 MB | 40,300 lines/s, 79 MB |
| 100,000 | 9,400 lines/s, 204 MB | 41,100 lines/s |
| 500,000 | 9,300 lines/s, 814 MB | 59,000 lines/s, 486 MB |

Per-client lists (scan paths, probe paths, judged tags, pending lines) are created on first use.

## Ban storms (real ipset, iptables and nftables in the container)

2,000 addresses each earning an instant ban, then one more scanner:

| | `main` | this branch |
|---|---|---|
| last scanner banned (log) | 68 s (ipset), 76 s (iptables), 83 s (nftables) | 0.12 s |
| all 2,001 in the firewall | same | 0.12–0.17 s |

Each ban ran `/bin/sh` and the firewall tool on the thread that reads the log, and saved the
whole state file. Firewall commands now run on their own thread and go in batches (one `ipset
restore`, `nft -f` or `iptables-restore` per batch; a failed batch is retried one by one, so
each failure is reported for its address); the state is saved at most once a second.
Checked as well: 500 IPv4 + 500 IPv6 bans in and out again on expiry with no errors, a restart
restoring 1,000 bans in one batch (ready in 0.08–0.11 s), and a forced batch failure (an
address removed by hand) falling back correctly.

## The model under load

300 password-guessing clients at once, mock decider at 0.5 s per client (4 s per batch):
`main` decided the last one after 150 s (with Flash 9B on a CPU, about 1.5 hours, every client
held in memory meanwhile). With `decider_backlog = 4` the model took 44 and the rules decided
the other 256 at once: all decided in 22 s. Only verdicts the model gave are cached, so those
clients reach the model with their next flagged request.

## Not done

- JSON logs: about 20,000 lines/s (fpjson builds a tree per line); IIS about 55,000.
- The decider queue's `Delete(0)` is quadratic in its length (0.1 s at 10,000 queued).
