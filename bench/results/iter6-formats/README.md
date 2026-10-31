# Iteration 6: IIS and JSON logs, big files

Branch `log-formats`, from `main` at `c1eb61d` (iteration 4's rules, without iteration 5).

**Formats.** IIS W3C Extended (any `#Fields:` set; the header is tracked per file, also when it
changes mid-file), JSON lines (nginx `escape=json` with its usual variable names, Caddy, Traefik).
The same 200,000 requests written as Apache, nginx JSON and IIS get identical decisions
(`formats.json`: 2,785 suspicious, 1,640 strikes, 1,630 bans in each). Parse speed on one core:
Apache and IIS about 20–27k lines/s, JSON about 12–14k (a full JSON parse per line).

**Apache unchanged.** Quality on every corpus is identical to `main`; an alternating A/B of
`main` and this branch on the same load files, three runs each: flood 5.7–6.2k vs 5.8–6.1k
lines/s, typical 27.8–29.1k vs 27.1–28.3k (noise).

**Big files**, measured with 1 GB logs:

| | result |
|---|---|
| daemon start on a 1 GB Apache log | 0.28 s, 4 MB RSS (starts at the end) |
| daemon start on a 1 GB IIS log whose only `#Fields:` is at the top | 0.28 s, 4 MB RSS; the header is found by a backward scan (page cache warm; a cold disk reads the file once) and new lines parse |
| `--test` replay of 1 GB Apache (6.4 M lines) | 89 s, 9 MB peak RSS |

The first version capped the header scan at 64 MB, which would have left a big IIS file with a
non-default field set unparsed; the cap is gone.

**Idle files.** IIS starts a new `u_exYYMMDD.log` daily and keeps the old ones, so a wildcard
held a handle on every one of them. Wildcard matches untouched for a day are now skipped, and
a followed one that is fully read and idle for a day is let go; if it is written again it is
picked up where it was, not replayed (checked: handle released, then reopened, no old lines).
