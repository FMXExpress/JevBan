# Iteration 9: Gemini Decision 1 (`provider = gemini`)

Branch `gemini-provider`. Google's Decisions API, `gemini-decision-1`, free tier, run through
jevban's `--eval` on the held-out test splits and the real LogarX log, against rules alone on
the same build. No benign client was banned in any run.

| Split | Benign banned | Rules alone | Gemini, threshold 0.80 | Gemini, threshold 0.50 | Attack requests through (rules → Gemini 0.50) |
|---|---|---|---|---|---|
| WordPress | 0 / 73 | 44 / 51 | 45 / 51 | 46 / 51 | 196 → 175 |
| Static site | 0 / 72 | 48 / 52 | 47 / 52 | 49 / 52 | 170 → 160 |
| Web app | 0 / 79 | 43 / 51 | 43 / 51 | 44 / 51 | 216 → 214 |
| LogarX (real) | 0 / 789 | 126 / 126 | 126 / 126 | 126 / 126 | 536 → 457 |

What Gemini adds at 0.50: two password guessers on WordPress and one stealth scanner each on the
static site and the web app, which the rules cannot separate from ordinary use.

**The threshold was chosen on the dev splits, not the test splits.** At jevban's default (0.80,
set for OpenJev Flash 9B) Gemini added one attacker and lost one: its probabilities for some real
attackers sit at 0.57–0.79. On the dev splits (`gemini-t80-*-dev.json`, run at 0.80 so that every
judged client's probability is in the log), no benign client scored above 0.26 (80 judged) and
most attackers 0.8–0.99, with a few password guessers, stealth scanners and a distributed scan at
0.40–0.71. So the preset uses 0.50 for a strike and 0.30 for REVIEW; the test splits were run
once at those settings. On LogarX, 22 clients fell in the REVIEW band (p 0.30–0.47): 3
reconnaissance attackers and 19 benign crawlers, API clients and browsers; none was banned.

**Against OpenJev Flash 9B on the same build** (local, 4-core CPU, threshold 0.80;
`flash-*.json`):

| Split | Benign banned (Gemini / Flash) | Attackers (rules / Gemini 0.50 / Flash) | Requests through (Gemini / Flash) | Wall clock (Gemini / Flash) |
|---|---|---|---|---|
| WordPress | 0 / 0 | 44 / 46 / 47 | 175 / 179 | 128 s / 26 min |
| Static site | **0 / 1** | 48 / 49 / 49 | 160 / 164 | 18 s / 7.5 min |
| Web app | 0 / 0 | 43 / 44 / 44 | 214 / 239 | 100 s / 12 min |

Flash banned one benign client on the static site: an uptime monitor (`Go-http-client`, `GET /`
every five minutes, 200) that it scored 0.80–0.84 on five separate requests, each a fresh
verdict and so a strike of its own; the site description mentions a monitor that uses curl.
Gemini scored it low. jevban has no guard against a model striking a client whose only flagged
trait is its user agent on successful page loads; that is the next thing to fix, separately.
Flash caught one more password guesser on WordPress; otherwise the two ban the same attackers.

**Speed and cost.** 18–223 s per split, about 0.4–0.5 s per batch; the local Flash 9B on a
4-core CPU takes 14–48 minutes per split. The free tier's 50,000 input tokens a minute was the
limit: the first run sent 18–111 batches per split to the rules on HTTP 429, which jevban now
waits out (see the PR); with the retries, 0 errors. On the paid tier ($0.10 per million input
tokens) a client costs roughly 400–800 tokens, a few cents per thousand clients judged.

**Not measured here:** the service's own latency under load, and accuracy on real traffic beyond
LogarX (where the rules alone already ban every attacker).
