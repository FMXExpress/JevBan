# Iteration 10: no strike for a user agent alone

Branch `agent-only-guard`, from `main` at `be61319`.

**The false ban.** In iteration 9, OpenJev Flash 9B banned an uptime monitor on the static-site
split: `Go-http-client`, `GET /` every five minutes, 200. Its only flagged trait was its user
agent (`script-agent`, weight 3), and the model scored five separate requests at 0.80–0.84, each
a fresh verdict and so a strike of its own.

**The guard.** A request whose only signature hits come from user-agent rules, and that was
answered below 400, gets at most REVIEW from a model verdict (logged `user agent only: no
strike`). A user agent is an identity, not an act. Hard rules, rules mode, and any request with
evidence of its own (a 4xx, a login, a known path, a payload a signature knows) are unchanged.

| | Benign banned | Attackers | Attack requests through |
|---|---|---|---|
| Flash 9B, static site, before | 1 / 72 | 49 / 52 | 164 |
| Flash 9B, static site, with the guard | **0 / 72** | 49 / 52 | 160 |
| Gemini, WordPress / static / web app | 0 / 0 / 0 | 46 / 49 / 44 (unchanged) | 175 / 160 / 214 (unchanged) |
| Gemini, LogarX | 0 / 789 | 126 / 126 | 457 → 458 |

**What evaluating it turned up.** On LogarX the guard first held back a real SQL injection
attacker: `" AND 1=1--` and `" AND 1=(SELECT ...)` in a search query slipped the `sqli`
signature, which knew only the single-quote form, so the requests looked like a Go client and
nothing else, and Gemini's 0.99 became REVIEW. Narrowing the guard (say, to requests without a
query string) would have exposed benign API clients polling `/api/stock?id=` that Gemini puts
at 0.52–0.58. The fix is the signature: `sqli` now takes double quotes and `and n=(select`;
`shell-inject` takes `id`, `whoami`, `uname`, `hostname`, `ifconfig`, `ping`; a new
`template-inject` rule (weight 10) takes `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` and `{{config}}`-style
probes. Rules alone: unchanged on every synthetic split, LogarX 438 → 440 attack requests caught,
still 0 benign. The one extra request through on LogarX is that attacker's ordinary page view
(`/p/8`), which carries no evidence of its own.

**Also fixed.** The strike label counted expired strikes ("strike 3/3" with no ban); it now
counts only strikes inside findtime.

**Deterministic test** (`tests/guard_access.log`, mock at `MOCK_P=0.95`, a model sure of
everyone; in CI): `main` bans the monitor, the password guesser and the `curl` prober; this
branch bans the last two and logs the monitor as REVIEW.
