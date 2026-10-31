# Iteration 5: stealth scanners, uploaded shells

Rules only, all corpora (`bench/run.sh iter5-stealth`). Compared with iteration 4 (`27e7901`):

| split | benign banned | attackers, iter 4 | attackers, iter 5 | attack requests leaked, iter 4 → 5 |
|---|---|---|---|---|
| wordpress-dev | 0/73 | 44/52 | 46/52 | 236 → 227 |
| wordpress-test | 0/73 | 44/51 | 44/51 | 212 → 196 |
| static-dev | 0/72 | 41/51 | 46/51 | 282 → 171 |
| static-test | 0/72 | 43/52 | 48/52 | 238 → 170 |
| app-dev | 0/79 | 44/52 | 45/52 | 222 → 217 |
| app-test | 0/79 | 41/51 | 43/51 | 233 → 216 |
| logarx-small (real) | 0/789 | 124/126 | 126/126 | 564 → 536 |

**File probes.** A 4xx on a path that names code, configuration, data or a backup (`.asp`,
`.php`, `.sql`, `.config`, `.json`, `.bak`, dotfiles ...) is +3, and the third different one
from a client within an hour adds +3 (a strike). Checked on real traffic first: on LogarX every
one of the 130 benign 4xx had no extension. Archives were dropped from the list after a link
checker's dead `/press-kit.zip` drew a strike (benign request precision went back to 100%).
`probe_files = 2` caught one more stealth client on the dev splits; kept at 3, because a site
that moved off PHP gets visitors on old `.php` links and there are no real logs to test that.

**Uploaded shells.** PHP run from an uploads, avatars, attachments or tmp folder is weight 6, so the model decides (a badly built plugin may really run PHP
from uploads/; no real logs yet to rule that out)
(`php-in-uploads`); `name.php.jpg` is weight 6 (`double-extension`). Before, a shell already
on the box under a random name scored nothing.

Stealth scanners: 0/3 → 1–2/3 on WordPress dev and static; still 0/3 on app and WordPress test
(they make only 2–6 file probes in all).

Prefilter throughput in a flood (every line a new address) fell from about 6,000 to about
5,000 lines/s; typical traffic is unchanged at about 36,000. Not yet profiled.
