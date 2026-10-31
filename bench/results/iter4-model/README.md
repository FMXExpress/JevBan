# Iteration 4: Flash 9B on the held-out test splits

Build `61ff7ba` (worker-thread decider, CPU-variant llama.cpp libraries, pass cache, compact
prompts, logged-in rule, strike cap). 4-core CPU, `MODEL=flash-9b bench/run.sh iter4-model`.

| split | benign clients banned | attackers, rules | attackers, rules + model | model prompts | s/prompt | wall |
|---|---|---|---|---|---|---|
| wordpress-test | 0/73 | 44/51 | 47/51 | 137 | 20.9 | 48 min |
| static-test | 0/72 | 43/52 | 46/52 | 46 | 17.4 | 14 min |
| app-test | 0/79 | 41/51 | 43/51 | 76 | 17.1 | 22 min |

What the model adds: the password guessers (3/3 on WordPress and static, 0/3 on the app, whose
login looks like its API traffic), and one to three exploit or variant probers per split.
Still missed by everything: `stealth` (0/3 per split), scanners whose probes sit between
ordinary page views on paths no list knows.

Request-level recall in the model runs counts only the requests the eval scored before each
ban, so it is not comparable with the rules-only column; compare clients.
