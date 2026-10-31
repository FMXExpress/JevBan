## Quality

| run | benign clients banned | attackers banned | attack requests caught | recall | precision | leaked/attacker | model clients | wall s |
|---|---|---|---|---|---|---|---|---|
| rules-app-dev | **0/79** | 22/52 | 108/288 | 37.5% | 100.0% | 3.0 | 0 | 0 |
| rules-app-test | **0/79** | 21/51 | 109/297 | 36.7% | 100.0% | 3.0 | 0 | 0 |
| rules-static-dev | **0/72** | 17/51 | 103/388 | 26.5% | 100.0% | 3.0 | 0 | 0 |
| rules-static-test | **0/72** | 20/52 | 107/300 | 35.7% | 100.0% | 3.0 | 0 | 0 |
| rules-wordpress-dev | **0/73** | 23/52 | 110/296 | 37.2% | 100.0% | 3.0 | 0 | 0 |
| rules-wordpress-test | **0/73** | 24/51 | 109/271 | 40.2% | 100.0% | 3.0 | 0 | 0 |

## Clients banned per category

| category | rules-app-dev | rules-app-test | rules-static-dev | rules-static-test | rules-wordpress-dev | rules-wordpress-test |
|---|---|---|---|---|---|---|
| attack:credential | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| attack:distributed | 0/16 | 1/15 | 1/15 | 0/16 | 0/16 | 1/15 |
| attack:evasion | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 |
| attack:exploit | 5/6 | 4/6 | 2/6 | 3/6 | 5/6 | 5/6 |
| attack:injection | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| attack:slow | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| attack:stealth | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| attack:variant | 4/5 | 2/5 | 2/5 | 5/5 | 4/5 | 5/5 |
| attack:wordlist | 8/8 | 8/8 | 8/8 | 8/8 | 8/8 | 8/8 |
| attack:wp-plugins | 1/3 | 2/3 | 0/3 | 0/3 | 2/3 | 1/3 |
| benign:api | 0/6 | 0/6 |  |  |  |  |
| benign:crawler | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 |
| benign:linkchecker | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| benign:monitor | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| benign:owner | 0/1 | 0/1 |  |  | 0/1 | 0/1 |
| benign:visitor | 0/60 | 0/60 | 0/60 | 0/60 | 0/60 | 0/60 |

## Prefilter throughput (rules, one core)

| log | lines | lines/s | peak RSS |
|---|---|---|---|
| flood | 100000 | 7108 | 26 MB |
| typical | 200000 | 15711 | 10 MB |
