## Quality

| run | benign clients banned | attackers banned | attack requests caught | recall | precision | leaked/attacker | model clients | wall s |
|---|---|---|---|---|---|---|---|---|
| rules-app-dev | **0/79** | 22/52 | 108/288 | 37.5% | 100.0% | 3.0 | 0 | 0 |
| rules-app-test | **0/79** | 21/51 | 109/297 | 36.7% | 100.0% | 3.0 | 0 | 0 |
| rules-logarx-small | **0/789** | 124/126 | 443/571 | 77.6% | 100.0% | 4.0 | 0 | 5 |
| rules-static-dev | **0/72** | 17/51 | 103/388 | 26.5% | 100.0% | 3.0 | 0 | 0 |
| rules-static-test | **0/72** | 20/52 | 107/300 | 35.7% | 100.0% | 3.0 | 0 | 0 |
| rules-wordpress-dev | **0/73** | 23/52 | 110/296 | 37.2% | 100.0% | 3.0 | 0 | 0 |
| rules-wordpress-test | **0/73** | 24/51 | 109/271 | 40.2% | 100.0% | 3.0 | 0 | 0 |

## Clients banned per category

| category | rules-app-dev | rules-app-test | rules-logarx-small | rules-static-dev | rules-static-test | rules-wordpress-dev | rules-wordpress-test |
|---|---|---|---|---|---|---|---|
| attack:credential | 0/3 | 0/3 |  | 0/3 | 0/3 | 0/3 | 0/3 |
| attack:distributed | 0/16 | 1/15 |  | 1/15 | 0/16 | 0/16 | 1/15 |
| attack:enumeration |  |  | 2/2 |  |  |  |  |
| attack:evasion | 4/4 | 4/4 |  | 4/4 | 4/4 | 4/4 | 4/4 |
| attack:exploit | 5/6 | 4/6 |  | 2/6 | 3/6 | 5/6 | 5/6 |
| attack:injection | 0/2 | 0/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| attack:path_traversal |  |  | 0/0 |  |  |  |  |
| attack:reconnaissance |  |  | 120/122 |  |  |  |  |
| attack:slow | 0/2 | 0/2 |  | 0/2 | 0/2 | 0/2 | 0/2 |
| attack:stealth | 0/3 | 0/3 |  | 0/3 | 0/3 | 0/3 | 0/3 |
| attack:variant | 4/5 | 2/5 |  | 2/5 | 5/5 | 4/5 | 5/5 |
| attack:wordlist | 8/8 | 8/8 |  | 8/8 | 8/8 | 8/8 | 8/8 |
| attack:wp-plugins | 1/3 | 2/3 |  | 0/3 | 0/3 | 2/3 | 1/3 |
| benign:api | 0/6 | 0/6 |  |  |  |  |  |
| benign:api_call |  |  | 0/23 |  |  |  |  |
| benign:authentication |  |  | 0/2 |  |  |  |  |
| benign:browsing |  |  | 0/542 |  |  |  |  |
| benign:crawler | 0/8 | 0/8 |  | 0/8 | 0/8 | 0/8 | 0/8 |
| benign:crawling |  |  | 0/222 |  |  |  |  |
| benign:linkchecker | 0/2 | 0/2 |  | 0/2 | 0/2 | 0/2 | 0/2 |
| benign:monitor | 0/2 | 0/2 |  | 0/2 | 0/2 | 0/2 | 0/2 |
| benign:owner | 0/1 | 0/1 |  |  |  | 0/1 | 0/1 |
| benign:static_asset |  |  | 0/0 |  |  |  |  |
| benign:visitor | 0/60 | 0/60 |  | 0/60 | 0/60 | 0/60 | 0/60 |

## Prefilter throughput (rules, one core)

| log | lines | lines/s | peak RSS |
|---|---|---|---|
| flood | 100000 | 7261 | 26 MB |
| typical | 200000 | 15621 | 10 MB |
