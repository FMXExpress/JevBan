## Quality

| run | benign clients banned | attackers banned | attack requests caught | recall | precision | leaked/attacker | model clients | wall s |
|---|---|---|---|---|---|---|---|---|
| rules-app-dev | **0/79** | 45/52 | 107/217 | 49.3% | 100.0% | 3.0 | 0 | 0 |
| rules-app-test | **0/79** | 43/51 | 109/216 | 50.5% | 100.0% | 3.0 | 0 | 0 |
| rules-logarx-small | **0/789** | 126/126 | 438/536 | 81.7% | 100.0% | 4.0 | 0 | 3 |
| rules-static-dev | **0/72** | 46/51 | 121/171 | 70.8% | 100.0% | 3.0 | 0 | 0 |
| rules-static-test | **0/72** | 48/52 | 120/170 | 70.6% | 100.0% | 3.0 | 0 | 0 |
| rules-wordpress-dev | **0/73** | 46/52 | 108/227 | 47.6% | 100.0% | 3.0 | 0 | 0 |
| rules-wordpress-test | **0/73** | 44/51 | 102/196 | 52.0% | 100.0% | 3.0 | 0 | 0 |

## Clients banned per category

| category | rules-app-dev | rules-app-test | rules-logarx-small | rules-static-dev | rules-static-test | rules-wordpress-dev | rules-wordpress-test |
|---|---|---|---|---|---|---|---|
| attack:credential | 0/3 | 0/3 |  | 3/3 | 3/3 | 0/3 | 0/3 |
| attack:distributed | 16/16 | 15/15 |  | 15/15 | 16/16 | 16/16 | 15/15 |
| attack:enumeration |  |  | 2/2 |  |  |  |  |
| attack:evasion | 4/4 | 4/4 |  | 4/4 | 4/4 | 4/4 | 4/4 |
| attack:exploit | 5/6 | 4/6 |  | 2/6 | 3/6 | 5/6 | 5/6 |
| attack:injection | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 |
| attack:path_traversal |  |  | 0/0 |  |  |  |  |
| attack:reconnaissance |  |  | 122/122 |  |  |  |  |
| attack:slow | 2/2 | 2/2 |  | 2/2 | 2/2 | 2/2 | 2/2 |
| attack:stealth | 0/3 | 0/3 |  | 2/3 | 2/3 | 1/3 | 0/3 |
| attack:variant | 5/5 | 5/5 |  | 5/5 | 5/5 | 5/5 | 5/5 |
| attack:wordlist | 8/8 | 8/8 |  | 8/8 | 8/8 | 8/8 | 8/8 |
| attack:wp-plugins | 3/3 | 3/3 |  | 3/3 | 3/3 | 3/3 | 3/3 |
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
| flood | 100000 | 30170 | 43 MB |
| typical | 200000 | 144075 | 9 MB |

## Log formats: the same requests as Apache, nginx JSON and IIS W3C

| format | lines/s | suspicious | strikes | bans |
|---|---|---|---|---|
| apache | 146181 | 2017 | 1762 | 1720 |
| json | 91189 | 2017 | 1762 | 1720 |
| iis | 128070 | 2017 | 1762 | 1720 |
