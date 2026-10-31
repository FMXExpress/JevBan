## Quality

| run | benign clients banned | attackers banned | attack requests caught | recall | precision | leaked/attacker | model clients | wall s |
|---|---|---|---|---|---|---|---|---|
| rules-app-dev | **0/79** | 44/52 | 102/222 | 45.9% | 100.0% | 3.0 | 0 | 0 |
| rules-app-test | **0/79** | 41/51 | 103/233 | 44.2% | 100.0% | 3.0 | 0 | 0 |
| rules-logarx-small | **0/789** | 124/126 | 438/564 | 77.7% | 100.0% | 4.0 | 0 | 7 |
| rules-static-dev | **0/72** | 41/51 | 105/282 | 37.2% | 100.0% | 3.0 | 0 | 0 |
| rules-static-test | **0/72** | 43/52 | 103/238 | 43.3% | 100.0% | 3.0 | 0 | 0 |
| rules-wordpress-dev | **0/73** | 44/52 | 104/236 | 44.1% | 100.0% | 3.0 | 0 | 0 |
| rules-wordpress-test | **0/73** | 44/51 | 103/212 | 48.6% | 100.0% | 3.0 | 0 | 0 |

## Clients banned per category

| category | rules-app-dev | rules-app-test | rules-logarx-small | rules-static-dev | rules-static-test | rules-wordpress-dev | rules-wordpress-test |
|---|---|---|---|---|---|---|---|
| attack:credential | 0/3 | 0/3 |  | 0/3 | 0/3 | 0/3 | 0/3 |
| attack:distributed | 16/16 | 15/15 |  | 15/15 | 16/16 | 16/16 | 15/15 |
| attack:enumeration |  |  | 2/2 |  |  |  |  |
| attack:evasion | 4/4 | 4/4 |  | 4/4 | 4/4 | 4/4 | 4/4 |
| attack:exploit | 5/6 | 4/6 |  | 2/6 | 3/6 | 5/6 | 5/6 |
| attack:injection | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 |
| attack:path_traversal |  |  | 0/0 |  |  |  |  |
| attack:reconnaissance |  |  | 120/122 |  |  |  |  |
| attack:slow | 2/2 | 2/2 |  | 2/2 | 2/2 | 2/2 | 2/2 |
| attack:stealth | 0/3 | 0/3 |  | 0/3 | 0/3 | 0/3 | 0/3 |
| attack:variant | 4/5 | 3/5 |  | 5/5 | 5/5 | 4/5 | 5/5 |
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
| flood | 100000 | 5219 | 40 MB |
| typical | 200000 | 26809 | 9 MB |

## Log formats: the same requests as Apache, nginx JSON and IIS W3C

| format | lines/s | suspicious | strikes | bans |
|---|---|---|---|---|
| apache | 20293 | 2785 | 1640 | 1630 |
| json | 11611 | 2785 | 1640 | 1630 |
| iis | 20075 | 2785 | 1640 | 1630 |
