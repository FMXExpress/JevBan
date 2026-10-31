# Iterations 2-3: the model micro benchmark

`bench/make_micro.py bench/corpus/wordpress-dev.log bench/corpus/micro.log`: every request of 8 clients
that reach the decider (a password guesser, a stealth scanner, a prompt-injecting client, a plugin
prober, a variant scanner, the site owner, an uptime monitor, a link checker). Flash 9B Q4_K_M on 4
cores (AVX-512), `--eval` with `bench/corpus/wordpress.ini`.

| | before (bc4742b: AVX2 build, 3 threads) | after |
|---|---|---|
| wall time | 15 min 50 s | 2 min 26 s |
| model requests | 18 | 7 |
| attackers banned | 3 of 5 | 4 of 5 |
| attack requests that reached the server | 48 | 31 |
| benign clients banned | 0 of 3 | 0 of 3 |
| benign requests struck | 0 | 2 (the owner's first look, p=0.80; capped below a ban) |

One 250-token prompt: 26.7 s (AVX2, 3 threads) -> 18.4 s (4 threads) -> 13.2 s (CPU variants, 4
threads; a native build: 11.8 s).
