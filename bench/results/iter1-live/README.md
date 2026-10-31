# Iteration 1: the daemon no longer stalls while the decider thinks

`bench/live.py --jev-url http://127.0.0.1:3010/v1/systemone` with `MOCK_DELAY=10 tests/mock_jev.py 3010`
(a decider that takes 10 s per client, standing in for a CPU model). Six password guessers keep it
busy (one 60 s batch); five seconds later an obvious scanner probes one known-bad path a second.

| | before: decider on the main loop (67fc863) | after: decider on a worker thread |
|---|---|---|
| scanner banned after | 57.2 s | 2.1 s |
| scanner requests that reached the server | 30 of 30 | 3 |
| guessers' verdicts after | 64.1 s | 64.8 s |
