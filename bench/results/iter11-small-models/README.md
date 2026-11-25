# Iteration 11: small decision models (Julia 1, OpenDecider-nano, TinyJev 0.6B)

Three small open models that answer Jev-style typed questions, each served over `POST /v1/systemone`
on this machine (4-core CPU) and asked by jevban with one client per request (`batch_clients = 1`, as
their authors benchmarked them), with jevban's own question and criteria unchanged:

| Model | Size | Served by |
|---|---|---|
| [Julia 1](https://huggingface.co/SupersonicLabs/Julia-1) (Supersonic Labs, mmBERT-small encoder) | 144M | its reference package through `bench/shims/julia_systemone.py`: llama.cpp's own GGUF (`ggml-org/Julia-1-GGUF`) does not load in current llama.cpp ("metaspace prepend_scheme 'always' is not supported for BPE vocab") |
| [OpenDecider-nano](https://huggingface.co/manjunathshiva/opendecider-nano) (Ettin-400m encoder) | ~400M | `opendecider serve` |
| [TinyJev 0.6B](https://huggingface.co/AnkitAI/TinyJev-0.6B) (Qwen3-0.6B decoder + pointer head) | 596M | `tinyjev serve` (PyTorch, CPU) |

Laya multilingual (322M) was left out: its own card puts it near chance without fine-tuning (0.342
against 0.318 random on typed decisions).

## Dev splits: can a threshold separate attackers from benign clients?

Each client's highest probability, at jevban's default threshold (0.80), from `bench/pdist.py`:

| Model | Highest benign P(attack) (WordPress / static / app) | Attackers' P(attack), middle half |
|---|---|---|
| Julia 1 | **1.00** / 1.00 / **1.00** | 0.92–1.00 |
| OpenDecider-nano | 0.78 / 0.76 / 0.87 | 0.48–0.85 |
| TinyJev 0.6B | 0.45 / 0.64 / 0.60 | 0.30–0.71 |
| Gemini Decision 1 (iteration 9) | 0.26 | 0.8–0.99 |

None separates them the way Gemini does. The threshold each was given for the test splits is the
lowest above its highest benign dev score: OpenDecider 0.88, TinyJev 0.65; Julia has none (benign
clients reach 1.00), so it ran at the default 0.80.

## Held-out test splits and LogarX

| | Rules alone | Julia 1 (0.80) | OpenDecider-nano (0.88) | TinyJev 0.6B (0.65) | Gemini (iteration 9) |
|---|---|---|---|---|---|
| WordPress: benign banned / attackers | 0 / 44 | **56** / 47 | 0 / 43 | 0 / 43 | 0 / 46 |
| Static site: benign / attackers | 0 / 48 | **1** / 48 | 0 / 45 | 0 / 46 | 0 / 49 |
| Web app: benign / attackers | 0 / 43 | **1** / 45 | 0 / 42 | 0 / 42 | 0 / 44 |
| LogarX: benign / attackers | 0 / 126 | 0 / 126 | 0 / 124 | 0 / 124 | 0 / 126 |
| LogarX: attack requests through | 536 | 351 | 671 | 671 | 457 |

- **Julia 1 bans visitors**: 55 WordPress visitors and the site's owner, a link checker and an API
  client. It caught three password guessers and three stealth scanners too, but scores nearly
  everything as an attack.
- **OpenDecider-nano and TinyJev 0.6B are worse than the rules alone.** With a model, jevban hands the
  borderline clients to it instead of striking them by rule, and these two pass exploit, stealth,
  plugin and reconnaissance probers the rules would have banned: 1–3 fewer attackers per site, and
  25% more attack requests through on LogarX.

**None of the three is supported.** What this measures is these models on jevban's task as jevban asks
it; another wording, or fine-tuning on labelled attack logs (the Laya audit puts it at thousands of
in-domain examples), might change it. Time per split: 7–216 s, against 18–128 s for Gemini and 7–26
minutes for OpenJev Flash 9B.

Files: `<model>-<split>.json` (`--eval-json`), `<model>-<split>.log.gz` (the decisions; LogarX logs
are left out, as its data is not redistributed). Reproduce with `bench/server_eval.sh` against each
model's server, and `bench/pdist.py bench/results/iter11-small-models <model> <splits>`.
