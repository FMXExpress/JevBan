# Iteration 8: JSON logs

Branch `json-fast`, from `main` at `7fad043`.

| one core, `--test`, rules | `main` | this branch |
|---|---|---|
| nginx JSON, 200,000 lines | 19,000–21,000 lines/s | 91,000–100,000 |
| IIS W3C, 200,000 lines | 54,000–59,000 | 127,000–150,000 |
| Apache text | 137,000–149,000 | unchanged |
| flood | 32,000–37,000 | unchanged |

Every decision line (`-v`) is identical to `main` on the JSON, IIS, typical and flood files,
and the three formats agree with each other (`formats.json`).

**What changed.** fpjson built an object tree for every line. A JSON line is now read by a
small scanner into a flat node list (key, kind, text, parent) in one pass, and the field
extraction (key aliases, Caddy's nested request and header arrays, Traefik's address with a
port) reads that list. A line the scanner does not take exactly as fpjson would (a surrogate
`\u` escape, a key twice in one object, nesting deeper than 16, `-0` or leading zeros, an
integer over 18 digits, text after the object) goes to fpjson, whose tree is turned into the
same node list, so there is one extraction path. Then the two costs around it:
`ApacheEscape` returns its input when there is nothing to escape (nearly always) and writes in
place otherwise, and the line time is formatted once per second.

**Checked against fpjson.** On all 200,007 lines of the JSON benchmark file and the fixtures,
the scanner's node list equals fpjson's, line by line (numbers compared by value: the scanner
keeps them as written, its readers parse them with `TryStrToFloat` or `StrToIntDef`, which
give the same result from either). Unit tests cover escapes, nesting, arrays, numbers, and the
lines left to fpjson; `ApacheEscape` is checked on all 256 byte values.

**One deliberate difference: non-ASCII.** fpjson turned raw UTF-8 into `?` and stray bytes,
and `é` into a single ANSI byte. The scanner keeps raw bytes and writes `\u` escapes
above ASCII as UTF-8, which `ApacheEscape` then logs as `\xhh`, as Apache does. nginx's
`escape=json` only writes `\u00XX` for control characters, where both agree.
