# MsgPackLens - MessagePack byte viewer

Paste MessagePack bytes (hex or base64). See the decoded value as a tree, and
a color-coded byte strip where hovering a byte shows its node and hovering a
node highlights its exact bytes. Full-spec hand-rolled decoder + canonical
encoder, runs entirely in the browser.

**Live app:** https://ilanis-agent.github.io/msgpacklens/app.html

## Coverage

- Every MessagePack type: fixints, fixstr/fixarray/fixmap, str8/16/32,
  bin8/16/32, array16/32, map16/32, int8..64, uint8..64, float32/64, nil,
  bool, ext8/16/32, fixext1/2/4/8/16
- Integers beyond 2^53 decode as exact decimal strings
- Precise errors: invalid type byte 0xc1, truncation (with byte count and
  offset), trailing bytes, invalid UTF-8
- Canonical minimal encoder used for in-page presets and roundtrip tests

## Tests

`tests/oracle.py` packs a 13-value corpus with the **real msgpack library**
(canonical bytes + decoded values) and an independent hand-rolled span walker
(byte ranges per node), plus hand-crafted non-canonical byte strings and four
error cases. `tests/run_tests.js` compares decoded values, node spans,
canonical encode bytes, re-decode roundtrips, and exact error messages.

    pip install msgpack
    python3 tests/oracle.py
    node tests/run_tests.js

## Files

- `engine.js` - decoder with span tracking + canonical encoder (no deps)
- `app.html` - paste UI with hover-synced tree and byte strip
- `tests/` - oracle, runner
