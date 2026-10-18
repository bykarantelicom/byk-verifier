# Verification runs

One line per run of `byk-verify.mjs` from GitHub Actions (`.github/workflows/verify.yml`): daily RESUMED runs from the committed
checkpoint and, on Sundays, a FULL run from sequence 0. The JSON of each run sits next to this file; `state/checkpoint.json` is the
reader checkpoint the next run continues from. A RESUMED run is not the full rc6 13.7 verdict: sequences before the checkpoint rely
on the run that wrote it. From 19 Oct 2026 the daily run carries the rc6 13.7 cache proof (`--cache-proof`): when every data witness
key before the checkpoint lists the same newest transaction the checkpoint recorded (or only failed and inadmissible ones after
it), the cached sequences are provably unchanged and the line says "full, cache proof held".

| as of (UTC) | mode | verdict | sequences | head | Base witness | exit |
|---|---|---|---|---|---|---|
| 2026-10-18 14:59 | bootstrap (from the 20 Sep full run's sequence 631, ByKaranteli's server, Solana archive RPC) | PASS (resumed) | 8119 of 8119 CANONICAL | head 8750 | Base throttled | exit 0 |
| 2026-10-18 15:09 | incremental | PASS (resumed) | 18 of 18 CANONICAL | head 8768 | Base incomplete | exit 0 |
| 2026-10-18 15:59 | full (ByKaranteli's server, Solana archive RPC) | PASS (full) | 8751 of 8751 CANONICAL | head 8750 | Base throttled | exit 0 |
| 2026-10-18 20:27 | incremental | PASS (resumed) | 64 of 64 CANONICAL | head 8832 | Base complete, copies 2 of 2 | exit 0 |
