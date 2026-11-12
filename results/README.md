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
| 2026-10-18 22:52 | full | PASS (full) | 8860 of 8860 CANONICAL | head 8859 | Base complete, copies 34 of 34 | exit 0 |
| 2026-10-19 08:05 | incremental | PASS (full, cache proof held) | 112 of 112 CANONICAL | head 8971 | Base complete, copies 1 of 1 | exit 0 |
| 2026-10-20 11:19 | incremental | PASS (full, cache proof held) | 327 of 327 CANONICAL | head 9298 | Base complete, copies 1 of 1 | exit 0 |
| 2026-10-21 06:57 | incremental | PASS (full, cache proof held) | 236 of 236 CANONICAL | head 9534 | Base complete, copies 1 of 1 | exit 0 |
| 2026-10-22 06:59 | incremental | PASS (full, cache proof held) | 288 of 288 CANONICAL | head 9822 | Base complete, copies 1 of 1 | exit 0 |
| 2026-10-22 16:11 | incremental | PASS (full, cache proof held) | 111 of 111 CANONICAL | head 9933 | Base complete, copies 0 of 0 | exit 0 |
| 2026-10-23 06:59 | incremental | PASS (full, cache proof held) | 177 of 177 CANONICAL | head 10110 | Base complete, copies 1 of 1 | exit 0 |
| 2026-10-24 07:00 | incremental | PASS (full, cache proof held) | 288 of 288 CANONICAL | head 10398 | Base complete, copies 1 of 1 | exit 0 |
| 2026-10-25 07:46 | full | PASS (full) | 10695 of 10695 CANONICAL | head 10694 | Base complete, copies 41 of 41 | exit 0 |
| 2026-10-26 07:02 | incremental | PASS (full, cache proof held) | 281 of 281 CANONICAL | head 10975 | Base complete, copies 1 of 1 | exit 0 |
| 2026-10-27 07:04 | incremental | PASS (full, cache proof held) | 288 of 288 CANONICAL | head 11263 | Base complete, copies 1 of 1 | exit 0 |
| 2026-10-28 07:04 | incremental | PASS (full, cache proof held) | 288 of 288 CANONICAL | head 11551 | Base complete, copies 1 of 1 | exit 0 |
| 2026-10-29 07:05 | incremental | PASS (full, cache proof held) | 288 of 288 CANONICAL | head 11839 | Base complete, copies 1 of 1 | exit 0 |
| 2026-10-30 07:06 | incremental | PASS (full, cache proof held) | 289 of 289 CANONICAL | head 12128 | Base complete, copies 1 of 1 | exit 0 |
| 2026-10-31 07:07 | incremental | PASS (full, cache proof held) | 288 of 288 CANONICAL | head 12416 | Base complete, copies 1 of 1 | exit 0 |
| 2026-11-01 08:00 | full | PASS (full) | 12713 of 12713 CANONICAL | head 12712 | Base complete, copies 48 of 48 | exit 0 |
| 2026-11-02 07:09 | incremental | PASS (full, cache proof held) | 280 of 280 CANONICAL | head 12992 | Base complete, copies 1 of 1 | exit 0 |
| 2026-11-03 07:10 | incremental | PASS (full, cache proof held) | 288 of 288 CANONICAL | head 13280 | Base complete, copies 1 of 1 | exit 0 |
| 2026-11-04 07:11 | incremental | PASS (full, cache proof held) | 289 of 289 CANONICAL | head 13569 | Base complete, copies 1 of 1 | exit 0 |
| 2026-11-05 06:59 | incremental | PASS (resumed, cache proof not held: the proof stopped on an endpoint error: 500 Internal Server Error: Int) | 285 of 285 CANONICAL | head 13854 | Base complete, copies 1 of 1 | exit 0 |
| 2026-11-06 07:17 | incremental | PASS (full, cache proof held) | 291 of 291 CANONICAL | head 14145 | Base complete, copies 0 of 1 (1 missing) | exit 0 |
| 2026-11-07 07:17 | incremental | PASS (full, cache proof held) | 288 of 288 CANONICAL | head 14433 | Base complete, copies 0 of 1 (1 missing) | exit 0 |
| 2026-11-08 08:56 | full | PASS (full) | 14732 of 14732 CANONICAL | head 14731 | Base incomplete, copies 0 of 55 (4 missing) (51 not walked) | exit 0 |
| 2026-11-09 09:04 | incremental | PASS (full, cache proof held) | 14782 of 14782 CANONICAL | head 15019 | Base incomplete, copies 0 of 52 (17 missing) (35 not walked) | exit 0 |
| 2026-11-10 08:48 | incremental | PASS (full, cache proof held) | 10171 of 10171 CANONICAL | head 15304 | Base incomplete, copies 0 of 36 (17 missing) (19 not walked) | exit 0 |
| 2026-11-11 06:40 | full | PASS (full) | 15579 of 15579 CANONICAL | head 15578 | Base complete, copies 58 of 58 | exit 0 |
| 2026-11-12 07:19 | incremental | PASS (full, cache proof held) | 296 of 296 CANONICAL | head 15874 | Base complete, copies 1 of 1 | exit 0 |
