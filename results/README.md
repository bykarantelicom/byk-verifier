# Verification runs

One line per run of `byk-verify.mjs` from GitHub Actions (`.github/workflows/verify.yml`): daily RESUMED runs from the committed
checkpoint and, on Sundays, a FULL run from sequence 0. The JSON of each run sits next to this file; `state/checkpoint.json` is the
reader checkpoint the next run continues from. A RESUMED run is not the full rc6 13.7 verdict: sequences before the checkpoint rely
on the run that wrote it.

| as of (UTC) | mode | verdict | sequences | head | Base witness | exit |
|---|---|---|---|---|---|---|
