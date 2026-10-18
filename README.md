# byk-verifier

Verify ByKaranteli's on-chain data layer yourself: spec, TypeScript library, Python reference, vectors.

The BYK Data Layer seals derived crypto market records (composite funding, aggregate open interest,
five-minute liquidation totals and the largest print, spot depth, whale prints, flow toxicity, Turkey and
Kimchi premiums, derivatives pressure, tokenized stocks, exchange insurance funds, venue withdrawal switches
and two daily records; 128 records per epoch since catalog beta-0.5, 11 Oct 2026) into a
Merkle root every five minutes, signs the manifest and writes the commitment to Solana, and once a day
to Base through the Ethereum Attestation Service. The verifier reads only the two chains, never our API or
database; it works on the public endpoints, and a free keyed endpoint of your own makes it fast (Solana) and
lets it read the Base copies in minutes (Base). The public Proof API at https://bykaranteli.com/api/v1/proof
serves the records and the audit paths the example reads.

## What is in this repository

| Path | What |
|---|---|
| `spec/BYK_Data_Layer_Protocol_v1.0.0-rc6.md` | The protocol, byte by byte (canonical encoding, leaf layout, Merkle rules, anchors, audit levels) |
| `spec/rc7-feedback-20260920.md` | Implementation notes fed back into the next revision |
| `ts/` | The TypeScript library used in production: encoding, records, funding composite, witness keys, audit, authorization log, the beta-profile rule for which manifests get a Base copy, with conformance tests; `ts/byk-chain/` reads the two chains (with tests against a fake JSON-RPC) and `ts/byk-verify.ts` is the verifier's source |
| `python/byk_ref.py` | Reference implementation, Python standard library only |
| `python/byk_xcheck.py` | Cross-checks the Python reference against the vectors |
| `vectors/byk_v1_test_vectors.json` | Test vectors (Section 17 of the spec) |
| `byk-verify.mjs` | The one-file independent verifier (also served at https://bykaranteli.com/byk-verify.mjs); built from `ts/byk-verify.ts` with viem and @solana/web3.js bundled |
| `.github/workflows/verify.yml` | Runs the verifier every day outside ByKaranteli's servers and commits each verdict to `results/` ([runs](https://github.com/bykarantelicom/byk-verifier/actions/workflows/verify.yml)) |
| `results/`, `state/` | The verdict of every run (the Base column counts the expected Base copies found) and the reader checkpoint the next daily run continues from |
| `examples/tamper.ts` | Reads one proof from the public Proof API, folds it to the signed root, then repeats with the value moved by one unit |

## Run the verifier

```
node byk-verify.mjs --stream <stream id> [--network mainnet|devnet] [--to <sequence>] [--json]
                    [--solana-rpc <url>] [--base-rpc <url>] [--base-scan windows|range] [--base-from-block <n>] [--no-base]
                    [--base-extension-hours <h>] [--checkpoint <file>] [--checkpoint-out <file>] [--help]
```

The stream id of the public stream is `46b69e107bc75175e86a336662311c6e198bbf0dab271c06bc5248888238f66d` (BYK.DATALAYER.BETA1,
genesis 17 Sep 2026 23:50 UTC); it is the one value a verifier takes out of band, pin it from a source you trust.

`--network` defaults to mainnet. The Solana endpoint must keep full history: the default
(`https://api.mainnet-beta.solana.com`) serves from block 0, while a fast pruned endpoint such as
PublicNode keeps about two days and the verifier then reports that an older anchor's absence proves
nothing (INCOMPLETE), never CANONICAL. `SOLANA_RPC_URL` and `BASE_RPC_URL` stand in for the two flags.

It reads the stream's genesis core, authorization log and epoch manifests from the chains, resolves the canonical
commitment of every sequence (spec sections 13.4 and 13.5) and prints one line per sequence: CANONICAL with its
commitment, UNRESOLVED with the flags that explain why, or INCOMPLETE when a witness key could not be enumerated
to the end. The exit code is 0 only when every checked sequence is CANONICAL. It never trusts a value it did not
read from a chain.

Under the beta profile every manifest is anchored on Solana and one a day on Base, so the verdict rests on Solana;
the Base witness is a second copy. A Base endpoint that throttles, is down or is pruned is reported as an
incomplete Base scan and never ends the run; `--base-rpc` names another endpoint, `--no-base` skips the second copy.

The Base copies are read in one of two ways. **Windows mode**, the default, places each expected copy from what it
has just read on Solana: a data manifest's copy right after the end of its window (the engine seals at T+45 s and
sends both copies in the same tick; on the live stream the daily Base copy landed 49 to 63 seconds after midnight),
the genesis core's and a log entry's copy around the Solana anchor's block time. It asks for that one witness key in
a short block range, two minutes before to fifteen minutes after (thirty minutes before for the genesis core and a
log entry, whose Solana transaction may have been sent again later); a copy that is not there is looked for six more
hours ahead (`--base-extension-hours` changes that; the Sunday run here passes 24) and then reported MISSING. That is one `eth_getLogs` call per copy on an endpoint that allows thousands
of blocks per call and about fifty on a free keyed endpoint that allows ten (Alchemy's free tier does), so a full
run over a month-old stream costs about two thousand calls either way and the public `mainnet.base.org` handles a
daily run. A window the pass could not finish (budget, throttling, an endpoint error, or a window still open) holds
the checkpoint back before that sequence, so the next run places it again. **Range mode**
(`--base-scan range`, or `--base-from-block <n>`) is one pass over every block since genesis with only the schema
filter: the full enumeration of the protocol's section 12.7, which also finds a copy sent hours late, by someone
else, or with no Solana twin at all (windows mode has no time to place such a copy and cannot see it), for an
endpoint that allows thousands of blocks per `eth_getLogs` (public ones cap it at 2,000 or 10,000 and throttle
bursts). Both modes read every hit back from the contract and keep only admissible attestations.

Nothing the verifier prints or writes carries an endpoint's path or query string: a keyed URL is cut to its host in
every message (the daily run below commits its output to this public repository).

A full run walks every sequence since genesis: on the public Solana endpoint that is hours for a month-old stream
(about eight requests a second), on an archive endpoint of your own under an hour. `--to <sequence>` bounds it.

### Continue from your own checkpoint

A run that passes can write a checkpoint with `--checkpoint-out <file>`: the last CANONICAL sequence, its
commitment, the authorization log head it saw, and what it read on Base (range mode: the last block scanned;
windows mode: the highest manifest whose window was walked and whether the genesis and log windows were). The next
run with `--checkpoint <file>` reads the sequences from that one on, seeds the resolution with it, walks only the
Base windows that are new, and writes the file again. Such a run is labelled RESUMED and its JSON carries `"verdict": "resumed"`: the sequences before the
checkpoint rely on the run that wrote it and are not re-read, so a late conflicting anchor for an older sequence is
only seen by a full run. The protocol (section 13.7) calls a verdict that starts at a checkpoint non-conformant on
its own; the checkpoint is refused when the authorization log changed since it was written, and the daily run in
this repository is paired with a full run every Sunday for that reason: every sequence since genesis is read again
on Solana, which carries the verdict, and every expected Base copy is looked for again in its window (a range pass
over Base needs an endpoint that allows thousands of blocks per call; the keyed free endpoint the runs use allows ten).

## Change one digit

```
npm install
npx tsx examples/tamper.ts                       # BYK.FUNDING.COMPOSITE.B / BTC at the newest epoch
npx tsx examples/tamper.ts BYK.OPEN_INTEREST.AGGREGATE.USD BTC
```

The untouched record folds up its audit path to the Merkle root inside the signed manifest (PASS). The same
record with its value moved by one unit does not (FAIL): a published number cannot be changed afterwards
without the proof showing it.

## Run the tests

```
npm install
npm test                                                           # conformance vectors, decimals, and the chain readers against a fake JSON-RPC
python3 python/byk_xcheck.py vectors/byk_v1_test_vectors.json
npm run verify:source -- --stream <stream id> --to 30 --no-base   # the verifier from its source instead of the bundle
```

## Scope

The production pipeline (collectors, signer, anchoring) is not part of this repository. The stream id
to pin and the live signer are shown at https://bykaranteli.com/proof.
