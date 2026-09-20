# byk-verifier

Verify ByKaranteli's on-chain data layer yourself: spec, TypeScript library, Python reference, vectors.

The BYK Data Layer seals derived crypto market records (composite funding, aggregate open interest,
five-minute liquidation totals, spot depth, Turkey and Kimchi premiums, derivatives pressure) into a
Merkle root every five minutes, signs the manifest and writes the commitment to Solana, and once a day
to Base through the Ethereum Attestation Service. Nothing here needs an account or an API key: the
verifier reads the two chains and the public Proof API at https://bykaranteli.com/api/v1/proof.

## What is in this repository

| Path | What |
|---|---|
| `spec/BYK_Data_Layer_Protocol_v1.0.0-rc6.md` | The protocol, byte by byte (canonical encoding, leaf layout, Merkle rules, anchors, audit levels) |
| `spec/rc7-feedback-20260920.md` | Implementation notes fed back into the next revision |
| `ts/` | The TypeScript library used in production: encoding, records, funding composite, witness keys, audit, authorization log, with conformance tests |
| `python/byk_ref.py` | Reference implementation, Python standard library only |
| `python/byk_xcheck.py` | Cross-checks the Python reference against the vectors |
| `vectors/byk_v1_test_vectors.json` | Test vectors (Section 17 of the spec) |
| `byk-verify.mjs` | The one-file independent verifier (also served at https://bykaranteli.com/byk-verify.mjs) |

## Run the verifier

```
node byk-verify.mjs --stream <stream id> [--solana-rpc <url>] [--base-rpc <url>] [--to <sequence>] [--json]
```

It reads the stream's genesis, authorization log and epoch manifests from the chains, recomputes the
Merkle roots from the records the Proof API returns, and reports PASS, WARNING (a witness could not be
enumerated completely) or FAIL per epoch. It never trusts a value it did not recompute.

## Run the tests

```
npm install
npm test
python3 python/byk_xcheck.py vectors/byk_v1_test_vectors.json
```

## Scope

The production pipeline (collectors, signer, anchoring) is not part of this repository. The stream id
to pin and the live signer are shown at https://bykaranteli.com/proof.
