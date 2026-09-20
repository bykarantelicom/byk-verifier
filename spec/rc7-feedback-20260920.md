# Feedback for BYK Data Layer Protocol v1.0.0-rc7 (from the production implementation, 2026-09-20)

Written for the document owner (Opus session that maintains the rc6 spec and byk_ref.py).
Source: reports/data-layer-beta-profile-20260917.md section 5 and 6, reports/data-layer-handoff-to-opus-20260917.md.
The TypeScript implementation (web/src/lib/byk) behaves correctly in every case below; these are defects in the
reference Python and gaps in the spec text.

## 1. Reference Python (byk_ref.py), three defects

1. Lexeme regex accepts a trailing line break: a lexeme followed by "\n" parses as valid, so a canonical byte string
   with a stray newline at the end produces the same hash as the canonical form. The spec (canonical encoding) says
   the byte string ends with the last lexeme; the regex must anchor without an optional trailing newline.
2. parse_genesis_core does not check alignment: a core whose fixed-width fields are misaligned by one byte still
   parses and yields wrong field values instead of raising. The TS parser rejects it.
3. GOVERNANCE_UPDATE with a short body raises IndexError instead of a validation error: a body shorter than the
   declared layout should fail with the protocol's own error class so callers can distinguish malformed input from a
   crash.

## 2. Section 12.4 (Solana memo anchor): explicit compute unit limit

Measured on mainnet: the Memo program burns about 350 compute units per byte. The data anchor costs about 190k CU
and the largest authorization-log anchor 271k CU. The default 200k CU limit drops the AL anchor. The spec should
require an explicit compute unit limit request (we use 400k) in the anchor transaction, and say so in 12.4.

## 3. Section 12.6 (Base attestations): public RPC log range

Public Base RPCs limit eth_getLogs to 10,000 blocks (some to 2,000). A verifier that scans from the genesis block
needs chunked queries with an adaptive chunk size and an honest INCOMPLETE state when it stops early; the spec
could recommend this in the verifier guidance so independent implementations do not report a partial scan as a
failure.

## 4. Base attestation gas

Measured: 373k to 468k gas per attest. Worth a sentence in the cost model.
