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

## 2026-10-18 · Class A leaves with no input at all (restart gap) and the audit of 13.8

Observed on mainnet: the host was shut down 11:06 to 11:28 UTC on 17 Oct 2026; the venue collector wrote no bucket
for 11:00, 11:10 and 11:20, so epochs 8437 (T 11:30) and 8438 (T 11:35) found an empty look-back window. Every
BYK.FUNDING.COMPOSITE.A and .B leaf of those two epochs was sealed NO_DATA with source_count 0, and the engine wrote
no Class A snapshot for them (it returns before any write when the window is empty). The daily shadow audit then
reported 24 "missing" snapshots and FAIL, which is what 13.8 and N29 ask for: "every Class A leaf, whatever its status
(NO_DATA included) fails the audit if a Class A snapshot is missing".

The conformant repair, a snapshot with an empty venue list, is not representable under rc6 as implemented: Annex A's
parameter validation requires the catalogue size (the number of venues) to be at least 1, so `fundingComposite([])`
raises "invalid methodology parameters" and an empty snapshot cannot be recomputed by the auditor. Two readings are
possible and the spec should pick one:

1. A Class A leaf sealed with an empty input set carries a snapshot whose venue list is empty, and the Level 3 audit
   recomputes it as NO_DATA with expected_source_count 0 without running the Annex A algorithm (the algorithm's
   parameter check is for non-empty inputs only). This keeps 13.8's "every Class A leaf has a snapshot" literal and
   makes a restart gap auditable.
2. The audit treats a NO_DATA Class A leaf with source_count 0 as "no input" and demands no snapshot for it, with the
   gap manifest or the leaf itself as the evidence that nothing was consumed.

Option 1 is the stronger one (a sealed leaf always has its input of record, even when the input is nothing) and is
what ByKaranteli intends to implement once the text says so; until then the shadow audit keeps reporting such epochs
as FAIL, which is honest, and the engine does not write empty snapshots.

### Production choice, 18 Oct 2026 evening

ByKaranteli implements option 1 from this date. The engine writes a snapshot with an empty venue list for every
composite funding leaf it seals from no input at all (no bucket in the look-back window, no venue publishing a rate),
for BYK.FUNDING.COMPOSITE.A and for the Class B shadow rows alike; a stored empty row is an input of record like any
other, so a later load of the same boundary seals NO_DATA from it instead of composing from rows that arrived later.
The shadow audit and `byk_ref.audit_range` recompute an empty snapshot as NO_DATA with expected_source_count 0 and every
other field zero without calling the Annex A algorithm; `funding_composite` itself is unchanged and still refuses an
empty catalogue under A.10. The 48 leaves of epochs 8437 and 8438 (24 in each) received their empty snapshots after the fact, written
from the same rule, so the gap of 17 Oct is auditable. Suggested rc7 wording for 13.8: "a Class A leaf sealed with an
empty input set carries a snapshot whose venue list is empty; the Level 3 audit recomputes it as NO_DATA with
expected_source_count 0 and every other field zero, without running Annex A, and a missing snapshot remains a failure".
