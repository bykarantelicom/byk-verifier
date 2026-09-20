# BYK Data Layer — Protocol Specification

**Version:** 1.0.0-rc6  
**Status:** Review Draft (not frozen)  
**Date:** 2026-09-16  
**Owner:** ByKaranteli (bykaranteli.com)  
**Changes:** rc1→rc2 in Annex E, rc2→rc3 in Annex F, rc3→rc4 in Annex G, rc4→rc5 in Annex H, rc5→rc6 in Annex I

---

## 0. Status of This Document and Review Instructions

This is the sixth review draft. rc6 resolves the two findings of the rc5 review (Annex I) without adding mechanisms. It is proposed as the freeze candidate for the protocol core (Sections 1–17). Annex A's input layer is aligned with the production collectors separately (Annex C15). Architecture decisions are closed (Annex D). Items needing an owner decision are marked **OPEN** and listed in Annex C.

**Instructions for reviewers:** Do not propose new architecture. Report only:

- ambiguities that let two competent implementers produce different bytes or different verification results;
- security flaws;
- interoperability bugs across Solidity, Rust, TypeScript and Python;
- contradictions between sections.

Cite section numbers.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119.

---

## 1. Overview

The BYK Data Layer makes market data produced by ByKaranteli cryptographically attributable, tamper-evident and positioned on two independent public blockchains. Every five minutes, ByKaranteli's signing service:

1. closes an epoch;
2. commits all records into one Merkle root;
3. wraps the root in a fixed-size manifest;
4. obtains a data-signer signature over the manifest hash.

Anyone may then submit the signed manifest to the witness chains. A governance key set, fixed by a genesis core whose hash is the stream's identity, authorizes data signers through a hash-linked authorization log.

### 1.1 Design principles

1. **The protocol is canonical; blockchains are witnesses.** Validity rules live in this document. Neither chain is a source of truth.
2. **Explicit trust root.** `stream_id = keccak256(genesis_core)`, pinned by verifiers out-of-band.
3. **One commitment per epoch.** On-chain writes per epoch are constant regardless of record count.
4. **Authority comes only from signatures. Witness submission is permissionless.** The identity of whoever submits a witness transaction never affects validity or admissibility.
5. **Integers only.** No floating point, decimal strings or text normalization in hashed structures.
6. **Honest gaps.** Missing data is an explicit status. Stale values are never carried forward.
7. **Deterministic verification.** Results are a function of the pinned `stream_id`, per-witness as-of heights, and the complete witness data at those heights. Incomplete data yields INCOMPLETE, never a positive result.
8. **Precise time language.** Witnesses prove chain position. Times are reported by witness consensus and are labelled as reported, never as proven.
9. **Additive adapters.** New witnesses or native registries never change the data format.

### 1.2 Data classes

| Class | Description | Examples | v1 distribution |
|---|---|---|---|
| A | Deterministic composites, reproducible from the methodology document and the retained input snapshot (Annex A.12) | Composite Funding Index | Leaves, API, MCP, Switchboard |
| B | Proprietary derived metrics; the methodology document hash is committed | VPIN, Liquidation Pressure, Market Stress | Leaves, API, MCP |
| C | Raw exchange data | Order books, open interest | Internal input only |

### 1.3 Non-goals

The protocol does not prove economic correctness of values or wall-clock time. It provides no on-chain consumption in v1 (Annex B). There is no token.

---

## 2. Terminology

| Term | Definition |
|---|---|
| Genesis core | Binary structure defining governance, witness networks and genesis epoch (Section 11.1) |
| Stream ID | `keccak256(genesis_core)`; the trust root, pinned by verifiers |
| Epoch / Sequence | 300000 ms window (or multiple, for gap manifests) / uint64 counter ordering manifests |
| Record / Leaf | One data point for one `(feed_id, asset_id)` in one epoch, 104 bytes |
| Feed catalog | Committed list of `(feed, asset, decimals, class)` entries every non-NO_DATA epoch contains |
| Manifest / Commitment | 200-byte epoch description / `C = keccak256(manifest_bytes)` |
| Data signer | secp256k1 key in a KMS/HSM that signs commitments; authorized through the authorization log |
| Signing service | ByKaranteli software that builds manifests and requests data-signer signatures; enforces Section 5.9 |
| Submitter | Any party that sends a witness transaction. It has no protocol role and no identity requirement. |
| Governance | M-of-N secp256k1 key set that appends to the authorization log |
| Authorization log (AL) | Hash-linked, governance-signed entries (Section 11.3) |
| Witness key | Per-item 32-byte discovery key (Section 12.3) |
| Witness index | All admissible anchors, discoverable through witness keys (Section 12.6) |
| As-of time `T` / as-of heights | Verification cutoff time / the per-witness block heights derived from `T` (Section 12.9) |
| Reported time | Witness-consensus timestamp of a block, in ms (Section 12.9) |
| Candidate / Canonical | Authorized manifest in the witness index (Section 13.4) / resolution output (Section 13.5) |
| Result codes | CANONICAL, UNRESOLVED, INCOMPLETE, GOVERNANCE_FORK, GOVERNANCE_FORK_TERMINAL |

---

## 3. Threat Model and Guarantees

### 3.1 Verification levels and guarantees

| Level | Name | Subject | Checks | Guarantees |
|---|---|---|---|---|
| 1E | Authentic epoch | any manifest, including NO_DATA | 13.2, 13.3, 13.6 steps 1–2 | G1, G2, G5 |
| 1 | Authentic record | a leaf of an OK or DEGRADED manifest | Level 1E + 13.6 steps 3–5 | G1, G2, G5 |
| 2E | Canonical epoch | any manifest | Level 1E + 13.4, 13.5, 13.7 | G1, G2, G3, G5 + resolution for the sequence |
| 2 | Canonical record | a leaf of an OK or DEGRADED manifest | Level 1 + Level 2E | G1, G2, G3, G5 + resolution for the sequence |
| 3 | Audit | a sequence range | Level 2E for every sequence + 13.8 | G1–G5 for the range |

- **G1 Attribution:** the manifest was signed by a data signer authorized for its sequence in AL at the as-of heights.
- **G2 Integrity:** record, manifest, schema version and methodology version are unaltered since commitment.
- **G3 Witness position:** for each witness, the manifest bytes existed before the finalized block containing the earliest admissible anchor carrying them (Base block number, Solana slot). That block's reported time (Section 12.9) is reported alongside, labelled REPORTED, INFERRED or UNAVAILABLE. G3 holds across re-signing.
- **G4 History integrity:** over an audited range, canonical manifests form an unbroken, window-contiguous `previous_commitment` chain.
- **G5 Methodology non-repudiation:** any methodology change alters `methodology_hash`.

### 3.2 Non-guarantees

- The protocol does not guarantee correctness of values relative to markets.
- **Reported times are not cryptographic wall-clock proofs.** Base block timestamps are assigned by the Base sequencer within OP Stack rules. Solana block times are estimated from the stake-weighted mean of validator vote timestamps and may be unavailable. Public statements MUST say "anchored in Base block X (reported time t) and Solana slot Y (reported time t′)", not "proven to exist at time t".
- There is no time lower bound. The EARLY flag is a heuristic.
- Only Level 3 detects missing or duplicate catalog entries.
- Liveness of external sources is not guaranteed.
- Results depend on `T`. Later authorization log entries, for example retroactive revocation, can change results for a later `T`. This is deterministic for any fixed `T`.
- Verification availability is not guaranteed under witness-key spam (Section 3.3); affected results become INCOMPLETE rather than wrong.

### 3.3 Adversaries

| Adversary | Effect | Mitigation |
|---|---|---|
| Trust-root substitution | Different `stream_id` | Out-of-band pinning (Section 11.2) |
| Network replay (testnet or other cluster) | None | Genesis network binding; identity checks (Section 12.2) |
| **Any submitter**, including a compromised ByKaranteli submitter key | Can post junk or duplicate anchors under any witness key; raises enumeration cost for targeted keys only | Signature-based validity; per-item witness keys isolate spam; cheap-first processing; INCOMPLETE semantics (Section 12.7). Attack cost grows with the number of polluted key listings. One transaction or multi-attestation can reference several keys, so batching amortizes fees and the bound is economic, not exact per key. |
| Compromised data signer | Equivocation or fake manifests | UNRESOLVED instead of wrong (Section 13.5); revocation, re-signing, checkpoints (Section 15, F5) |
| Compromised governance (≥ M keys) | Arbitrary authorizations | Hardware keys, separate custody. Total trust failure is out of scope. |
| Governance double-signing (benign or malicious) | GOVERNANCE_FORK | Fork-threshold continuation (Section 11.5); terminal only if conflicting fork-threshold continuations exist |
| Witness clock skew (sequencer or validator clocks) | Reported times inaccurate | Two independent witnesses, both reported; claims phrased per Section 3.2 |
| Dishonest signing service | Wrong but attributable values | G1, G2, G5 |
| Late anchoring (backdating attempt) | Anchors far after window | LATE flag; G3 positions |
| Witness outage or reorg | Missing or delayed anchors | Two witnesses; only finalized blocks count |
| Malicious proof server | Wrong hints | Verifier recomputes everything |
| Source withdrawal | Coverage loss | Explicit statuses; methodology versioning |

---

## 4. Encoding Rules

1. **Integers:** big-endian, fixed-width. `uint8/16/32/64`, `int64` two's complement. Little-endian serializers (for example Borsh) MUST NOT be used for hashed structures.
2. **Validation:** reserved bytes zero. Wrong magic, version or length, or trailing bytes, cause rejection.
3. **Arithmetic:** exact integer and rational arithmetic. Each methodology states input bounds under which every intermediate value fits a stated width (Annex A: signed 256-bit). Implementations MAY use that width and MUST otherwise compute with arbitrary precision; results never depend on the width chosen. A published field outside its type range makes the record NO_DATA. Integer division truncates toward zero (`trunc_div`). Saturating fields saturate at their maximum.
4. **Identifiers:** `id32(name) = keccak256(ASCII bytes)`. The name is non-empty and every character is in `0x21–0x7E`. Case-sensitive.
5. **Time:** protocol timestamps are uint64 Unix milliseconds. Witness times given in seconds are converted by multiplying by 1000 (Section 12.9).
6. **Hash:** `keccak256` is original Keccak-256 (Ethereum), not SHA3-256.
7. **Text encodings outside hashed structures:** JSON uses lowercase hex with `0x`, and integers outside ±(2^53 − 1) are written as decimal strings; Solana memos use lowercase hex without prefix.

---

## 5. Epochs and Sequence

1. **Window length:** OK or DEGRADED manifests span exactly 300000 ms. NO_DATA manifests MAY span any positive multiple (gap manifests).
2. **Alignment:** `epoch_start_ms mod 300000 = 0`.
3. **Contiguity:** for `s > 0`, `epoch_start_ms(s) = epoch_end_ms(s-1)`.
4. **Sequence:** `sequence(s) = sequence(s-1) + 1`; genesis is 0. Sequence is a counter; rules 1–3 link it to time.
5. **Genesis:** sequence 0 is NO_DATA, `record_count = 0`, `merkle_root = keccak256("")`, previous commitment zero, window `[genesis_epoch_start_ms, +300000)` from the genesis core.
6. **Input cutoff:** records in `[start, end)` use only inputs timestamped `< end`; `start ≤ observed_at_ms ≤ end`. v1 composites use `observed_at_ms = end`.
7. **Deadline:** sign within 60 s after `epoch_end_ms` and submit immediately (SHOULD).
8. **Outage recovery:** one gap manifest for missed windows, then resume. Never publish values for unobserved windows.
9. **Signing discipline:** the signing service MUST persist each signed manifest before releasing it for submission. It MUST NOT request a data-signer signature over a different manifest for a sequence it has already had signed. Re-signing the same manifest under Section 11.7 is permitted.

---

## 6. Status Model

| Code | Name | Leaf meaning | In manifest |
|---|---|---|---|
| 0 | OK | Valid, nominal | yes |
| 1 | DEGRADED | Valid, reduced quality | yes |
| 2 | INSUFFICIENT_COVERAGE | Quorum not met; `value = 0`, `dispersion = 0`; value MUST be ignored | **no** |
| 3 | NO_DATA | No usable inputs; `value = 0`, `dispersion = 0` | yes |

- **Epoch status is derived:** NO_DATA if and only if `record_count = 0`; OK if all leaves are OK; otherwise DEGRADED.
- **Completeness:** OK and DEGRADED epochs contain exactly one leaf per catalog entry. Missing data is a NO_DATA leaf.
- **No carry-forward:** a leaf does not reuse a previous epoch's value unless the methodology defines it as the current observation.

---

## 7. Records (Leaves)

### 7.1 Layout (104 bytes)

| Offset | Size | Field | Type | Rule |
|---|---|---|---|---|
| 0 | 1 | leaf_version | uint8 | `0x01` |
| 1 | 1 | status | uint8 | Section 6 |
| 2 | 1 | decimals | uint8 | equals catalog |
| 3 | 1 | reserved | — | zero |
| 4 | 32 | feed_id | bytes32 | `id32` |
| 36 | 32 | asset_id | bytes32 | `id32` |
| 68 | 8 | observed_at_ms | uint64 | Section 5.6 |
| 76 | 8 | value | int64 | `value × 10^-decimals` |
| 84 | 2 | source_count | uint16 | contributing sources |
| 86 | 2 | expected_source_count | uint16 | catalog sources |
| 88 | 2 | coverage_bps | uint16 | 0–10000, methodology-defined |
| 90 | 2 | outlier_count | uint16 | removed by outlier filter |
| 92 | 4 | max_source_age_ms | uint32 | oldest input of any kind used by any contributor, as the methodology enumerates inputs; saturating |
| 96 | 8 | dispersion | int64 | ≥ 0, same decimals as value. Methodologies MUST bound their inputs so that `value` and `dispersion` always fit int64 (Annex A.6). |

### 7.2 Class B quality fields

Class B feeds MAY set quality fields to 0 when they are not meaningful. Their semantics are stated in the committed methodology document.

---

## 8. Merkle Tree

1. `leaf_hash = keccak256(0x00 || leaf)`; `node_hash = keccak256(0x01 || left || right)`.
2. **Ordering:** leaves sorted ascending by `feed_id || asset_id`. Duplicate keys make the manifest invalid.
3. **Construction** (RFC 6962 shape):
   - `MTH({}) = keccak256("")`;
   - `MTH({d0}) = leaf_hash(d0)`;
   - for `n > 1`, with `k` the largest power of two `< n`: `MTH(D[n]) = node_hash(MTH(D[0:k]), MTH(D[k:n]))`.
4. **Proofs:** RFC 6962 `PATH`, verified per RFC 9162 Section 2.1.3.2.
5. **Tree size MUST be authenticated.** Proofs do not bind tree size (Section 17.3). Use `tree_size = record_count` and `root = merkle_root` from a verified manifest.

---

## 9. Manifest and Commitment

### 9.1 Layout (200 bytes)

| Offset | Size | Field | Type | Rule |
|---|---|---|---|---|
| 0 | 4 | magic | bytes | `BYKD` |
| 4 | 1 | protocol_version | uint8 | `0x01` |
| 5 | 1 | status | uint8 | derived; never 2 |
| 6 | 2 | reserved | — | zero |
| 8 | 8 | sequence | uint64 | Section 5 |
| 16 | 8 | epoch_start_ms | uint64 | Section 5 |
| 24 | 8 | epoch_end_ms | uint64 | Section 5 |
| 32 | 4 | record_count | uint32 | leaves |
| 36 | 4 | reserved | — | zero |
| 40 | 32 | stream_id | bytes32 | Section 11.1 |
| 72 | 32 | merkle_root | bytes32 | Section 8 |
| 104 | 32 | previous_commitment | bytes32 | zero for genesis |
| 136 | 32 | schema_hash | bytes32 | Section 9.3 |
| 168 | 32 | methodology_hash | bytes32 | Section 9.3 |

### 9.2 Commitment

`C = keccak256(manifest_bytes)`. Signatures are not part of the manifest, so re-signing never changes `C`.

### 9.3 Schema and methodology hashes

These are keccak256 of the exact published schema document and methodology registry bytes. Their machine-readable formats are **OPEN** (C14). A hash change coincides with a documented version change.

---

## 10. Signatures

1. **Scheme:** ECDSA secp256k1 over `C` as the 32-byte digest. No prefix, no further hashing.
2. **Canonical encoding (65 bytes):** `r || s || recovery_id`, with `1 ≤ r < n`, `1 ≤ s ≤ n/2`, `recovery_id ∈ {0, 1}`. Anything else MUST be rejected.
3. **Identity:** last 20 bytes of `keccak256(uncompressed_public_key[1:65])`.
4. **Adapters:**
   - off-chain recovery without message prefixes;
   - EVM `ecrecover(C, recovery_id + 27, r, s)`;
   - Solana secp256k1 precompile with `message = manifest_bytes`, not `C`.
5. **Nonces:** RFC 6979 RECOMMENDED for software signers. KMS signers may be non-deterministic.
6. **AWS KMS:**
   - key spec `ECC_SECG_P256K1`;
   - `Sign(Message = C, MessageType = DIGEST, SigningAlgorithm = ECDSA_SHA_256)`; `RAW` MUST NOT be used;
   - parse DER; normalize low-S;
   - derive `recovery_id` by trial recovery; abort if neither 0 nor 1 matches;
   - verify independently before release.
7. **KMS conformance gate (before mainnet):** sign `C1` (Section 17.4) with the staging key, then verify off-chain, by `ecrecover` on Base Sepolia, and by the Solana precompile on devnet with `message = M1`.
8. **Operations:** Section 5.9 applies. Every KMS `Sign` call is logged and alerted on anomalies.

---

## 11. Trust Root, Governance and Authorization

### 11.1 Genesis core

`stream_id = keccak256(genesis_core_bytes)`.

| Offset | Size | Field | Type | Rule |
|---|---|---|---|---|
| 0 | 4 | magic | bytes | `BYKG` |
| 4 | 1 | version | uint8 | `0x01` |
| 5 | 1 | governance_threshold (M) | uint8 | `M ≥ 1` and `N ≥ 2M − 1` (hence `M ≤ 2`) |
| 6 | 1 | governance_count (N) | uint8 | `1 ≤ N ≤ 4` |
| 7 | 1 | reserved | — | zero |
| 8 | 8 | genesis_epoch_start_ms | uint64 | aligned |
| 16 | 32 | stream_name_id | bytes32 | `id32(name)`; informative, no trust |
| 48 | 8 | base_chain_id | uint64 | Base mainnet `8453` |
| 56 | 32 | solana_genesis_hash | bytes32 | raw 32 bytes (mainnet-beta base58 `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`) |
| 88 | 20 | base_eas_address | bytes20 | `0x4200000000000000000000000000000000000021` |
| 108 | 4 | reserved | — | zero |
| 112 | 20×N | governance addresses | bytes20[] | strictly ascending |

The length is exactly `112 + 20N`.

- `N ≤ 4` bounds every witness payload to fit a Solana transaction (Section 12.4).
- `N ≥ 2M − 1` guarantees that when fewer than M keys are compromised and the rest are available, at least M honest keys remain to remove them (Section 15, F6).
- The same bounds apply to GOVERNANCE_UPDATE.

### 11.2 Trust root pinning and publication

- Verifiers MUST be configured with `stream_id` from an out-of-band source and MUST recompute `keccak256(genesis_core)`.
- A `stream_id`, genesis core or governance set discovered only from witness data or the Proof API MUST NOT be accepted.
- When first configuring, a verifier SHOULD confirm that at least two publication channels agree.
- Proposed channels (**OPEN**, C10):
  - `https://bykaranteli.com/.well-known/byk-data-layer.json`;
  - DNS TXT `_byk-data-layer.bykaranteli.com`;
  - a signed source-repository release;
  - the production annex of this specification.

### 11.3 Authorization log entries

Header (80 bytes):

| Offset | Size | Field | Type | Rule |
|---|---|---|---|---|
| 0 | 4 | magic | bytes | `BYKL` |
| 4 | 1 | version | uint8 | `0x01` |
| 5 | 1 | entry_type | uint8 | 1 AUTHORIZE, 2 GOVERNANCE_UPDATE, 3 CHECKPOINT, 4 ACK |
| 6 | 2 | body_length | uint16 | exact |
| 8 | 8 | log_seq | uint64 | 1, 2, 3, … |
| 16 | 32 | stream_id | bytes32 | pinned |
| 48 | 32 | previous_entry_hash | bytes32 | hash of the entry at `log_seq - 1`; zero for 1 |

Bodies:

| Type | Body | Size |
|---|---|---|
| AUTHORIZE (1) | signer bytes20, reserved 4, `valid_from_sequence` uint64, `valid_until_sequence` uint64 | 40 |
| GOVERNANCE_UPDATE (2) | threshold uint8, count uint8, reserved 2, addresses bytes20×count (strictly ascending; genesis bounds) | 4 + 20·count |
| CHECKPOINT (3) | sequence uint64, commitment bytes32 | 40 |
| ACK (4) | empty; no state change (used to resolve governance forks, Section 11.5) | 0 |

`entry_hash = keccak256(entry_bytes)`.

### 11.4 Governance bundles

A bundle is a concatenation of canonical 65-byte signatures over `entry_hash`. Signatures are ordered by recovered address, strictly ascending, and every signer is a member of the governance set that validates the entry (Section 11.5). A bundle meets a threshold `t` when it contains at least `t` such signatures; by construction it contains at most N.

Governance signatures are plain secp256k1 signatures, not Safe (EIP-1271) or Squads signatures. A member's secp256k1 key MAY also own a Safe. Squads membership requires a separate Ed25519 keypair.

### 11.5 Constructing AL at the as-of heights

Collect all AL entries from admissible anchors within the as-of heights (Sections 12.6, 12.9). Start with the genesis governance set and threshold, `prev = 0x00…00`, `i = 1`.

1. `V_i` = distinct entries with `log_seq = i`, pinned `stream_id`, `previous_entry_hash = prev`, and a bundle meeting the current threshold under the current set.
2. **If `V_i` is empty:** stop with status OK. The head is `(i - 1, prev)`.
3. **If `V_i` has exactly one entry:** apply it, set `prev` to its hash and `i = i + 1`, and repeat from step 1.
4. **If `V_i` has two or more entries (governance fork):**
   - let `F = min(current threshold + 1, current N)`, the fork threshold, and keep the pre-fork set;
   - let `R_i` = distinct **ACK** entries with `log_seq = i + 1` whose `previous_entry_hash` equals the hash of some member of `V_i` and whose bundle meets `F` under the **pre-fork** set;
   - entries of other types at `log_seq = i + 1` are ignored for fork resolution, even if they meet `F`;
   - an ACK's bytes are fully determined by `(log_seq, stream_id, previous_entry_hash)`, so distinct ACK entries necessarily reference different members of `V_i`; the same ACK with different bundles counts once;
   - **`R_i` empty:** stop with status **GOVERNANCE_FORK**, head `(i - 1, prev)`. A qualifying continuation anchored later resolves the fork for later as-of heights.
   - **`R_i` has two or more entries:** stop with status **GOVERNANCE_FORK_TERMINAL**. The stream cannot continue (Section 15, F13).
   - **`R_i` has exactly one entry `c`:** apply the `V_i` entry that `c` references (the ACK itself changes nothing). Set `prev` to the hash of `c` and `i = i + 2`, and repeat from step 1. State changes after resolution require new entries under the normal rule with the post-fork governance.

Applying an entry:

- AUTHORIZE replaces the signer's range;
- GOVERNANCE_UPDATE replaces set and threshold for subsequent entries;
- CHECKPOINT sets `checkpoint[sequence]`, replacing any earlier one;
- ACK changes nothing.

While the status is GOVERNANCE_FORK or GOVERNANCE_FORK_TERMINAL, every data verification result for the stream at these heights is that status.

### 11.6 Signer applicability

A signer `S` is authorized for sequence `s` if and only if its latest AUTHORIZE has `valid_from_sequence ≤ s`, and either `valid_until_sequence = 2^64 − 1` (unbounded, including `2^64 − 1`) or `s < valid_until_sequence`.

### 11.7 Revocation and re-signing

- Revocation is an AUTHORIZE entry that shortens a range, possibly retroactively.
- Manifests outside the new range lose that signature's authorization and may be re-signed by another authorized signer.
- Commitments do not change on re-signing, and G3 positions are preserved because they depend on manifest bytes, not signatures (Section 12.10).

### 11.8 Checkpoints

A CHECKPOINT declares the canonical commitment for one sequence. It resolves an equivocation, or restarts resolution after an unresolved predecessor. It never breaks the chain: when the predecessor sequence is resolved, the checkpointed manifest MUST link to it (Section 13.5), otherwise the result is UNRESOLVED with flag CHECKPOINT_CONFLICT. When the predecessor is UNRESOLVED, the checkpoint restarts resolution and the result carries flag HISTORY_UNRESOLVED_BEFORE, inherited by all later canonical sequences.

### 11.9 Solana Attestation Service mirror (optional)

Governance MAY mirror AL entries as Solana Attestation Service (SAS) attestations for future native Solana consumers. SAS mirrors are not part of the witness index.

---

## 12. Witnesses

### 12.1 Requirement and submission

- Every manifest (including genesis and gap manifests) MUST be anchored on both witnesses every epoch.
- Every AL entry with its bundle MUST be anchored on at least one witness and SHOULD be anchored on both.
- The genesis core SHOULD be anchored on both.
- **Submission is permissionless:** admissibility and validity MUST NOT depend on the fee payer, transaction signer, EAS attester or any other submitter property.
- ByKaranteli operates its own submitters. Their keys are operational only (Section 15, F4).

### 12.2 Network identity

Only anchors on the networks bound in the genesis core count. Verifiers MUST confirm, for every endpoint they use, that `eth_chainId` equals `base_chain_id` and that `getGenesisHash` (base58-decoded) equals `solana_genesis_hash`.

### 12.3 Witness keys

`witness_key(kind, n) = keccak256("BYKW" || stream_id || uint8(kind) || uint64(n))`

| kind | Anchors | n |
|---|---|---|
| 1 | data manifests | sequence |
| 2 | AL entries | log_seq |
| 3 | genesis core | 0 |

- **Solana:** the 32 bytes are used as an account address.
- **Base:** the last 20 bytes are used as the EAS attestation recipient.
- Witness keys are derived by hashing, so no party holds a corresponding private key.
- They isolate discovery per item: spam against one key does not affect any other key.

### 12.4 Solana

- **Program:** SPL Memo `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`. Exactly one BYK memo per transaction.
- **Memo formats** (ASCII, single `0x20` separators, lowercase hex without `0x`, nothing else):

  | Payload | Format | Size |
  |---|---|---|
  | Data | `BYK1 <hex(manifest)> <hex(signature)>` | exactly 536 bytes |
  | AL | `BYKL1 <hex(entry)> <hex(bundle)>` | ≤ 855 bytes |
  | Genesis | `BYKG1 <hex(genesis_core)>` | ≤ 390 bytes |

- **Witness key inclusion:** the transaction MUST include the matching witness key as a **static** account key (legacy message, or v0 static keys; not loaded through an address lookup table). RECOMMENDED construction: a System Program transfer of 0 lamports from the fee payer to the witness key.
- **Size:** the serialized transaction MUST be ≤ 1232 bytes. Under the reference construction (legacy, 1 signature, 5 account keys, compute-unit price, 0-lamport transfer, memo) the overhead is 295 bytes, leaving a 937-byte memo budget.
- **Conformance gate:** on devnet, such an anchor MUST be returned by `getSignaturesForAddress(witness_key)`.

### 12.5 Base (EAS)

- **Contracts:** EAS at `base_eas_address`; Schema Registry `0x4200000000000000000000000000000000000020`.
- **Schemas** (resolver `0x0`, `revocable = false`):
  - `uint64 sequence,bytes32 commitment,bytes manifest,bytes signature`
  - `uint64 logSeq,bytes32 entryHash,bytes entry,bytes governanceSignatures`
  - `bytes32 streamId,bytes genesisCore`
- **UID:** `keccak256(abi.encodePacked(schema, resolver, revocable))` (Section 17.6). Conformance gate: registration on Base Sepolia returns the listed UIDs.
- **Attestation:**
  - **recipient = last 20 bytes of the matching witness key**;
  - `expirationTime = 0`, `revocable = false`, `refUID = 0x0`, `value = 0`;
  - `data = abi.encode(...)` in schema order.
- The attester is unrestricted.

### 12.6 Admissibility (the witness index)

An anchor is admissible only if all of the following hold. Inadmissible anchors are ignored for all purposes.

**Common:**

- network identity matches;
- the transaction succeeded;
- the payload parses exactly (Sections 9, 11.1, 11.3);
- the embedded `stream_id` equals the pinned value;
- the witness key matches the payload: data kind with manifest `sequence`, AL kind with entry `log_seq`, genesis kind with 0.

**Base:**

- `Attested` event emitted by `base_eas_address` with one of the three schema UIDs;
- attestation fields as in Section 12.5;
- `data` is canonical ABI (re-encoding reproduces it byte for byte);
- data payloads: outer `sequence` and `commitment` equal manifest `sequence` and `keccak256(manifest)`, manifest 200 bytes, signature 65 bytes;
- AL payloads: outer `logSeq` and `entryHash` match the entry, bundle a positive multiple of 65 bytes;
- genesis payloads: `streamId = keccak256(genesisCore)`.

**Solana:**

- the witness key is a static account key;
- exactly one SPL Memo instruction, matching one format of Section 12.4.

An admissible anchor whose signature is invalid or unauthorized still counts for G3, but never for candidacy.

### 12.7 Enumeration, cost bounding and completeness

**Discovery:** for each required item, verifiers query by witness key.

- **Solana:** `getSignaturesForAddress(witness_key)` at `finalized` commitment, paginated to the as-of slot.
- **Base:** `eth_getLogs` on `base_eas_address`, `Attested` topic, `topic1 = recipient`, `topic3 = schema UID`, up to the as-of block.

**Processing order (cheap-first):**

1. Skip failed transactions.
2. Skip anchors beyond the as-of heights.
3. Optionally pre-filter by the RPC `memo` field (non-authoritative).
4. Fetch and check admissibility.
5. Deduplicate by `keccak256(payload)`.
6. Check `stream_id`.
7. Recover signatures and check authorization.

**Completeness:**

- A result is complete only if every required witness-key query was enumerated to the as-of heights on every witness it depends on.
- If any required enumeration fails (for example: RPC history unavailable, pagination limits, timeouts, or a source returning inconsistent data), the verifier MUST return **INCOMPLETE** for the affected sequences or log positions. It MUST NOT return CANONICAL.
- Archival data sources are required for historical verification (C11).

### 12.8 Anchor states and flags

| State | Solana | Base |
|---|---|---|
| PENDING | submitted, not included | submitted, not included |
| INCLUDED | `confirmed` | included in L2 block |
| FINAL | `finalized` | at or below the `finalized` head |
| MISSED | no admissible FINAL anchor 24 h after `epoch_end_ms` | same |

Flags:

- **LATE:** reported time − `epoch_end_ms` > 120 s (**OPEN**).
- **EARLY:** reported time < `epoch_end_ms` − 30 s. It is anomalous and must be investigated.
- LATE and EARLY are computed only when the reported-time status is REPORTED or INFERRED. Otherwise the flag TIME_UNAVAILABLE applies.
- **EQUIVOCATION:** two linking candidates for one sequence (Section 13.5).

### 12.9 Reported time and as-of heights

**Reported time:**

- **Base:** `reported_time_ms = block.timestamp × 1000`. Status is always REPORTED.
- **Solana:** if `getBlockTime(slot)` is available, `reported_time_ms = block_time × 1000`, status REPORTED. If it is unavailable, use the reported time of the nearest later finalized slot whose block time is available, status INFERRED (an upper bound in chain order on the estimate). If no such slot exists yet, status UNAVAILABLE.
- If archival sources disagree, a non-null value takes precedence over null. Two different non-null values for the same finalized slot make dependent results INCOMPLETE.

**As-of heights for time `T` (ms):**

- **Base:** `H_B(T)` = highest finalized block with `timestamp × 1000 ≤ T`.
- **Solana:** `H_S(T)` = highest finalized slot whose block time is available and `block_time × 1000 ≤ T`.
- All uses in Sections 11.5 and 13 consider exactly the anchors in blocks at or below these heights, including slots whose own block time is unavailable. Verification outputs MUST report `T`, `H_B(T)` and `H_S(T)`.

### 12.10 Witness position (G3)

For manifest bytes `M` and each witness:

- the **witness position** is the (block number or slot, transaction index) of the earliest admissible anchor within the as-of heights carrying byte-identical `M`, regardless of its signature;
- the reported time of that block, with its status, is reported alongside.

---

## 13. Verification

### 13.1 Inputs and outputs

**Inputs:**

- pinned `stream_id` and genesis core;
- as-of time `T`, which SHOULD be at least the finalization delay of both witnesses in the past;
- witness access (own RPC endpoints RECOMMENDED; archival for history);
- the record or range to verify.

**Outputs:** every output MUST include:

- `stream_id`, `T`, `H_B(T)`, `H_S(T)`;
- the AL status and head `(log_seq, entry_hash)`;
- the level;
- a result code (CANONICAL, UNRESOLVED, INCOMPLETE, GOVERNANCE_FORK, GOVERNANCE_FORK_TERMINAL);
- flags (EQUIVOCATION, CHECKPOINT_CONFLICT, CHECKPOINT_NOT_CANDIDATE, HISTORY_UNRESOLVED_BEFORE, LATE, EARLY, TIME_UNAVAILABLE).

Two conformant verifiers with the same inputs and complete witness data MUST produce identical outputs.

### 13.2 Manifest structure

1. Length, magic, version and reserved bytes are valid.
2. `status ∈ {0, 1, 3}`.
3. Window rules 5.1 and 5.2 hold.
4. NO_DATA if and only if `record_count = 0`; if `record_count = 0` then `merkle_root = keccak256("")`.
5. If `sequence = 0`: previous commitment zero and the window equals the genesis window.
6. `stream_id` equals the pinned value.
7. **Stream sequence rule:** `epoch_start_ms ≥ genesis_epoch_start_ms + sequence × 300000`, evaluated without overflow (the right-hand side can exceed 2^64; use at least 128-bit arithmetic). Every honest manifest satisfies this, because each window spans at least 300000 ms and windows are contiguous from genesis.

### 13.3 Authorization log

Construct AL per Section 11.5. A status other than OK determines all results.

### 13.4 Candidates

`Cand(s)` is the set of distinct commitments `C` for which there exists **one** admissible anchor within the as-of heights whose payload carries both manifest bytes `M` with `keccak256(M) = C` and a signature that recovers, over `C`, to a signer authorized for `s`, and where:

- `M` passes Section 13.2;
- `epoch_end_ms(M) ≤ T`.

A manifest and a signature taken from different anchors never form a candidate (N21). Re-signing produces a new anchor that carries the same `M` next to the new signature. G3 positions are unaffected by this rule (Section 12.10).

### 13.5 Canonical resolution

Let `S_max(T) = floor((T − genesis_epoch_start_ms) / 300000) − 1`. If `T < genesis_epoch_start_ms + 300000`, nothing is resolvable. By Sections 13.2 step 7 and 13.4, every candidate has `sequence ≤ S_max(T)`. Checkpoints for sequences greater than `S_max(T)` are ignored at `T`. For a target sequence `t`, evaluate:

```text
prev := none; gap := false
for s = 0 .. min(t, S_max(T)):       # bound derived from T only, never from signed sequence numbers
    flags := []
    links(C) := previous_commitment(C) = prev and epoch_start_ms(C) = epoch_end_ms(prev)
    if checkpoint[s] exists:
        K := checkpoint[s]
        if K ∉ Cand(s):          res := UNRESOLVED; flags += CHECKPOINT_NOT_CANDIDATE
        else if s = 0:           res := K
        else if prev is UNRESOLVED:
                                 res := K; gap := true
        else if links(K):        res := K
        else:                    res := UNRESOLVED; flags += CHECKPOINT_CONFLICT
    else if s = 0:
        res := single element of Cand(0) if |Cand(0)| = 1 else UNRESOLVED
        (flags += EQUIVOCATION if |Cand(0)| > 1)
    else if prev is UNRESOLVED:  res := UNRESOLVED
    else:
        L := { C ∈ Cand(s) : links(C) }
        res := single element of L if |L| = 1 else UNRESOLVED
        (flags += EQUIVOCATION if |L| > 1)
    if res ≠ UNRESOLVED and gap: flags += HISTORY_UNRESOLVED_BEFORE
    canonical[s] := (res, flags); prev := res
```

- A sequence with no candidates and no checkpoint is UNRESOLVED.
- `canonical[s]` depends only on sequences ≤ `s`.
- If any `Cand(s)` needed for this loop is INCOMPLETE (Section 12.7), then `canonical[s]` and all later results are INCOMPLETE.
- Work is linear in the number of epochs elapsed since genesis at `T`, whatever sequence numbers a compromised signer signs (N22).

Properties:

- orphan branches never block resolution;
- two linking candidates yield UNRESOLVED until governance acts;
- a CANONICAL result with a resolved predecessor always links to it, so Level 2 and Level 3 agree on history.

### 13.6 Level 1E (authentic epoch) and Level 1 (authentic record)

1. Section 13.2 holds for the manifest.
2. The signature is canonical and authorized for `sequence` in AL.

Steps 1–2 constitute **Level 1E** and apply to every manifest, including genesis and other NO_DATA manifests. **Level 1** applies to a record of an OK or DEGRADED manifest and additionally requires:

3. The leaf is valid (104 bytes, version, reserved, Section 6 rules).
4. RFC 9162 inclusion holds with `record_count` and `merkle_root`.
5. `observed_at_ms` is within the window.

A NO_DATA manifest has no records, so Level 1 and Level 2 are not defined for it. Its epoch-level verification is Level 1E or 2E.

### 13.7 Level 2E (canonical epoch) and Level 2 (canonical record)

1. Level 1E holds (Level 2E), or Level 1 holds (Level 2).
2. `canonical[sequence]` is `(C, flags)` with `C` the manifest's commitment, evaluated by Section 13.5 **from sequence 0**.
   - Starting at a checkpoint is non-conformant, because whether that checkpoint restarted after an unresolved predecessor (and therefore carries HISTORY_UNRESOLVED_BEFORE) can only be derived from earlier sequences (N20).
   - Implementations MAY reuse cached results only when the cached outputs are provably identical to full evaluation at the new as-of heights. That requires, at minimum, no new AL entries and no new admissible anchors for any witness key of a cached sequence.
3. Witness positions and reported times (Section 12.10) are reported per witness.

### 13.8 Level 3: audit

Over a range `[s_from, s_to]`, for **every** sequence `s`:

1. **Level 2E** holds (evaluated from sequence 0) with no HISTORY_UNRESOLVED_BEFORE flag.
2. **Continuity:** if `s > 0`, `previous_commitment` equals `canonical[s − 1]` and the window starts at its end. This also applies at `s = s_from`, using the canonical predecessor outside the range.
3. **NO_DATA manifests** (genesis, gap manifests, single-window NO_DATA): no leaf-level or catalog checks apply. Section 13.2 already enforces `record_count = 0`, the empty root, and NO_DATA for every multi-window manifest.
4. **OK and DEGRADED manifests:** the complete leaf set is available, and:
   - its size equals `record_count`;
   - every leaf passes Level 1 steps 3 and 5;
   - leaves are strictly ascending;
   - the recomputed Merkle root equals `merkle_root`;
   - the set of `(feed_id, asset_id, decimals)` equals the committed catalog;
   - the epoch status equals the status derived from the leaves;
   - **every** Class A leaf, whatever its status (OK, DEGRADED, INSUFFICIENT_COVERAGE, NO_DATA), recomputes exactly from its retained snapshot. The recomputation:
     - uses the parameter set of the committed methodology document;
     - requires the snapshot `T` to equal `epoch_end_ms`;
     - requires every leaf field (status, value, dispersion, all quality fields, decimals, `observed_at_ms`) to match;
     - fails the audit if a Class A snapshot is missing.
   - This is how Level 3 detects a Class A value, quality field or status that the methodology does not produce, for example NO_DATA published although inputs were sufficient (N29).
5. Anchor states and flags are recorded.

Whether an outage really occurred behind a gap manifest (Section 5.8) is an operational fact that Level 3 cannot verify. The reference audit is `byk_ref.audit_range`. It consumes retained Class A snapshots and the methodology parameters and calls `funding_composite` for every Class A leaf. Vectors are in Section 17.9 (N26, N29).

---

## 14. Proof API

The API is a convenience layer; verifiers recompute everything. All endpoints accept `as_of_ms`; the default is the latest time final on both witnesses (C12). Every response includes `as_of_ms`, `H_B`, `H_S`, AL status and head.

| Method and path | Returns |
|---|---|
| `GET /v1/genesis` | Genesis core, decoded fields, `stream_id`, publication channels |
| `GET /v1/authorization-log` | Ordered entries, bundles, anchors (with witness keys), status, head |
| `GET /v1/epochs/latest` | Latest sequence with its result |
| `GET /v1/epochs/{sequence}` | Result code, flags, canonical commitment, **all candidates** (manifest, signatures, signers, authorization, anchors, witness positions, reported times and statuses) |
| `GET /v1/epochs/{sequence}/records` | Leaves of the canonical manifest |
| `GET /v1/proofs/{sequence}/{feed_id}/{asset_id}` | Leaf, index, audit path, canonical manifest, signatures, anchors, result, flags |
| `GET /v1/class-a-inputs/{sequence}/{feed_id}/{asset_id}` | Retained input snapshot (Annex A.12) |
| `GET /v1/witness-keys/{kind}/{n}` | Witness key: hex, Solana base58 address, Base recipient |

Proof response fields: `protocol`, `stream_id`, `as_of_ms`, `H_B`, `H_S`, `al_status`, `al_head`, `result`, `flags`, `sequence`, `leaf`, `leaf_index`, `audit_path`, `manifest`, `commitment`, and `signatures[]`. Each entry of `anchors.solana[]` and `anchors.base[]` carries its identifier, height, transaction index, `reported_time_ms`, `time_status`, state, LATE and EARLY. `tree_size` and `root` are absent by design.

**Data responses** embed `"byk_proof": {"sequence", "feed_id", "asset_id", "status": "pending" | "committed", "proof_url"}`. Individual API responses are not signed.

**Retention (C9):** leaves, manifests, signatures, AL entries and bundles, anchor references and Class A input snapshots are retained for the stream's lifetime.

---

## 15. Failure and Recovery

| # | Event | Required behavior |
|---|---|---|
| F1 | Engine outage | One NO_DATA gap manifest for missed windows, then resume |
| F2 | Source loss | Statuses per methodology; permanent venue removal is a methodology version change |
| F3 | Witness outage or missed anchor | Retry; late anchors remain valid and are flagged LATE |
| F4 | ByKaranteli submitter key compromised | Operational only: protect fee balances and rotate the key. No protocol effect, because submission is permissionless and admissibility ignores submitter identity. |
| F5 | Data signer compromise or equivocation | (1) Disable the KMS key. (2) AUTHORIZE the compromised signer with `valid_until` = last known-good + 1. (3) AUTHORIZE the new signer from there. (4) Re-sign genuine manifests; commitments and G3 positions are unchanged. (5) Submit re-signed payloads. (6) CHECKPOINT any still-unresolved sequence, linking to its resolved predecessor. (7) Publish a post-mortem. |
| F6 | Fewer than M governance keys compromised | If at least M uncompromised keys are available, which Section 11.1 (`N ≥ 2M − 1`) guarantees when all other keys are available, they sign a GOVERNANCE_UPDATE removing the compromised keys. If key loss leaves fewer than M available honest keys, proceed as F11. |
| F7 | Methodology bug | Errata plus a new methodology version from a stated sequence; never modify past epochs |
| F8 | Reorg of an INCLUDED anchor | Re-submit; only finalized anchors count |
| F9 | Signing-service bug caused equivocation | CHECKPOINT the sequence with the commitment the signing service continued from (it must link to the resolved predecessor), then fix Section 5.9 enforcement |
| F10 | Governance rotation | GOVERNANCE_UPDATE signed by the current set |
| F11 | Governance below threshold (keys lost) | New stream (new genesis core and `stream_id`) announced through all Section 11.2 channels with a statement signed by the remaining keys. The old history remains verifiable. |
| F12 | Governance double-signed one `log_seq` (GOVERNANCE_FORK) | Anchor an entry at `log_seq + 1` (typically ACK) on the intended branch, signed by the fork threshold `min(M + 1, N)` of the pre-fork set |
| F13 | GOVERNANCE_FORK_TERMINAL | Conflicting fork-threshold continuations prove key misuse. Proceed as F11. |
| F14 | Witness-key spam degrades verification | No protocol action. Affected verifiers report INCOMPLETE until enumeration completes; indexers continue. |

---

## 16. Distribution Channels (Informative)

- **Explorer:** result codes, flags, all candidates, witness positions with reported times and statuses, client-side verification.
- **REST API and MCP:** `byk_proof` references.
- **x402:** USDC on Base and Solana in one `accepts` list; Bazaar registration.
- **Oracle:** Class A via Switchboard. The delivered value equals the canonical committed leaf.
- **Agent identity:** ERC-8004 and the Solana Agent Registry MAY reference the pinned `stream_id`.

## 17. Conformance and Test Vectors

All values are produced by `byk_gen_vectors.py`, which depends only on the Python standard library (`byk_ref.py` implements Keccak-256, secp256k1 with RFC 6979, and the protocol). Output: `byk_v1_test_vectors.json`. Cross-checked by `byk_xcheck.py` (pycryptodome, coincurve/libsecp256k1, eth_abi; pinned in `requirements-xcheck.txt`) and `xcheck.mjs` (ethers 6.15.0; `package-lock.json`).

Signatures are RFC 6979 deterministic and MUST be reproduced byte for byte with the same keys. Production KMS signatures differ, but MUST recover to the KMS address. In the JSON file, integers outside ±(2^53 − 1) are encoded as decimal strings so that binary64-backed JSON parsers cannot round them.

> **Test keys are public development keys (Hardhat/Anvil accounts 0–5). Never use them outside tests.** Test streams bind to Base Sepolia and Solana devnet.

Conformance: reproduce 17.1–17.9 and Annex A.9, and satisfy every case in 17.10.

### 17.1 Encoding and network constants

| Input | Expected |
|---|---|
| `keccak256('')` | `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` |
| `keccak256('abc')` | `4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45` |
| `id32('BYK.BTC.FUNDING.COMPOSITE')` | `c9b4693aac0ef55b0bff2f29ca4338df7e87f688bda4f7c6a1d66891a6722980` |
| `id32('BTC')` | `e98e2830be1a7e4156d656a7505e65d08c67660dc618072422e9c78053c261e9` |
| `int64(-48750)` | `ffffffffffff4192` |
| `int64(6872)` | `0000000000001ad8` |
| `trunc_div(-7,2)` | `-3` |
| `trunc_div(7,-2)` | `-3` |
| `trunc_div(-7,-2)` | `3` |

`id32` MUST reject: '' (empty), 'BTC ' (space), 'B TC', 'BT\nC', non-ASCII, 0x7F.

| Constant | Value |
|---|---|
| base_mainnet_chain_id | `8453` |
| base_sepolia_chain_id | `84532` |
| solana_mainnet_beta_genesis_hash_b58 | `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d` |
| solana_mainnet_beta_genesis_hash_hex | `45296998a6f8e2a784db5d9f95e18fc23f70441a1039446801089879b08c7ef0` |
| solana_devnet_genesis_hash_b58 | `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG` |
| solana_devnet_genesis_hash_hex | `ce59db5080fc2c6d3bcf7ca90712d3c2e5e6c28f27f0dfbb9953bdb0894c03ab` |
| base_eas_address | `0x4200000000000000000000000000000000000021` |

### 17.2 Genesis core, stream_id and witness keys

Threshold 2, governance (sorted): `0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc`, `0x70997970c51812dc3a010c7d01b50e0d17dc79c8`, `0x90f79bf6eb2c4f870365e785982e1f101e93b906`. Genesis epoch `1789257600000` (2026-09-13T00:00:00Z), stream name `BYK.DATALAYER.TESTVECTORS`, Base chain id 84532, Solana devnet.

Genesis core (172 bytes):
```text
42594b4701020300000001a098104c00172de24442f4e5501209928454097ac46c52782b6bd71061242d649ba3296ee00000000000014a34ce59db5080fc2c6d3bcf7ca90712d3c2e5e6c28f27f0dfbb9953bdb0894c03ab4200000000000000000000000000000000000021000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc70997970c51812dc3a010c7d01b50e0d17dc79c890f79bf6eb2c4f870365e785982e1f101e93b906
```
`stream_id`:
```text
aa9c3fba4bd9e4e8f9ccfa4423a3bcbae240653fa2fa343c578034ae78fa2892
```
| Witness key | keccak256 | Solana address (base58) | Base recipient |
|---|---|---|---|
| data_sequence_0 | `320191eab08b34d6194edcd4bd320c323c95ef3fc2ccf7e77c8c092229f93563` | `4NCmrhDhkN3aCgMbp54jDKx7EtmRxpLMjncbETPZGemY` | `0xbd320c323c95ef3fc2ccf7e77c8c092229f93563` |
| data_sequence_1 | `5f404b0dd907562d2d94a14b34c06fac9c45e8ba2e527631e83b0b49bf5e4890` | `7QpbNBBuiB44DXSehmgo6mg7A4ypzbLvdiTuNjLNvdgs` | `0x34c06fac9c45e8ba2e527631e83b0b49bf5e4890` |
| al_log_seq_1 | `4790a8f374dc767c4c95eb25ebbf2d8a58083b2e094a334b30defb237e50b355` | `5pMtJcnyYcCb5wRY9M7nwDV6D57XTL4r7fiTQSYRPC8c` | `0xebbf2d8a58083b2e094a334b30defb237e50b355` |
| genesis | `d143e2a7ac631f6e2952581f782d136a595898380f296ce783f171560578244b` | `F5tFKuLmZtRSXZqUd3MWr7fQ1s3TJECmnD2v29hCFJCA` | `0x782d136a595898380f296ce783f171560578244b` |

### 17.3 Epoch 0, epoch 1 records and Merkle tree

`M0` (sequence 0, NO_DATA):
```text
42594b44010300000000000000000000000001a098104c00000001a09814dfe00000000000000000aa9c3fba4bd9e4e8f9ccfa4423a3bcbae240653fa2fa343c578034ae78fa2892c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4700000000000000000000000000000000000000000000000000000000000000000f6a9558708bc7ad51652433412f3bebd0b1399a3c7bcbbf7e2e8b01c826306f80874bea7da3827c6ae3bee1f9b3e605927a392f4fef0080fbba4d3d559734226
```
`C0 = 3c9567c0e237e9e0fc074edaf831e43ca9187f2bae81644ef82afb7c22cdea40`; S1 signature `f8b3076ca03c1961686477085affec72e0a9db06215408f250ed4cf01b08e9e34ab059387ccd531dcb935eb5d8a3a1d3a1fa83c665fdcbd83bac37be6c1faec201`

**Leaf 0**: SOL funding composite (Class A, negative value, from snapshot) (`BYK.SOL.FUNDING.COMPOSITE` / `SOL`)
```text
01010a00258bbe571b178d42b2d9944e617e7adacee828dcca100cfe4edc6b4818df825b0a3ec4fc70eaf64faf6eeda4e9b2bd4742a785464053aa23afad8bd24650e86f000001a0981973c0fffffffffffe2fae0005000724450001001712400000000000002b7e
```
leaf_hash `d72190127ddd446cef7ec34115d9155513e8ee64174856be18b80965e43e338d`  
audit path: `7407b9d63c5fdbd6283304e633a74800158ec4de6b1d84a0544c8289cf8820df`, `d33cf8b0cee69e27c0a99166219626a26098577010d2ed4de51459f45bb62005`

**Leaf 1**: BTC VPIN (Class B) (`BYK.BTC.VPIN` / `BTC`)
```text
01000400616bba5f4356cb49392096b70dc18b123c2dfe7c27cb26520be9bcea1fe5e0a8e98e2830be1a7e4156d656a7505e65d08c67660dc618072422e9c78053c261e9000001a0981973c00000000000001ad8000b000b271000000000032c0000000000000000
```
leaf_hash `7407b9d63c5fdbd6283304e633a74800158ec4de6b1d84a0544c8289cf8820df`  
audit path: `d72190127ddd446cef7ec34115d9155513e8ee64174856be18b80965e43e338d`, `d33cf8b0cee69e27c0a99166219626a26098577010d2ed4de51459f45bb62005`

**Leaf 2**: ETH funding composite (Class A, INSUFFICIENT_COVERAGE, from snapshot) (`BYK.ETH.FUNDING.COMPOSITE` / `ETH`)
```text
01020a008101bb83065325d0a1fa1ab7e8316a2c372da708f2ffdb3d99d362f15616170eaaaebeba3810b1e6b70781f14b2d72c1cb89c0b2b320c43bb67ff79f562f5ff4000001a0981973c000000000000000000003000723aa0001001712400000000000000000
```
leaf_hash `cc737f6251b398a947d7754974d6f350cdddecbd6054ea72e75d0f1c42139db5`  
audit path: `d2a80288ae6d469c3e85bf38d0482138cc938ec542620dd8c63e8c187ba6756d`, `b256b20bec1cae3df82801c8d1bad11f57c2aef0802cc7797bb8391343459d20`

**Leaf 3**: BTC funding composite (Class A, from snapshot) (`BYK.BTC.FUNDING.COMPOSITE` / `BTC`)
```text
01010a00c9b4693aac0ef55b0bff2f29ca4338df7e87f688bda4f7c6a1d66891a6722980e98e2830be1a7e4156d656a7505e65d08c67660dc618072422e9c78053c261e9000001a0981973c0000000000001d0520005000724450001001712400000000000002b7e
```
leaf_hash `d2a80288ae6d469c3e85bf38d0482138cc938ec542620dd8c63e8c187ba6756d`  
audit path: `cc737f6251b398a947d7754974d6f350cdddecbd6054ea72e75d0f1c42139db5`, `b256b20bec1cae3df82801c8d1bad11f57c2aef0802cc7797bb8391343459d20`

Internal node (0,1): `b256b20bec1cae3df82801c8d1bad11f57c2aef0802cc7797bb8391343459d20`  
Merkle root: `63d98ab47de6834a5dbb0c9d60106354e1be2e30ed684191336ae0a58ee05559`

**Tree-size finding (Section 8.5):** proof for leaf 0 of a 5-leaf tree verifies against the same root when tree_size 6 is claimed → `True`.

### 17.4 Epoch 1 manifest, commitment, signature

```text
42594b44010100000000000000000001000001a09814dfe0000001a0981973c00000000400000000aa9c3fba4bd9e4e8f9ccfa4423a3bcbae240653fa2fa343c578034ae78fa289263d98ab47de6834a5dbb0c9d60106354e1be2e30ed684191336ae0a58ee055593c9567c0e237e9e0fc074edaf831e43ca9187f2bae81644ef82afb7c22cdea40f6a9558708bc7ad51652433412f3bebd0b1399a3c7bcbbf7e2e8b01c826306f80874bea7da3827c6ae3bee1f9b3e605927a392f4fef0080fbba4d3d559734226
```
`C1 = e2fce44df816d8ce513df26f9d8455556caaec2b91f9985dcd5da0ed0e720f9d`

S1 (`0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266`) signature:
```text
cdf678e0013406bbc21ecaeaa9644d898b74037beafd85ebab0ecdd6fac0665b44485c4f095cbb497cf8d6611a0bb525550224a5ebfb3f869cae9ce414ee692c00
```
`r = cdf678e0013406bbc21ecaeaa9644d898b74037beafd85ebab0ecdd6fac0665b`, `s = 44485c4f095cbb497cf8d6611a0bb525550224a5ebfb3f869cae9ce414ee692c`, `recovery_id = 0`, EVM `v = 27`

### 17.5 Authorization log entries

**E1** (log_seq 1: S1 authorized for sequences [0, unbounded)):
```text
42594b4c010100280000000000000001aa9c3fba4bd9e4e8f9ccfa4423a3bcbae240653fa2fa343c578034ae78fa28920000000000000000000000000000000000000000000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000ffffffffffffffff
```
entry_hash `6e633036bcfae38330538cd571f8a97de4e000a8fb23567ccf53cfc9601bb95b`; bundle (G1, G2):
```text
48e11237fe34d3e7fefa444b6fa16ce08aed7f2c341bbe3c577302d2c0b912e822b45656d1d7dc19c0355aa73c9e414d303b65fc8b7eace8c9e3bef088306bc201a988935e11eff182b3f0fa01f99da4e72797fd00297b579a7dc06e8d1752dc115ccf8b590071345809224a44b4394e11b1dfa943eac580661b9a6457afedf3f900
```
| Entry | Meaning | Prefix (full hex and bundles in JSON) |
|---|---|---|
| E2b | CHECKPOINT seq 2 → C2a | `42594b4c0103002800000000…` |
| E2c | CHECKPOINT seq 2 → C2b | `42594b4c0103002800000000…` |
| E2d | AUTHORIZE S1 [0, 2) (retroactive revocation) | `42594b4c0101002800000000…` |
| E3d | AUTHORIZE S2 [2, unbounded) | `42594b4c0101002800000000…` |
| E2bad | CHECKPOINT seq 2 → C2bad (non-linking) | `42594b4c0103002800000000…` |
| E2restart | CHECKPOINT seq 3 → C3 | `42594b4c0103002800000000…` |
| E2e | GOVERNANCE_UPDATE → {G1, G2, G4}, M=2 (signed G2, G3) | `42594b4c0102004000000000…` |
| E3e | AUTHORIZE S2 [4, unbounded) (signed by new set G1, G4) | `42594b4c0101002800000000…` |
| ACK3→E2b | ACK on E2b (bundles: G1+G2+G3, and G1+G2 only) | `42594b4c0104000000000000…` |
| ACK3→E2c | ACK on E2c (bundle G1+G2+G3) | `42594b4c0104000000000000…` |
| CP3→E2b | CHECKPOINT at log_seq 3 on E2b, 3 signatures (non-ACK continuation) | `42594b4c0103002800000000…` |

Governance update heads: `log[E1,E2e,E3e(new set G1,G4)]` → 3; `log[E1,E2e,E3e(G1,G3)]` → 2.

Governance bounds (Section 11.1, `N ≥ 2M − 1`): 2-of-2 → invalid, 3-of-4 → invalid, 2-of-3 → valid, 1-of-1 → valid, 2-of-4 → valid.

### 17.6 Witness payloads

| Schema | UID |
|---|---|
| `uint64 sequence,bytes32 commitment,bytes manifest,bytes signature` | `71160dd1d38fa3cea9fdead2779d18599c9582e49e442bfd3ba7d1198068a684` |
| `uint64 logSeq,bytes32 entryHash,bytes entry,bytes governanceSignatures` | `fa05b015396340e1dad97871de2420c86aafc90bfe19dc3fa1c8c678db39c68a` |
| `bytes32 streamId,bytes genesisCore` | `66db46fb9d1a307ccafc25945415e2b6d14a68ce22d22c3943c0f21671087bcd` |

Epoch 1 EAS attestation: recipient `0x34c06fac9c45e8ba2e527631e83b0b49bf5e4890` (witness key, data sequence 1); `data`:
```text
0000000000000000000000000000000000000000000000000000000000000001e2fce44df816d8ce513df26f9d8455556caaec2b91f9985dcd5da0ed0e720f9d0000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000c842594b44010100000000000000000001000001a09814dfe0000001a0981973c00000000400000000aa9c3fba4bd9e4e8f9ccfa4423a3bcbae240653fa2fa343c578034ae78fa289263d98ab47de6834a5dbb0c9d60106354e1be2e30ed684191336ae0a58ee055593c9567c0e237e9e0fc074edaf831e43ca9187f2bae81644ef82afb7c22cdea40f6a9558708bc7ad51652433412f3bebd0b1399a3c7bcbbf7e2e8b01c826306f80874bea7da3827c6ae3bee1f9b3e605927a392f4fef0080fbba4d3d5597342260000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041cdf678e0013406bbc21ecaeaa9644d898b74037beafd85ebab0ecdd6fac0665b44485c4f095cbb497cf8d6611a0bb525550224a5ebfb3f869cae9ce414ee692c0000000000000000000000000000000000000000000000000000000000000000
```
E1 EAS `data`:
```text
00000000000000000000000000000000000000000000000000000000000000016e633036bcfae38330538cd571f8a97de4e000a8fb23567ccf53cfc9601bb95b00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000007842594b4c010100280000000000000001aa9c3fba4bd9e4e8f9ccfa4423a3bcbae240653fa2fa343c578034ae78fa28920000000000000000000000000000000000000000000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000ffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000000000000000008248e11237fe34d3e7fefa444b6fa16ce08aed7f2c341bbe3c577302d2c0b912e822b45656d1d7dc19c0355aa73c9e414d303b65fc8b7eace8c9e3bef088306bc201a988935e11eff182b3f0fa01f99da4e72797fd00297b579a7dc06e8d1752dc115ccf8b590071345809224a44b4394e11b1dfa943eac580661b9a6457afedf3f900000000000000000000000000000000000000000000000000000000000000
```
Genesis EAS `data`:
```text
aa9c3fba4bd9e4e8f9ccfa4423a3bcbae240653fa2fa343c578034ae78fa2892000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000ac42594b4701020300000001a098104c00172de24442f4e5501209928454097ac46c52782b6bd71061242d649ba3296ee00000000000014a34ce59db5080fc2c6d3bcf7ca90712d3c2e5e6c28f27f0dfbb9953bdb0894c03ab4200000000000000000000000000000000000021000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc70997970c51812dc3a010c7d01b50e0d17dc79c890f79bf6eb2c4f870365e785982e1f101e93b9060000000000000000000000000000000000000000
```
Solana data memo (536 bytes; transaction includes the data witness key for sequence 1):
```text
BYK1 42594b44010100000000000000000001000001a09814dfe0000001a0981973c00000000400000000aa9c3fba4bd9e4e8f9ccfa4423a3bcbae240653fa2fa343c578034ae78fa289263d98ab47de6834a5dbb0c9d60106354e1be2e30ed684191336ae0a58ee055593c9567c0e237e9e0fc074edaf831e43ca9187f2bae81644ef82afb7c22cdea40f6a9558708bc7ad51652433412f3bebd0b1399a3c7bcbbf7e2e8b01c826306f80874bea7da3827c6ae3bee1f9b3e605927a392f4fef0080fbba4d3d559734226 cdf678e0013406bbc21ecaeaa9644d898b74037beafd85ebab0ecdd6fac0665b44485c4f095cbb497cf8d6611a0bb525550224a5ebfb3f869cae9ce414ee692c00
```
Solana AL memo for E1 (507 bytes):
```text
BYKL1 42594b4c010100280000000000000001aa9c3fba4bd9e4e8f9ccfa4423a3bcbae240653fa2fa343c578034ae78fa28920000000000000000000000000000000000000000000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000ffffffffffffffff 48e11237fe34d3e7fefa444b6fa16ce08aed7f2c341bbe3c577302d2c0b912e822b45656d1d7dc19c0355aa73c9e414d303b65fc8b7eace8c9e3bef088306bc201a988935e11eff182b3f0fa01f99da4e72797fd00297b579a7dc06e8d1752dc115ccf8b590071345809224a44b4394e11b1dfa943eac580661b9a6457afedf3f900
```
Solana genesis memo (350 bytes):
```text
BYKG1 42594b4701020300000001a098104c00172de24442f4e5501209928454097ac46c52782b6bd71061242d649ba3296ee00000000000014a34ce59db5080fc2c6d3bcf7ca90712d3c2e5e6c28f27f0dfbb9953bdb0894c03ab4200000000000000000000000000000000000021000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc70997970c51812dc3a010c7d01b50e0d17dc79c890f79bf6eb2c4f870365e785982e1f101e93b906
```
Size bounds: AL memo max 855 (GOVERNANCE_UPDATE with N=4 and a 4-signature bundle), genesis memo max 390, reference overhead 295, memo budget 937.

### 17.7 Canonical resolution, fork and adversarial scenarios

All scenarios use as-of time `T_TEST = 1789259460000` (T0 + 6 epochs + 60 s), so `S_max(T_TEST) = 5`. Manifests are NO_DATA unless stated and signed by S1 (M2a, M3 also by S2):

- `M2a`: seq 2, `[T0+600000, T0+900000)`, prev C1 → `C2a = dc7f853d2effa20baf2a6056f72efa5cd573a41ed3db58710bd239c457a32c0e`
- `M2b`: seq 2, gap `[T0+600000, T0+1200000)`, prev C1 → `C2b = 70be1cd2066db656c81390ae417d57adaeebb2a8569aed3b017d99b2c628c6b6`
- `M2bad`: seq 2, `[T0+600000, T0+900000)`, prev **C0** → `C2bad = a5b9cc1dc7475baf42f01743573c397f5e39664d79015702bbf6537ab3142dee`
- `M3`: seq 3, prev C2a → `C3 = 9926ac504730d739234bee33fce684509355463ae9adc6cd9fc3eb0814000dc3`; `M4`: seq 4, prev C3 → `C4 = 5cfd99c0ed56b1997797fdf3a081cee58152cb88b745352c27d3e716b1cc1b00`; `M5`: seq 5, prev C4 → `C5 = a7c4b17aa1de12347c5d5a5c6b8fa04967e15ed7c0ec887666796214fcbc68c6`
- `M1x`: seq 1, `[T0+300000, T0+600000)`, prev C0, differs from M1 → `C1x = fad879dba2556c7b40355632c6fda8c955acb1f27a68690c38cd8f97745cb8b7`
- `M_far`: seq 1000000000, window `[T0 + 1000000000·300000, +300000)`: satisfies the stream sequence rule but ends after T
- `M_max`: seq 2^64 − 1, window `[floor((2^64 − 1 − 300000)/300000)·300000, +300000)`: violates `epoch_start_ms ≥ G + sequence·300000`
- garbage signature: 65 bytes of `0x01`

| Scenario | AL entries | Payload (manifest, signature) pairs | Expected `canonical[0..5]` or AL status |
|---|---|---|---|
| A_fork_no_action | E1 | P_FORK | 0: C0 · 1: C1 · 2: UNRESOLVED[EQUIVOCATION] · 3: UNRESOLVED · 4: UNRESOLVED · 5: UNRESOLVED |
| B_checkpoint_C2a | E1, E2b | P_FORK | 0: C0 · 1: C1 · 2: C2a · 3: C3 · 4: UNRESOLVED · 5: UNRESOLVED |
| C_checkpoint_C2b | E1, E2c | P_FORK | 0: C0 · 1: C1 · 2: C2b · 3: UNRESOLVED · 4: UNRESOLVED · 5: UNRESOLVED |
| D_revoke_and_resign | E1, E2d, E3d | P_FORK + S2 signatures on M2a, M3 | 0: C0 · 1: C1 · 2: C2a · 3: C3 · 4: UNRESOLVED · 5: UNRESOLVED |
| E0_orphan_does_not_block | E1 | P_BADLINK | 0: C0 · 1: C1 · 2: C2a · 3: C3 · 4: UNRESOLVED · 5: UNRESOLVED |
| E1_checkpoint_non_linking | E1, E2bad | P_BADLINK | 0: C0 · 1: C1 · 2: UNRESOLVED[CHECKPOINT_CONFLICT] · 3: UNRESOLVED · 4: UNRESOLVED · 5: UNRESOLVED |
| F_restart_after_unresolved | E1, E2restart | P_FORK + M4, M5 | 0: C0 · 1: C1 · 2: UNRESOLVED[EQUIVOCATION] · 3: C3[HISTORY_UNRESOLVED_BEFORE] · 4: C4[HISTORY_UNRESOLVED_BEFORE] · 5: C5[HISTORY_UNRESOLVED_BEFORE] |
| G1_governance_fork | E1, E2b, E2c | P_FORK | GOVERNANCE_FORK |
| G2_fork_resolved_by_ack_3of3 | E1, E2b, E2c, ACK3→E2b (3 sigs) | P_FORK | 0: C0 · 1: C1 · 2: C2a · 3: C3 · 4: UNRESOLVED · 5: UNRESOLVED |
| G3_ack_below_fork_threshold | E1, E2b, E2c, ACK3→E2b (2 sigs) | P_FORK | GOVERNANCE_FORK |
| G4_conflicting_acks | E1, E2b, E2c, ACK3→E2b (3), ACK3→E2c (3) | P_FORK | GOVERNANCE_FORK_TERMINAL |
| G5_non_ack_continuation | E1, E2b, E2c, CP3→E2b (3 sigs) | P_FORK | GOVERNANCE_FORK |
| G6_same_ack_two_bundles | E1, E2b, E2c, ACK3→E2b with 3-sig and 2-sig bundles | P_FORK | 0: C0 · 1: C1 · 2: C2a · 3: C3 · 4: UNRESOLVED · 5: UNRESOLVED |
| H_signature_binding | E1 | (M0, S1), (M1, garbage), (M1x, S1 signature over C1) | 0: C0 · 1: UNRESOLVED · 2: UNRESOLVED · 3: UNRESOLVED · 4: UNRESOLVED · 5: UNRESOLVED |
| I_far_sequence_dos | E1 | P_FORK + (M_far, S1), (M_max, S1) | 0: C0 · 1: C1 · 2: UNRESOLVED[EQUIVOCATION] · 3: UNRESOLVED · 4: UNRESOLVED · 5: UNRESOLVED |

Notes:

- **F:** the flag HISTORY_UNRESOLVED_BEFORE is inherited by 4 and 5. A verifier that starts evaluation at the checkpoint (sequence 3) would omit it and is non-conformant (N20).
- **H:** a reading that combines M1 from one anchor with a valid signature over C1 carried next to a different manifest would put C1 into `Cand(1)`. That reading is non-conformant (N21).
- **I:** neither far manifest is a candidate. The resolver range is `0..S_max(T_TEST) = 0..5`, independent of any signed sequence number (N22).

### 17.8 Witness time

Solana slot times (seconds, `null` = unavailable): `{"100": 1789258201, "101": null, "102": 1789258203, "103": null}`. Base block timestamps: `{"5000": 1789258200, "5001": 1789258202, "5002": 1789258204}`.

| Function | Expected |
|---|---|
| `solana_as_of_slot(T=1789258202000)` | `100` |
| `solana_as_of_slot(T=1789258203000)` | `102` |
| `base_as_of_block(T=1789258203000)` | `5001` |
| `solana_reported_time(100)` | `[1789258201000, "REPORTED"]` |
| `solana_reported_time(101)` | `[1789258203000, "INFERRED"]` |
| `solana_reported_time(103)` | `[null, "UNAVAILABLE"]` |

### 17.9 Level 3 audit

As-of time `1789259160000` (S_max = 4). The audit catalog is given as input: `BYK.BTC.FUNDING.COMPOSITE`/`BTC`/10/class A, `BYK.ETH.FUNDING.COMPOSITE`/`ETH`/10/class A, `BYK.SOL.FUNDING.COMPOSITE`/`SOL`/10/class A, `BYK.BTC.VPIN`/`BTC`/4/class B. In production it is read from the registry whose bytes hash to `methodology_hash`. AL = [E1]; all manifests are signed by S1.

- Sequence 0 `M0` (genesis, NO_DATA) → sequence 1 `M1` (DEGRADED, 4 catalog leaves; Class A leaves computed from snapshots).
- Sequence 2 `A2`: **gap** NO_DATA, window `[T0+600000, T0+1200000)` → `CA2 = 70be1cd2066db656c81390ae417d57adaeebb2a8569aed3b017d99b2c628c6b6`.
- Sequence 3 `A3`: DEGRADED, window `[T0+1200000, T0+1500000)`, 4 catalog leaves (Class A from snapshots at T = T0+1500000), prev CA2 → `CA3 = f37feb6dce9bebd974de38492200539b7d7077ea0c2b1e93babec7e38088e725`.
- Variants of sequence 3 (full bytes in `audit.variants`): `A3bad_missing_catalog_leaf` → `a33c546c82bcd83b…`, `A3_tampered_value` → `c54106998553d7c1…`, `A3_tampered_source_count` → `e48fcee55d721d51…`, `A3_no_data_despite_inputs` → `2197d846117a4fb7…`, `A3_insufficient_wrong_quality` → `7bdc518d262647b7…`.

Class A snapshots for sequences 1 and 3 are in `audit.class_a_snapshots` (key `sequence|feed|asset`). The methodology parameters are `audit.methodology_parameters`. Epoch 3 variants each change one thing, re-derive the Merkle root, and are signed by S1, so only the methodology recomputation can detect them.

| Case | Epoch 3 payload | Range | Expected |
|---|---|---|---|
| AUD1 | A3 | [0,3] | PASS |
| AUD2 | A3bad (VPIN leaf dropped) | [0,3] | FAIL (sequence 3: leaf set or decimals differ from catalog) |
| AUD3 | A3 | [0,4] | FAIL (sequence 4: not CANONICAL) |
| AUD4 | A3 | [3,3] | PASS |
| AUD5 | BTC value 118866 → 118867 | [0,3] | FAIL (sequence 3: Class A recomputation mismatch for BYK.BTC.FUNDING.COMPOSITE/BTC (value)) |
| AUD6 | BTC source_count 5 → 6 | [0,3] | FAIL (sequence 3: Class A recomputation mismatch for BYK.BTC.FUNDING.COMPOSITE/BTC (source_count)) |
| AUD7 | BTC leaf rewritten as NO_DATA although inputs are sufficient | [0,3] | FAIL (sequence 3: Class A recomputation mismatch for BYK.BTC.FUNDING.COMPOSITE/BTC (status, value, source_count, coverage_bps, outlier_count, max_source_age_ms, dispersion)) |
| AUD8 | ETH INSUFFICIENT_COVERAGE leaf with source_count 4, coverage_bps 9999 | [0,3] | FAIL (sequence 3: Class A recomputation mismatch for BYK.ETH.FUNDING.COMPOSITE/ETH (source_count, coverage_bps)) |
| AUD9 | A3, snapshot for SOL at sequence 3 withheld | [0,3] | FAIL (sequence 3: Class A snapshot missing for BYK.SOL.FUNDING.COMPOSITE/SOL) |
| AUD10 | A3, auditor given parameters with outlier_k = 6 | [0,3] | FAIL (sequence 1: Class A snapshot T or parameters differ for BYK.SOL.FUNDING.COMPOSITE/SOL; sequence 1: Class A snapshot T or parameters differ for BYK.ETH.FUNDING.COMPOSITE/ETH; sequen…) |

### 17.10 Negative and non-conformance cases

| # | Case | Required result |
|---|---|---|
| N1 | Epoch 1 signature with `s → n - s`, recovery id flipped (`epoch1.high_s_variant_must_be_rejected`) | reject |
| N2 | Any bit flipped in any leaf | inclusion fails |
| N3 | Non-zero reserved bytes (manifest 6–7, 36–39; genesis core 7, 108–111; AL headers and bodies) | reject |
| N4 | Wrong structure length or trailing bytes; ACK with non-empty body | reject |
| N5 | Leaf status 2 or 3 with non-zero value or dispersion | reject |
| N6 | NO_DATA with record_count > 0, or OK/DEGRADED with record_count = 0 | reject |
| N7 | Bundle unsorted, duplicated, from non-member, or below threshold (`E3e_bundle_removed_member_G1_G3_must_fail`) | entry not applied |
| N8 | Governance fork without an ACK continuation meeting the fork threshold (G1, G3), or whose continuation is not ACK (G5) | GOVERNANCE_FORK |
| N9 | Two distinct ACK continuations meeting the fork threshold; they necessarily reference different fork entries (G4) | GOVERNANCE_FORK_TERMINAL |
| N10 | CHECKPOINT whose manifest does not link to a resolved predecessor (E1) | UNRESOLVED [CHECKPOINT_CONFLICT] |
| N11 | Solana precompile given `message = C1` instead of `M1` | verification fails |
| N12 | Tree size not taken from `record_count` | non-conformant verifier |
| N13 | Anchor from a network whose `eth_chainId` or `getGenesisHash` differs from the genesis core | ignored |
| N14 | EAS attestation with wrong recipient, outer field mismatch, or non-canonical ABI | inadmissible |
| N15 | Solana anchor without the matching static witness key, or with malformed memo | inadmissible |
| N16 | Trust root obtained only from witness data or Proof API | non-conformant verifier |
| N17 | CANONICAL reported although a required witness-key enumeration was incomplete | non-conformant (must be INCOMPLETE) |
| N18 | Admissibility decided using submitter identity | non-conformant verifier |
| N19 | `id32` input containing space, control or non-ASCII | reject |
| N20 | Level 2 evaluation started at a checkpoint instead of sequence 0, losing HISTORY_UNRESOLVED_BEFORE (F) | non-conformant verifier |
| N21 | Candidate formed from a manifest and a signature taken from different anchors (H) | non-conformant verifier |
| N22 | Resolver loop bound derived from a candidate or checkpoint sequence instead of `S_max(T)` (I); manifest with `epoch_start_ms < G + sequence·300000` treated as structurally valid (M_max) | non-conformant verifier / reject |
| N23 | Genesis core or GOVERNANCE_UPDATE with `N < 2M − 1` (2-of-2, 3-of-4) | reject |
| N24 | Annex A numeric input taken from a binary64 value instead of its raw lexeme, or a lexeme violating A.2 (exponent, sign on unsigned, > 24 characters, > 18 fractional digits) | non-conformant / input invalid |
| N25 | Annex A rate input with `|hourly| > 2^62 − 1` (rc4 overflow inputs ±9·10^18), or any methodology output whose value or dispersion does not fit int64 | input invalid / non-conformant |
| N26 | Level 3 applying leaf or catalog checks to a NO_DATA manifest (genesis or gap), or skipping continuity at the range start | non-conformant auditor |
| N27 | Integer input not matching `^[0-9]{1,19}$`, in an undeclared unit, exceeding 2^63 − 1 after scaling, or interval outside [60000, 86400000] ms | input invalid |
| N28 | Methodology parameters with `max_weight_bps × min_contributors < 10000` or any other A.10 violation | methodology invalid |
| N29 | Level 3 audit that does not recompute every Class A leaf (any status) from its snapshot, accepts a missing snapshot, or uses parameters other than the committed methodology's (AUD5–AUD10) | non-conformant auditor |
| N30 | Methodology parameter out of the A.10 bounds, non-integer (including boolean), or parameter set with missing or extra keys (`outlier_k = 10^100`) | methodology invalid |

---

## Annex A. BYK_FUNDING_COMPOSITE_V1 Methodology (Proposed)

**Status:** the structure is proposed for adoption; numeric parameters are **PROPOSED DEFAULTS** (C1–C2). This annex becomes a separately versioned methodology document committed through the methodology registry.

### A.1 Scope

| Feed name | Asset | Decimals | Class | Unit |
|---|---|---|---|---|
| `BYK.BTC.FUNDING.COMPOSITE` | `BTC` | 10 | A | fraction per hour |
| `BYK.ETH.FUNDING.COMPOSITE` | `ETH` | 10 | A | fraction per hour |
| `BYK.SOL.FUNDING.COMPOSITE` | `SOL` | 10 | A | fraction per hour |

Instruments are linear perpetuals margined in USDT or USDC, one per venue per asset (A.11). Inverse (coin-margined) contracts are out of scope. Display APR (`value × 8760 × 10^-10`) is not part of the protocol.

### A.2 Numeric lexemes and arithmetic

Venue inputs are of two kinds. **Decimal lexemes:** funding rate, OI value, contract size, mark price. **Integer lexemes:** funding interval, settlement timestamp, OI timestamp, mark-price timestamp. Each is read in the unit the catalog declares for it (A.11).

**Source of the lexeme.** Every venue numeric input, of either kind, is taken as a raw lexeme from the venue response bytes, or from the catalog when the catalog declares a constant (for example a fixed interval):

- for a JSON string, its content;
- for a JSON number, the exact characters of the number token as they appear in the response.

Adapters MUST obtain lexemes without converting through binary floating point. For example, a parser configured to preserve number tokens, or a raw-token extractor. A value that has passed through binary64 is non-conformant (N24).

**Decimal lexeme grammar and bounds.** A decimal lexeme is invalid unless all of the following hold:

- non-negative quantities (open interest, contract size, mark price) match `^[0-9]+(\.[0-9]+)?$`;
- funding rates match `^-?[0-9]+(\.[0-9]+)?$`;
- it has at most 24 characters and at most 18 fractional digits.

No exponent, leading `+`, whitespace, separator or leading or trailing dot is allowed.

**Integer lexeme grammar and normalization.** An integer lexeme matches `^[0-9]{1,19}$` (leading zeros permitted). It is multiplied by its catalog unit factor:

- timestamps: `s` × 1000, `ms` × 1;
- intervals: `h` × 3600000, `s` × 1000, `ms` × 1.

The result is in milliseconds and MUST be ≤ `2^63 − 1`, otherwise the input is invalid. Other units are invalid in v1.

**Arithmetic.** Values are exact rationals. Truncation toward zero happens once, at the stated points. Under these bounds and the range rules of A.4 and A.6:

- with the parameter bounds of A.10, every intermediate numerator, denominator and sum in A.4–A.8 is below `2^240`, so it fits in a signed 256-bit integer. The largest intermediates are:
  - OI rational products: numerators < `10^72`, denominators ≤ `10^54`;
  - `Σ w × hourly` < `65535 × 2^93 × 2^62` < `2^171`;
  - `outlier_k × MAD` ≤ `1000 × 2^63`;
  - `cap × Σ oi_usd` < `2^93`;
- implementations MAY use 256-bit integers and MUST otherwise use arbitrary precision (Section 4.3).

### A.3 Inputs per catalog venue, as of `T = epoch_end_ms`

| Input | Kind and unit (from catalog) | Rule |
|---|---|---|
| Settled funding rate | decimal; `rate_unit` ∈ {`FRACTION`, `PERCENT`, `BPS`} | Most recent realized rate with `settlement_ts < T`. `units = trunc(rate × 10^10)` for FRACTION, `× 10^8` for PERCENT, `× 10^6` for BPS. |
| Settlement interval | integer; `interval_unit` ∈ {`h`, `s`, `ms`} | `interval_ms` in effect for that settlement, MUST be within `[60000, 86400000]` |
| Settlement timestamp | integer; `s` or `ms` | `settlement_ts < T` |
| Open interest quantity | decimal; `oi_unit` ∈ {`QUOTE`, `BASE`, `CONTRACTS`} | `oi_value` |
| OI timestamp | integer; `s` or `ms` | `oi_ts < T` |
| Mark price | decimal; quote units per base unit | Same instrument; required unless `oi_unit = QUOTE` |
| Mark-price timestamp | integer; `s` or `ms` | `price_ts < T`; required unless `oi_unit = QUOTE` |

### A.4 Open interest in USD

Using exact rational arithmetic:

| `oi_unit` | `oi_quote` |
|---|---|
| `QUOTE` | `oi_value` |
| `BASE` | `oi_value × mark_price` |
| `CONTRACTS` | `oi_value × contract_size × mark_price` |

Then `oi_usd = trunc(oi_quote)`, an integer. In v1, one unit of USDT or USDC is defined as 1 USD. A stablecoin depeg can distort weights but never the funding-rate unit.

The OI input is invalid if any of the following holds:

- the mark price is required and missing;
- `price_ts ≥ T`;
- `|oi_ts − price_ts| > price_max_skew_ms`;
- `oi_usd = 0` or `oi_usd > 2^63 − 1`.

### A.5 Reproducibility

The composite is deterministic given the input snapshot (A.12). Open-interest and mark-price observations at `T` may not be re-acquirable later, so reproducibility is defined against the retained snapshot, not against independent re-acquisition. Predicted-rate feeds MAY be added under distinct names.

### A.6 Normalization and eligibility

`units_v` per A.3 and `hourly_v = trunc_div(units_v × 3600000, interval_ms_v)`.

The rate input is invalid if any of the following holds:

- `|units_v| > 2^63 − 1`;
- `|hourly_v| > 2^62 − 1`;
- `interval_ms_v` is outside `[60000, 86400000]`.

The hourly bound is what keeps leaves encodable. `R` is a weighted average of hourly values, so `|R| ≤ 2^62 − 1`, and every deviation `|hourly_v − R| ≤ 2^63 − 2`. Therefore `value` and `dispersion` always fit int64.

A venue is excluded (and not counted as an outlier) if any of the following holds:

- `T − settlement_ts > stale_factor × interval_ms`;
- its OI input is invalid (A.4);
- `T − oi_ts > oi_max_age_ms`;
- any input timestamp is `≥ T`.

### A.7 Outlier filter

1. **Weighted median `m`:** sort eligible venues by `(hourly, venue_id)`, where `venue_id = id32(venue name)`. `m` is the `hourly` of the first venue where `2 × cumulative oi_usd ≥ total`.
2. **MAD:** the median of `|hourly_v − m|`. For an even count, `trunc_div` of the sum of the two middle values by 2.
3. **Threshold:** `tau = max(outlier_k × MAD, outlier_floor)`.
4. **Exclusion:** venues with `|hourly_v − m| > tau` are outliers. The rest are contributors.

### A.8 Evaluation order, weights, composite, leaf fields and status

Evaluate strictly in this order. Later steps are not executed once a status is fixed.

1. **Validate inputs** (A.2–A.4, A.6) and determine the eligible set.
2. **NO_DATA:** if no venue is eligible, the leaf is `status = NO_DATA`, `value = 0`, `dispersion = 0`, `source_count = 0`, `outlier_count = 0`, `coverage_bps = 0`, `max_source_age_ms = 0`, and `expected_source_count` = catalog size. No median, weights or composite are computed.
3. **Outlier filter** (A.7). The contributor set is never empty, because the weighted-median venue has deviation 0. Compute `source_count`, `outlier_count`, `coverage_bps` and `max_source_age_ms` per the table below. The `coverage_bps` denominator is at least the contributors' OI, which is greater than 0.
4. **INSUFFICIENT_COVERAGE:** if `source_count < min_contributors`, the leaf is `status = INSUFFICIENT_COVERAGE`, `value = 0`, `dispersion = 0`, with the step-3 fields. No weights or composite are computed.
5. **Weights, composite, dispersion and status OK or DEGRADED** as below.

`min_contributors ≥ 1` and a non-empty catalog are required.

**Weights (maximum-share cap):** let `n` = contributors and `cap = max_weight_bps`. Step 5 runs only when `n ≥ min_contributors`, and A.10 requires `cap × min_contributors ≥ 10000`, so `cap × n ≥ 10000` always holds here. There is no infeasible case and no fallback.

1. Sort contributors by `(oi_usd descending, venue_id)`.
2. For `k = 0, 1, …`: compute `X_k = trunc_div(cap × Σ_{i≥k} oi_usd_i, 10000 − cap × k)` and stop at the first `k` with `oi_usd_k ≤ X_k`.
3. The first `k` venues get `w = X_k`; all others get `w = oi_usd`.

**Properties (exact, no truncation slack):**

- **Integer comparisons are unaffected by truncation.** For integer `oi_usd_k`, `oi_usd_k ≤ trunc(X)` holds if and only if `oi_usd_k ≤ X`.
- **Denominators stay positive.** Continuing past `k` implies `oi_usd_k (10000 − cap·k) > cap·Σ_{i≥k} oi_usd_i ≥ cap·oi_usd_k`, hence `cap·(k+1) < 10000`.
- **The loop stops by `k = n − 1`.** At that point the stop condition reduces to `cap·n ≥ 10000`.
- **Every share is within the cap.** With `X' = trunc(X_k)`, each final weight `w ≤ X'` and `X'(10000 − cap·k) ≤ cap·Σ_{i≥k} oi_usd_i`, which gives `w / Σw ≤ cap / 10000` exactly.

**Composite:** `R = trunc_div(Σ w_v × hourly_v, Σ w_v)`. By A.6, `|R| ≤ 2^62 − 1`.

**Leaf fields:**

| Field | Value |
|---|---|
| `value` | `R`, or 0 for status 2 or 3 |
| `source_count` | contributors |
| `expected_source_count` | catalog venues for the asset |
| `coverage_bps` | `trunc_div(10000 × Σ oi_usd over contributors, Σ oi_usd over catalog venues with valid OI inputs)`: the contributors' share of **observable** open interest. It says nothing about venues whose OI is unobservable; that is covered by the source-ratio rule below. |
| `outlier_count` | outliers |
| `max_source_age_ms` | max over contributors of `max(T − settlement_ts, T − oi_ts, T − price_ts if used)`, saturating |
| `dispersion` | median of `|hourly_v − R|` over contributors (even-count rule of A.7), or 0 for status 2 or 3 |

**Status (step 5):**

- `OK` if `coverage_bps ≥ coverage_ok_bps` **and** `10000 × source_count ≥ min_source_ratio_bps × expected_source_count`;
- otherwise `DEGRADED`.

Every leaf produced by these steps is encodable under Section 7.1; the reference implementation asserts this for all examples in A.9.

The reference implementation is `byk_ref.funding_composite`.

### A.9 Worked examples (illustrative inputs)

**Example 1 (normal).** Snapshot `T = 1789258200000`. Inputs are raw lexemes with catalog units:

| Venue | Rate (unit) | Interval (unit) | Settlement ts (unit) | OI unit | OI lexeme | Contract size | Mark price | OI ts / price ts (unit) | Hourly | oi_usd | Eligible |
|---|---|---|---|---|---|---|---|---|---|---|---|
| venue-a | 0.0001 (FRACTION) | 8 (h) | 1789256688 (s) | BASE | 42000 | — | 100000 | 1789258140 / 1789258145 (s) | 125000 | 4,200,000,000 | yes |
| venue-b | 0.008 (PERCENT) | 28800 (s) | 1789256688000 (ms) | QUOTE | 2900000000.75 | — | — | 1789258140000 / — (ms) | 100000 | 2,900,000,000 | yes |
| venue-c | 0.000013 (FRACTION) | 3600000 (ms) | 1789257288 (s) | CONTRACTS | 13000000 | 0.001 | 100000 | 1789258140 / 1789258145 (s) | 130000 | 1,300,000,000 | yes |
| venue-d | 1.12 (BPS) | 8 (h) | 1789256688000 (ms) | BASE | 11000 | — | 100000 | 1789258140000 / 1789258145000 (ms) | 140000 | 1,100,000,000 | yes |
| venue-e | 0.000046 (FRACTION) | 14400 (s) | 1789256688 (s) | CONTRACTS | 900000 | 0.01 | 100000 | 1789258140 / 1789258145 (s) | 115000 | 900,000,000 | yes |
| venue-f | 0.00064 (FRACTION) | 8 (h) | 1789256688 (s) | QUOTE | 300000000 | — | — | 1789258140 / — (s) | 800000 | 300,000,000 | yes |
| venue-g | 0.00009 (FRACTION) | 8 (h) | 1789197000 (s) | BASE | 5000 | — | 100000 | 1789258140 / 1789258145 (s) | 112500 | 500,000,000 | no (stale) |

Median `125000`, MAD `12500`, tau `62500`; venue-f is an outlier; venue-g is stale. Cap: 1 venue at `3,338,461,538`, largest share `3499` bps.

Leaf: `value = 118866`, `dispersion = 11134`, `source_count = 5`, `expected = 7`, `coverage_bps = 9285`, `outlier_count = 1`, `max_source_age_ms = 1512000`, status **DEGRADED**.

**Example 2 (NO_DATA).** Same inputs at `T = 1789431000000` (48 h later): nothing is eligible. Leaf: `value = 0`, `dispersion = 0`, `source_count = 0`, `expected_source_count = 7`, `coverage_bps = 0`, `outlier_count = 0`, `max_source_age_ms = 0`, `status = NO_DATA`. No median, weights or composite are computed.

**Example 3 (INSUFFICIENT_COVERAGE).** As Example 1, but venue-d and venue-e mark-price timestamps are 120 s before their OI timestamps (skew > 60 s), so their OI inputs are invalid. Median `125000`, MAD `15000`, tau `75000`; venue-f is an outlier; 3 contributors (< 5). Leaf: `status = INSUFFICIENT_COVERAGE`, `value = 0`, `dispersion = 0`, `source_count = 3`, `expected_source_count = 7`, `coverage_bps = 9130`, `outlier_count = 1`, `max_source_age_ms = 1512000`.

**Example 4 (rc4 overflow inputs).** Five 1 h venues with rates `900000000` ×2 and `-900000000` ×3 (FRACTION), so `|hourly| = 9·10^18 > 2^62 − 1`. Every rate input is invalid (`hourly outside +-(2^62 - 1)`), so the status is **NO_DATA** with all fields zero. rc4 produced `dispersion = 12600000000000000000`, which is not encodable.

**Example 5 (hourly bound).** Rates `±461168601.8427387903` (FRACTION, 1 h), so `hourly = ±(2^62 − 1)`; OI 3500, 3500, 1000, 1000, 1000 (QUOTE). Leaf: `value = 1844674407370955161`, `dispersion = 6456360425798343064` (≤ 2^63 − 1), status **OK**, encodable. With `461168601.8427387904` the first rate input is invalid.

**Example 6 (cap equality).** Parameters `min_contributors = 2`, `max_weight_bps = 5000` (product exactly 10000). OI 3000 and 1000 USD, hourly 1000 and 2000. Weights `{'big': 1000, 'small': 1000}`, largest share `5000` bps, `value = 1500`. Invalid parameter set: min_contributors=2 with max_weight_bps=3500 (7000 < 10000) (N28).

**Parameter bounds (A.10):** proposed defaults → valid; outlier_k = 10^100 → invalid; outlier_k = 1000 → valid; stale_factor = 1001 → invalid; outlier_floor = 2^62 → invalid; oi_max_age_ms = 604800001 → invalid; min_contributors = 65536 → invalid; outlier_k = true (bool) → invalid; extra key → invalid.

**Decimal lexemes (A.2):**

| Lexeme | Signed | Result |
|---|---|---|
| `100000` | False | valid |
| `0.001` | False | valid |
| `2900000000.75` | False | valid |
| `-0.0001` | True | valid |
| `-0.0001` | False | invalid |
| `1e5` | False | invalid |
| `+1` | True | invalid |
| `' 1'` | False | invalid |
| `1,000` | False | invalid |
| `.5` | False | invalid |
| `5.` | False | invalid |
| `1111111111111111111111111` | False | invalid |
| `0.1111111111111111111` | False | invalid |
| `0.111111111111111111` | False | valid |
| `12345678901234567.89` | False | valid |

**Integer lexemes (A.2):**

| Lexeme, unit (kind) | Result (ms) |
|---|---|
| `1789258140 s (time)` | 1789258140000 |
| `1789258140000 ms (time)` | 1789258140000 |
| `0001 ms (time)` | 1 |
| `12345678901234567890 ms (time)` | invalid (integer lexeme or unit) |
| `-1 ms (time)` | invalid (integer lexeme or unit) |
| `1.0 s (time)` | invalid (integer lexeme or unit) |
| `1e3 ms (time)` | invalid (integer lexeme or unit) |
| `9223372036854775 s (time)` | 9223372036854775000 |
| `9223372036854776 s (time)` | invalid (integer exceeds 2^63 - 1 after unit scaling) |
| `1789258140 us (time)` | invalid (integer lexeme or unit) |
| `8 h (interval)` | 28800000 |
| `0 h (interval)` | invalid (interval outside [60000, 86400000] ms) |
| `25 h (interval)` | invalid (interval outside [60000, 86400000] ms) |
| `59999 ms (interval)` | invalid (interval outside [60000, 86400000] ms) |
| `86400 s (interval)` | 86400000 |
| `86401 s (interval)` | invalid (interval outside [60000, 86400000] ms) |

**Rate units (A.3):** `0.0001 FRACTION` → 1000000; `0.01 PERCENT` → 1000000; `1 BPS` → 1000000; `-0.0375 PERCENT` → -3750000.

**Exactness:** OI `BASE 12345678901234567.89 × mark 1.5` → exact `18518518351851851`; binary64 gives `18518518351851852` (non-conformant).

### A.10 Parameters (PROPOSED DEFAULTS)

| Parameter | Proposed | Meaning |
|---|---|---|
| `decimals` | 10 | funding composites |
| `min_contributors` | 5 | quorum |
| `coverage_ok_bps` | 9500 | minimum observable-OI coverage for OK |
| `min_source_ratio_bps` | 7000 | minimum share of catalog venues contributing for OK |
| `stale_factor` | 2 | settlement staleness multiple |
| `oi_max_age_ms` | 900000 | OI freshness |
| `price_max_skew_ms` | 60000 | maximum gap between OI and mark-price observations |
| `outlier_k` | 5 | MAD multiplier |
| `outlier_floor` | 50000 | minimum threshold, 1e-10 per hour |
| `max_weight_bps` | 3500 | maximum final share per venue |

**Parameter validity (MUST):**

Every parameter is an integer (not a boolean) within these bounds, and the set contains exactly these ten parameters:

| Parameter | Min | Max |
|---|---|---|
| `decimals` | 10 | 10 |
| `min_contributors` | 1 | 65535 |
| `max_weight_bps` | 1 | 10000 |
| `coverage_ok_bps` | 0 | 10000 |
| `min_source_ratio_bps` | 0 | 10000 |
| `stale_factor` | 1 | 1000 |
| `oi_max_age_ms` | 0 | 604800000 (7 days) |
| `price_max_skew_ms` | 0 | 604800000 |
| `outlier_k` | 0 | 1000 |
| `outlier_floor` | 0 | `2^62 − 1` |

In addition:

- `max_weight_bps × min_contributors ≥ 10000` (the proposed values give 17500);
- catalog size per asset is in `[1, 65535]`.

These bounds are what make the 256-bit sufficiency statement of A.2 hold. An invalid parameter set makes the methodology document invalid (N28, N30).

### A.11 Venue catalog — OPEN (required fields)

Each catalog entry MUST specify:

- `venue` name (the `id32` input);
- `instrument` symbol;
- `margin_asset` (`USDT` or `USDC`);
- `funding_source` (endpoint and exact field path) with `rate_unit` (`FRACTION`, `PERCENT` or `BPS`), and the settlement-timestamp field path with its unit (`s` or `ms`);
- `interval_source`: either an endpoint and field path, or a catalog constant, with `interval_unit` (`h`, `s` or `ms`);
- `oi_source` (endpoint and exact field path) and `oi_unit` (`QUOTE`, `BASE` or `CONTRACTS`), and the OI-timestamp field path with its unit;
- `contract_size` as a decimal string of base units per contract (required if and only if `oi_unit = CONTRACTS`);
- `price_source` (endpoint and exact field path of the venue's **mark price** for the same instrument) and the mark-price-timestamp field path with its unit; both required unless `oi_unit = QUOTE`.

At most 65535 venues per asset.

Any catalog change is a methodology version change. Two implementations reading the same raw responses through the same catalog MUST produce identical `oi_usd`.

### A.12 Input snapshot retention

For every Class A leaf, **whatever its status** (including INSUFFICIENT_COVERAGE and NO_DATA leaves), retain and serve via `/v1/class-a-inputs` the snapshot `T`, the methodology parameter set, and, per venue:

- the raw decimal lexemes (rate, OI value, contract size, mark price);
- the raw integer lexemes (interval, settlement timestamp, OI timestamp, mark-price timestamp);
- every catalog unit applied (`rate_unit`, `interval_unit`, timestamp units, `oi_unit`);
- the normalized values (`units`, `hourly`, `interval_ms`, timestamps in ms, `oi_usd`);
- the eligibility, outlier and cap outcomes.

Re-running `funding_composite` on a snapshot MUST reproduce the published leaf fields exactly (Level 3, Section 13.8).

On-chain commitment of snapshots is **OPEN** (C13).

---

## Annex B. Native On-Chain Registries (v2, Non-Normative)

Built only when a real on-chain consumer requires them. When built, they MUST:

1. **Verify every submission's signature on-chain.**
   - EVM: OpenZeppelin `ECDSA`.
   - Solana: the secp256k1 precompile with `message = M`, checked through `load_instruction_at_checked` / `load_current_index_checked` and a program-id check. The deprecated unchecked functions MUST NOT be used; they enabled the 2022 Wormhole exploit.
2. **Maintain the authorization log** with Section 11.5 semantics, including fork-threshold continuation and terminal fork, and apply Section 13.5 checkpoint linkage.
3. **Bound sequence growth by time:** accept `s` only if `s > latest`, `epoch_end_ms ≤ block_time_ms + 60000`, and `s − latest ≤ (epoch_end_ms − latest_epoch_end_ms) / 300000`.
4. **Have no pause function.** Revoking all signers is the stop mechanism.
5. **Store only latest state;** history lives in events and logs.
6. **Be immutable after audit** (testnet, property and fuzz tests, external audit, mainnet, source verification, immutability).
7. **Migrate by continuation:** a successor registry continues the commitment chain.

---

## Annex C. Open Decisions (Owner)

| # | Decision | Proposal | Blocks |
|---|---|---|---|
| C1 | Venue catalog with A.11 fields | — | Class A launch |
| C2 | Annex A parameters (A.10) | as listed | Class A launch |
| C3 | Governance members, threshold, custody (`N ≤ 4`, `N ≥ 2M − 1`) | 2-of-3 hardware keys, separate locations | mainnet |
| C4 | Governance ceremony runbook (drafting, review, signing, anchoring, fork response F12) | 2-person rule | mainnet |
| C5 | Production stream name and genesis epoch | `BYK.DATALAYER.MAINNET` | mainnet |
| C6 | Class B feeds and decimals at launch | — | catalog |
| C7 | KMS provider, region, IAM, alerting | AWS KMS, Sign-only role | mainnet |
| C8 | LATE threshold and MISSED window | 120 s, 24 h | explorer |
| C9 | Retention and archival | indefinite, two locations | mainnet |
| C10 | Trust-root publication channels | the four listed in Section 11.2 | mainnet |
| C11 | RPC providers | ≥ 2 per chain, archival for both | mainnet |
| C12 | Default Proof API `as_of_ms` | latest time final on both witnesses | API |
| C13 | On-chain commitment of Class A input snapshots | defer to v1.1 | none |
| C14 | Machine-readable schema document and methodology registry formats | versioned JSON, hashed as bytes | mainnet |
| C15 | Methodology v1 input profile aligned with the production collectors (field sources, units, funding kind, snapshot cadence) | snapshot profile, see the Server Integration Profile | Class A launch |

---

## Annex D. Decision Log (Closed for v1)

| Decision | Rejected alternative | Reason |
|---|---|---|
| Chain-neutral protocol; chains are witnesses | Chain as source of truth | Portability; single validity definition |
| Solana Memo + Base EAS in v1 | Custom registries at launch | No on-chain consumer yet (Annex B) |
| Every-epoch anchoring on both chains | Base hourly checkpoints | Independent per-epoch positions; no single-epoch proof path for checkpoints |
| `stream_id = keccak256(genesis_core)`, pinned out-of-band | Trust from on-chain genesis | Anchors come from untrusted submitters |
| Witness networks bound in genesis core | Network implied by RPC config | Prevents replay |
| Hash-linked AL, as-of evaluation | "Latest known set" | Determinism |
| Forward resolution with UNRESOLVED; linking checkpoints | First-seen wins; history-reset checkpoints | Safety; Level 2 and Level 3 agree |
| Fork-threshold continuation (`min(M+1, N)`) with ACK | Permanent halt; lowest-hash tie-break | Recoverable without silent choice; terminal only on proven key misuse |
| Permissionless submission; per-item witness keys | Publisher allow-lists; single global index | Consistent with signature-only authority; spam isolated per item; no liveness dependence on ByKaranteli keys |
| G3 as witness position plus reported time | Claimed cryptographic wall-clock bound | Solana block time is an estimate; Base timestamps are sequencer-assigned |
| INCOMPLETE result code | Best-effort positive results | Completeness is a precondition of uniqueness |
| secp256k1; Keccak-256; RFC 6962 tree | ed25519; SHA-256; duplicate-last-node | Native on EVM and Solana; no duplication ambiguity |
| Fixed-width big-endian, `id32` | Floats, strings, JSON canonicalization | Byte-exact determinism |
| Explicit statuses, no carry-forward | Republishing last values | "No data" differs from "old data" |
| Realized funding; exact OI unit conversion with mark price; max-share cap; source-ratio rule | Predicted funding; implicit USD OI; raw-OI cap; coverage-only status | Reproducibility across implementations; honest status |
| Plain secp256k1 governance signatures | Safe or Squads signatures | Chain-independent verification |
| Resolver bound `S_max(T)` plus stream sequence rule | Bound from highest signed sequence | A compromised signer cannot inflate verifier work |
| Candidate = manifest and signature from one anchor | Cross-anchor combination | Single, cheap, implementation-independent rule |
| Level 2 evaluates from sequence 0 | Start at latest checkpoint | Restart flags depend on earlier history |
| Fork continuation is ACK only | Any entry type | No state change authorized by the pre-fork set after a governance update |
| `N ≥ 2M − 1` | Any `M ≤ N` | Recovery from fewer than M compromised keys always possible |
| Raw numeric lexemes with length bounds; 256-bit sufficiency | Shortest decimal from parsed numbers; loose precision | Identical results in JavaScript, Python, Rust and Solidity |
| Hourly bound `2^62 − 1` | Range check after computing | `value` and `dispersion` encodable by construction |
| Epoch-level verification levels (1E, 2E); NO_DATA exempt from leaf and catalog checks | Leaf checks for every manifest | Genesis and gap manifests have no records |
| Typed inputs with catalog units; interval range | Untyped numeric inputs | Adapter behavior fully specified |
| `max_weight_bps × min_contributors ≥ 10000`, no fallback | Fallback to raw weights | Exact share guarantee in every reachable case |
| Level 3 recomputes every Class A leaf from its snapshot | Structural audit only | Methodology violations (wrong value, quality fields, status) are detectable |
| Bounded integer methodology parameters | Unbounded parameters | 256-bit sufficiency is provable |
| No token | Token or staking | Not required for provenance |

---

## Annex E. Changes rc1 → rc2 (historical)

| rc1 finding | rc2 resolution |
|---|---|
| Genesis root of trust undefined | Genesis core, `stream_id = keccak256(core)`, out-of-band pinning |
| Authorization freshness non-deterministic | Hash-linked authorization log; as-of evaluation |
| Canonical manifest after equivocation undefined | Candidates, forward resolution, UNRESOLVED, checkpoints |
| Witness network identity not bound | Network identity in genesis core plus RPC checks |
| G4 too strong for single records | Verification levels |
| Retroactive revocation weakened G3 | Existence independent of signature validity |
| NO_DATA invariant one-directional | If-and-only-if rule |
| EAS outer fields unchecked | Cross-checks, canonical ABI |
| `max_source_age_ms` contradiction | Oldest input of any kind |
| Weight-cap semantics | Max-share water-filling |
| Class A reproducibility overstated | Retained snapshot |
| Safe/Squads wording | Separate Ed25519 keys |
| Identifier validation | Every character in `0x21–0x7E` |
| Sentinel semantics | Unbounded including `2^64 − 1` |
| Package reproducibility | Stdlib-only generator, pinned cross-checks |
| Hourly checkpoint proof path | Mode removed |

The rc2 global Solana index address is superseded in rc3 by per-item witness keys (Annex F).

---

## Annex F. Changes rc2 → rc3

| rc2 finding | Severity | rc3 resolution |
|---|---|---|
| Publisher key defined but never bound to admissibility | Blocker | Submission declared permissionless (Sections 1.1 principle 4, 12.1). "Publisher" replaced by *submitter* (no protocol role) and *signing service*. Admissibility MUST ignore submitter identity (N18). F4 is operational only. |
| G3 "time upper bound" not valid for Solana | Blocker | G3 redefined as **witness position** (block number or slot) plus **reported time**, labelled REPORTED, INFERRED or UNAVAILABLE (Sections 3.1, 3.2, 12.9, 12.10). Public-statement wording rule added. |
| GOVERNANCE_FORK had no recovery | High | Section 11.5: fork-threshold continuation `min(M+1, N)` by the pre-fork set, new ACK entry type, GOVERNANCE_FORK_TERMINAL for conflicting continuations. F12, F13. Vectors G1–G4. |
| CHECKPOINT could select a non-linking branch | High | Sections 11.8 and 13.5: a checkpoint must link to a resolved predecessor, otherwise UNRESOLVED with CHECKPOINT_CONFLICT; restart flag HISTORY_UNRESOLVED_BEFORE. Level 2 and Level 3 now agree. Vectors E0, E1, F. |
| OI normalization not deterministic across venues | High | A.2 decimal grammar, A.4 unit conversion (QUOTE, BASE, CONTRACTS × mark price), stablecoin = 1 USD definition, `price_max_skew_ms`, A.11 required catalog fields, A.12 raw-string retention. Worked example uses all three units. |
| Publisher versus data signer confusion | Medium | Section 2 roles; Section 5.9 and F9 now address the signing service |
| `coverage_bps` could read 100% while venues are unobservable | Medium | Defined as observable-OI share; OK additionally requires `min_source_ratio_bps` of catalog venues contributing |
| Solana block time null and seconds-to-milliseconds unit | Medium | Section 12.9: × 1000 conversion, INFERRED/UNAVAILABLE rules, source-disagreement rule, deterministic as-of heights `H_B(T)` and `H_S(T)` |
| Witness-index spam against verification | Medium | Section 12.3 per-item witness keys (Solana account key, Base recipient); Section 12.7 per-key enumeration, cheap-first order, **INCOMPLETE** result (N17); F14 |

**Additional changes found while implementing rc3:**

- The genesis core loses the global index field (length `112 + 20N`).
- N ≤ 4, because fork-resolution bundles with N = 5 exceeded the Solana memo budget (1025 > 937 bytes).
- Witness keys must be static account keys (not loaded through address lookup tables).
- The witness-time vector set was added (Section 17.8).
- The generator asserts all 11 resolution and fork scenarios.

---

## Annex G. Changes rc3 → rc4

No mechanisms were added. Every change tightens or clarifies an existing rule.

| rc3 finding | Severity | rc4 resolution |
|---|---|---|
| Sequence-space DoS: resolver looped to the highest signed sequence | Blocker | Section 13.2 step 7: stream sequence rule `epoch_start_ms ≥ G + sequence × 300000`. Section 13.4: candidates require `epoch_end_ms ≤ T`. Section 13.5: loop bound `S_max(T) = floor((T − G)/300000) − 1`, derived from `T` only; checkpoints beyond `S_max` ignored. Vector I (`M_far` with sequence 10^9, `M_max` with sequence 2^64 − 1); N22. |
| Candidate signature semantics differed between spec and reference | High | Section 13.4: manifest and signature must come from one anchor. Vector H; N21. |
| Checkpoint-start shortcut lost HISTORY_UNRESOLVED_BEFORE | High | Section 13.7: Level 2 evaluates from sequence 0; caching only if provably output-identical. Vector F extended with M4, M5; N20. |
| Fork continuation too broad; TERMINAL wording mismatch | High | Section 11.5: continuations must be ACK; ACK bytes determine the referenced branch, so distinct continuations reference different branches; duplicate bundles count once. Vectors G5 (non-ACK), G6 (same ACK, two bundles); N8 and N9 aligned. |
| Annex A NO_DATA path divided by zero or took the max of an empty set | High | A.8 evaluation order with explicit field values for NO_DATA and INSUFFICIENT_COVERAGE; contributor set proven non-empty; coverage denominator proven positive. Examples 2 and 3. |
| F6 infeasible for some M/N | Medium | Section 11.1: `N ≥ 2M − 1` for genesis and GOVERNANCE_UPDATE; F6 rewritten with the exact condition. Governance-bound vectors; N23. |
| Numeric JSON "shortest decimal" not deterministic across languages | Medium | A.2: raw lexemes from response bytes (JSON number token text); no binary64 conversion. Exactness vector (exact `18518518351851851` vs binary64 `18518518351851852`); N24. |
| "At least 128-bit" precision too loose | Medium | Section 4.3 and A.2: exact arithmetic; lexeme bounds (≤ 24 characters, ≤ 18 fractional digits) and int64 range rules make signed 256-bit sufficient. Bounds vectors. |
| Spam cost wording overstated | Medium | Section 3.3: cost amortization through batching stated explicitly |

**Additional changes found while implementing rc4:**

- **Test-vector JSON large integers.** The ethers cross-check exposed that the vectors file itself was affected by the binary64 problem: `JSON.parse` rounded `18518518351851851`. Integers outside ±(2^53 − 1) are now decimal strings in the vector file and in API JSON (Section 4.7).
- **Result for sequences without candidates.** A sequence with no candidates now yields UNRESOLVED explicitly: the loop runs to `S_max(T)` or the target, not to the highest candidate.
- **Generator speed.** The reference implementation uses Jacobian coordinates, 4-bit windows and memoization. The generator now runs in well under a second (rc3: 23 s), still byte-identical to libsecp256k1.

---

## Annex H. Changes rc4 → rc5

No mechanisms were added.

| rc4 finding | Severity | rc5 resolution |
|---|---|---|
| `dispersion` could exceed int64: the reference produced an unencodable leaf | High | A.6: `|hourly| ≤ 2^62 − 1`, which bounds `|R| ≤ 2^62 − 1` and every deviation by `2^63 − 2`. Section 7.1 states the obligation. The rc4 reproduction inputs (±9·10^18) are now invalid, giving NO_DATA. A boundary example at ±(2^62 − 1) yields `dispersion = 6456360425798343064`, encodable. The reference asserts encodability of every example (N25). |
| Level 3 audit contradicted genesis and gap NO_DATA manifests | High | Section 13.6–13.8: epoch levels 1E and 2E; Level 3 applies leaf and catalog checks only to OK and DEGRADED manifests; continuity at the range start defined. Reference `audit_range`. Vectors: normal → gap → normal PASS, missing catalog leaf FAIL, unresolved sequence FAIL, range starting after gap PASS (N26). |
| Decimal versus integer inputs untyped; interval bounds differed from the reference | Medium-High | A.2 and A.3: two lexeme kinds, integer grammar `^[0-9]{1,19}$`, catalog units (`rate_unit`; `h`/`s`/`ms` for intervals; `s`/`ms` for timestamps), interval range `[60000, 86400000]`; A.11 catalog fields extended. Integer-lexeme and rate-unit vectors (N27). |
| Weight-cap fallback contradicted the share guarantee; equality case | Medium | A.10: `max_weight_bps × min_contributors ≥ 10000`; fallback removed; A.8 proves positive denominators, termination by `k = n − 1`, and exact share bound. Also property-tested on 148,553 random cases. Equality vector (2 venues, cap 5000, equal weights) and invalid-parameter vector (N28). |

**Additional change found while implementing rc5:** the share bound is exact. rc4's "up to one unit of truncation" was unnecessarily weak, and the proof in A.8 removes it.

---

## Annex I. Changes rc5 → rc6

No mechanisms were added.

| rc5 finding | Severity | rc6 resolution |
|---|---|---|
| Level 3 required Class A recomputation but the reference audit did not perform it; tampered Class A values and quality fields passed | High | `byk_ref.audit_range` consumes retained snapshots and the methodology parameters and calls `funding_composite` for **every** Class A leaf, including INSUFFICIENT_COVERAGE and NO_DATA leaves. Section 13.8 and A.12 aligned ("whatever its status"). The test epochs now derive all Class A leaves from snapshots (BTC DEGRADED, ETH INSUFFICIENT_COVERAGE, SOL negative). New vectors: tampered value, tampered `source_count`, NO_DATA despite sufficient inputs, INSUFFICIENT_COVERAGE with wrong quality fields, missing snapshot, parameters differing from the methodology (N29). |
| 256-bit sufficiency claim not guaranteed without parameter upper bounds | Medium | A.10 bounds every parameter (integers, no booleans, exact key set); A.2 lists the largest intermediates (< `2^240`). Vectors: `outlier_k = 10^100`, `stale_factor = 1001`, `outlier_floor = 2^62`, `oi_max_age_ms = 604800001`, `min_contributors = 65536`, boolean and extra-key cases rejected (N30). |

**Also in rc6:** Annex C15 records that Annex A's input layer is aligned with the production collectors in the separate Server Integration Profile. The protocol core is unaffected.
