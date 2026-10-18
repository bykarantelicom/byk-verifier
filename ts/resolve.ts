/* BYK Data Layer v1 (rc6) · Sections 13.4 and 13.5: candidates and canonical resolution. */
import { B0, B1, BykError, type Bytes, equal, toHex } from "./bytes";
import { type AlState, authorized } from "./authlog";
import { keccak256, recoverAddress } from "./crypto";
import { type Genesis, type Manifest, maxSequence, parseManifest, validateManifestInStream } from "./stream";

/** One admissible anchor's payload. The manifest and the signature MUST come from the same anchor (N21). */
export type AnchoredPayload = { manifest: Bytes; signature: Bytes };
export type Candidate = { commitment: Bytes; manifest: Manifest };
/** sequence -> commitment (hex) -> candidate */
export type Candidates = Map<bigint, Map<string, Candidate>>;

export type ResolutionFlag = "EQUIVOCATION" | "CHECKPOINT_NOT_CANDIDATE" | "CHECKPOINT_CONFLICT" | "HISTORY_UNRESOLVED_BEFORE" | "READER_CHECKPOINT";
/** A reader's own earlier verdict: the last sequence a previous run of the same reader resolved CANONICAL and its commitment.
 *  Not a protocol object (the log's type 3 checkpoint is governance-signed); it lets a daily run continue where the last one
 *  stopped instead of reading every sequence since genesis, and the row it seeds is flagged READER_CHECKPOINT because this run
 *  did not re-verify anything before it. A late conflicting anchor for an older sequence is only seen by a full run. */
export type ReaderCheckpoint = { sequence: bigint; commitment: Bytes; /** the seed row carried HISTORY_UNRESOLVED_BEFORE in the run that wrote it */ historyUnresolvedBefore?: boolean };
export type Resolved = { commitment: Bytes | null; flags: ResolutionFlag[] };
export type Resolution = Map<bigint, Resolved>;

/** Section 13.4. Payloads that fail structure, the stream rules or signature recovery are skipped, as are
 *  manifests that end after T and signers that the log does not authorize for that sequence. */
export function collectCandidates(state: AlState, genesis: Genesis, payloads: AnchoredPayload[], asOfMs: bigint): Candidates {
  const out: Candidates = new Map();
  for (const p of payloads) {
    let m: Manifest;
    let signer: Bytes;
    let commitment: Bytes;
    try {
      m = parseManifest(p.manifest);
      validateManifestInStream(m, genesis);
      commitment = keccak256(p.manifest);
      signer = recoverAddress(commitment, p.signature);
    } catch (err) {
      if (err instanceof BykError) continue;
      throw err;
    }
    if (m.epochEndMs > asOfMs || !authorized(state, signer, m.sequence)) continue;
    const bySeq = out.get(m.sequence) ?? new Map<string, Candidate>();
    bySeq.set(toHex(commitment), { commitment, manifest: m });
    out.set(m.sequence, bySeq);
  }
  return out;
}

/** Section 13.5. Always evaluated from sequence 0 (N20); the one exception is a reader checkpoint (`seed`), the
 *  verifier's own earlier verdict, which starts the loop after that sequence and marks the seed row READER_CHECKPOINT
 *  (a resumed verdict, not the full one of 13.7; see the type above). The loop bound comes from T alone, never from a
 *  candidate or checkpoint sequence number (N22), so a far-future manifest cannot make a verifier spin. */
export function resolveCanonical(state: AlState, cands: Candidates, genesis: Genesis, asOfMs: bigint, target?: bigint, seed?: ReaderCheckpoint): Resolution {
  const result: Resolution = new Map();
  const sMax = maxSequence(genesis, asOfMs);
  const last = target === undefined || target > sMax ? sMax : target;
  for (const q of cands.keys()) if (q > sMax) throw new Error("candidate beyond S_max(T): candidates must be collected with the same as-of time");
  let prevC: Bytes | null = null;
  let prevM: Manifest | null = null;
  let gap = false;
  let first = B0;
  if (seed !== undefined) {
    if (seed.sequence < B0 || seed.sequence > last) throw new Error(`reader checkpoint sequence ${seed.sequence} is outside the resolved range 0 to ${last}`);
    const k = cands.get(seed.sequence)?.get(toHex(seed.commitment));
    if (!k) throw new Error(`reader checkpoint: sequence ${seed.sequence} has no admissible candidate with the checkpoint commitment on chain; run without --checkpoint`);
    const governed = state.checkpoints.get(seed.sequence);
    if (governed !== undefined && !equal(governed, seed.commitment)) throw new Error(`reader checkpoint: the authorization log's checkpoint at sequence ${seed.sequence} names another commitment; run without --checkpoint`);
    result.set(seed.sequence, { commitment: k.commitment, flags: ["READER_CHECKPOINT"] });
    prevC = k.commitment;
    prevM = k.manifest;
    gap = seed.historyUnresolvedBefore === true; // the full run's memory of an unresolved past travels with the seed
    first = seed.sequence + B1;
  }
  for (let s = first; s <= last; s += B1) {
    const cs = cands.get(s) ?? new Map<string, Candidate>();
    const flags: ResolutionFlag[] = [];
    let res: Candidate | null = null;
    const links = (c: Candidate) => prevC !== null && prevM !== null && equal(c.manifest.previousCommitment, prevC) && c.manifest.epochStartMs === prevM.epochEndMs;
    const checkpoint = state.checkpoints.get(s);

    if (checkpoint !== undefined) {
      const k = cs.get(toHex(checkpoint));
      if (!k) flags.push("CHECKPOINT_NOT_CANDIDATE");
      else if (s === B0) res = k;
      else if (prevC === null) {
        res = k;
        gap = true;
      } else if (links(k)) res = k;
      else flags.push("CHECKPOINT_CONFLICT");
    } else if (s === B0) {
      if (cs.size === 1) res = cs.values().next().value as Candidate;
      else if (cs.size > 1) flags.push("EQUIVOCATION");
    } else if (prevC !== null) {
      const linked = [...cs.values()].filter(links);
      if (linked.length === 1) res = linked[0]!;
      else if (linked.length > 1) flags.push("EQUIVOCATION");
    }
    if (res !== null && gap) flags.push("HISTORY_UNRESOLVED_BEFORE");
    result.set(s, { commitment: res ? res.commitment : null, flags });
    prevC = res ? res.commitment : null;
    prevM = res ? res.manifest : null;
  }
  return result;
}
