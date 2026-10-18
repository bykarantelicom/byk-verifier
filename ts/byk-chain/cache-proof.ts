/* BYK Data Layer · the rc6 13.7 cache proof of a resumed verification (2026-10-18).
 *
 * 13.7 lets a verifier reuse cached results only when they are provably identical to a full evaluation at the new as-of
 * heights, which needs at least: no new authorization-log entry (byk-verify compares the log head and refuses a changed
 * one) and no new admissible anchor under any witness key of a cached sequence. The reader checkpoint carries the newest
 * transaction signature the reader listed under each data witness key up to its sequence (newest_signatures, index =
 * sequence). This module asks each of those keys for its newest signature now (one getSignaturesForAddress with limit 1)
 * and, where it moved, lists every transaction after the stored one (until) and judges each by 12.6. A new admissible
 * anchor breaks the proof for its sequence: the cached verdict may then differ from a full evaluation (a late or a rival
 * manifest), so the run stays RESUMED and a full run decides. New inadmissible transactions (failed, or spam sent to the
 * key) do not break it: the stored signature moves to the newest one so the next run does not list them again. A key
 * that lists nothing, a transaction that cannot be fetched or more new transactions than the bound cannot be proven
 * either way. The genesis and log keys are enumerated in full by every run and need no proof. The proof covers the
 * Solana witness, on which the verdict rests under the beta profile; the Base copies of cached sequences are not read
 * again (the Sunday full run looks for every expected copy once more). */
import { PublicKey } from "@solana/web3.js";

import { type Bytes, WITNESS_KIND, witnessKey, type WitnessPayload } from "../index";
import { admissiblePayload } from "./solana";

export type SignatureInfo = { signature: string; slot: number; err: unknown };
export type TransactionLike = Parameters<typeof admissiblePayload>[0];
/** The slice of @solana/web3.js Connection the proof uses; a test passes a fake. */
export type SignatureSource = {
  getSignaturesForAddress(address: PublicKey, options: { before?: string; until?: string; limit?: number }, commitment: "finalized"): Promise<SignatureInfo[]>;
  getTransaction(signature: string, options: { commitment: "finalized"; maxSupportedTransactionVersion: number }): Promise<TransactionLike | null>;
};

export type CacheProof = {
  proven: boolean;
  /** cached sequences asked, 0 upward */
  checked: number;
  /** keys whose newest signature moved since the checkpoint (every new transaction inadmissible when proven) */
  changed: number;
  /** new transactions seen that are not admissible anchors (failed, or not an anchor of this stream) */
  inadmissible: number;
  calls: number;
  reason: string | null;
  /** the cached sequence the proof stopped at, when not proven */
  sequence: string | null;
  /** the list to carry into the next checkpoint for the cached sequences: the stored one, moved forward on the keys whose
   *  new transactions were all inadmissible (up to the sequence the proof stopped at, when it did) */
  newest: Array<string | null>;
};

/** How many new transactions under one cached key are examined before the proof gives up on that key. */
export const CACHE_PROOF_MAX_NEW = 1000;
const PAGE = 100;

/** A proof that could not be attempted (no list in the checkpoint, a pruned endpoint), in the shape of a failed one. */
export function unprovable(reason: string, newest: ReadonlyArray<string | null>): CacheProof {
  return { proven: false, checked: 0, changed: 0, inadmissible: 0, calls: 0, reason, sequence: null, newest: [...newest] };
}

/** The next checkpoint's newest_signatures list: the cached part (0 to `from` - 1, from the list the run continued from or the
 *  proof's moved copy of it; [] for a full run) followed by the keys this run read itself (`from` to `through`). null when the
 *  cached part is missing or short, or a sequence in the run's range was not read: then no list is written and the next full
 *  run records one. */
export function assembleNewestList(cachedPart: ReadonlyArray<string | null> | null, from: bigint, through: bigint, read: ReadonlyMap<bigint, string | null>): Array<string | null> | null {
  if (cachedPart === null || cachedPart.length < Number(from) || through < from) return null;
  const list = cachedPart.slice(0, Number(from));
  for (let s = from; s <= through; s += BigInt(1)) {
    if (!read.has(s)) return null;
    list.push(read.get(s) ?? null);
  }
  return list;
}

/** Proves, or fails to prove, that no data witness key of the sequences 0 to `through` - 1 carries a new admissible anchor
 *  since the run that recorded `stored` (index = sequence). `through` is the checkpoint sequence, which the resumed run
 *  reads again itself. */
export async function proveCachedSequences(conn: SignatureSource, streamId: Bytes, stored: ReadonlyArray<string | null>, through: bigint, opts: { maxNew?: number; judge?: (tx: TransactionLike, key: Bytes) => WitnessPayload | null; onKey?: (sequence: bigint) => Promise<void> | void } = {}): Promise<CacheProof> {
  const maxNew = opts.maxNew ?? CACHE_PROOF_MAX_NEW;
  const judge = opts.judge ?? ((tx: TransactionLike, key: Bytes) => admissiblePayload(tx, key, streamId));
  const newest: Array<string | null> = [...stored];
  let calls = 0;
  let changed = 0;
  let inadmissible = 0;
  let checked = 0;
  const fail = (sequence: bigint, reason: string): CacheProof => ({ proven: false, checked, changed, inadmissible, calls, reason, sequence: sequence.toString(), newest });
  for (let s = BigInt(0); s < through; s += BigInt(1)) {
    const i = Number(s);
    const sig = stored[i];
    if (typeof sig !== "string" || sig.length === 0) return fail(s, `the checkpoint records no newest transaction for sequence ${s}; a full run with --checkpoint-out records every key`);
    const key = witnessKey(streamId, WITNESS_KIND.DATA, s);
    const address = new PublicKey(key);
    const head = await conn.getSignaturesForAddress(address, { limit: 1 }, "finalized");
    calls++;
    checked++;
    if (head.length === 0) return fail(s, `sequence ${s} lists no transaction on this endpoint although the checkpoint saw one: the history is missing here, use an archive endpoint`);
    const top = head[0]!.signature;
    if (top !== sig) {
      changed++;
      /* A listing with `until` runs to the beginning of the key's history when the endpoint no longer holds the stored
       * transaction (a partial archive whose first block is still before genesis), and would then present the sequence's
       * own anchor as new: the stored transaction must be retrievable here before anything newer is judged. */
      const storedTx = await conn.getTransaction(sig, { commitment: "finalized", maxSupportedTransactionVersion: 0 });
      calls++;
      if (!storedTx) return fail(s, `the transaction the checkpoint recorded for sequence ${s} (${sig}) is not retrievable on this endpoint: the history is missing here, use an archive endpoint`);
      let before: string | undefined;
      let examined = 0;
      let done = false;
      while (!done) {
        /* until: the listing stops at the stored signature (excluded), newest first; a page shorter than PAGE is the end */
        const page = await conn.getSignaturesForAddress(address, { until: sig, before, limit: PAGE }, "finalized");
        calls++;
        for (const x of page) {
          if (x.signature === sig) {
            done = true; // an endpoint that includes the until signature itself: nothing older is new
            break;
          }
          examined++;
          if (x.err !== null) {
            inadmissible++;
            continue;
          }
          const tx = await conn.getTransaction(x.signature, { commitment: "finalized", maxSupportedTransactionVersion: 0 });
          calls++;
          if (!tx) return fail(s, `transaction ${x.signature} under sequence ${s} is listed but not retrievable on this endpoint`);
          if (judge(tx, key)) return fail(s, `sequence ${s} has a new admissible anchor since the run that wrote the checkpoint (${x.signature}): the cached verdict may differ from a full evaluation, run without --checkpoint`);
          inadmissible++;
        }
        if (examined > maxNew) return fail(s, `more than ${maxNew} new transactions under sequence ${s} since the checkpoint: not bounded, run without --checkpoint`);
        if (page.length < PAGE) done = true;
        if (!done) before = page[page.length - 1]!.signature;
      }
      newest[i] = top;
    }
    if (opts.onKey) await opts.onKey(s);
  }
  return { proven: true, checked, changed, inadmissible, calls, reason: null, sequence: null, newest };
}
