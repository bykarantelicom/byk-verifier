/* The rc6 13.7 cache proof against a fake signature source (2026-10-18): unchanged keys prove in one call each, new failed
 * or inadmissible transactions keep the proof and move the stored signature forward, a new admissible anchor breaks it at
 * its sequence, a missing record, an empty listing (pruned endpoint) and an unbounded key cannot be proven. */
import assert from "node:assert/strict";
import { test } from "node:test";

import type { PublicKey } from "@solana/web3.js";

import { fromHex, WITNESS_KIND, witnessKey } from "../index";
import { base58Encode } from "../index";
import { assembleNewestList, CACHE_PROOF_MAX_NEW, proveCachedSequences, type SignatureInfo, type SignatureSource, type TransactionLike } from "./cache-proof";

const STREAM = fromHex("46b69e107bc75175e86a336662311c6e198bbf0dab271c06bc5248888238f66d");
const addressOf = (s: number) => base58Encode(witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(s)));
const tx = (sig: string, slot: number, err: unknown = null): SignatureInfo => ({ signature: sig, slot, err });

/** A key's history, newest first; the fake honours limit, before and until like the RPC does. */
function fakeSource(histories: Record<string, SignatureInfo[]>, retrievable = (sig: string) => sig !== "lost", inclusiveUntil = false): SignatureSource & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async getSignaturesForAddress(address: PublicKey, options: { before?: string; until?: string; limit?: number }) {
      const list = histories[address.toBase58()] ?? [];
      calls.push(`list ${options.limit ?? "all"}${options.before ? " before" : ""}${options.until ? " until" : ""}`);
      let start = 0;
      if (options.before) start = list.findIndex((x) => x.signature === options.before) + 1;
      const out: SignatureInfo[] = [];
      for (let i = start; i < list.length && out.length < (options.limit ?? 1000); i++) {
        /* the RPC excludes the until signature; an endpoint that includes it must not make the proof page past it */
        if (options.until && list[i]!.signature === options.until && !inclusiveUntil) break;
        out.push(list[i]!);
        if (options.until && list[i]!.signature === options.until) break;
      }
      return out;
    },
    async getTransaction(signature: string) {
      calls.push(`tx ${signature}`);
      return retrievable(signature) ? ({ meta: { err: null }, transaction: { message: { staticAccountKeys: [], compiledInstructions: [] } }, signature } as unknown as TransactionLike) : null;
    },
  };
}
/** The fake judge reads the admissibility off the signature name: "anchor-..." is an admissible anchor, anything else is not. */
const judge = (t: TransactionLike) => ((t as unknown as { signature: string }).signature.startsWith("anchor-") ? ({ kind: "data" } as never) : null);

test("cache proof: unchanged keys prove in one call each and the stored list is carried as it was", async () => {
  const src = fakeSource({ [addressOf(0)]: [tx("g0", 10)], [addressOf(1)]: [tx("a1", 20), tx("old1", 15)], [addressOf(2)]: [tx("a2", 30)] });
  const seen: bigint[] = [];
  const p = await proveCachedSequences(src, STREAM, ["g0", "a1", "a2", "seed"], BigInt(3), { judge, onKey: (s) => { seen.push(s); } });
  assert.equal(p.proven, true);
  assert.deepEqual({ checked: p.checked, changed: p.changed, inadmissible: p.inadmissible, calls: p.calls }, { checked: 3, changed: 0, inadmissible: 0, calls: 3 });
  assert.deepEqual(p.newest, ["g0", "a1", "a2", "seed"]);
  assert.deepEqual(src.calls, ["list 1", "list 1", "list 1"]);
  assert.deepEqual(seen, [BigInt(0), BigInt(1), BigInt(2)]);
  assert.equal((await proveCachedSequences(src, STREAM, [], BigInt(0), { judge })).proven, true, "nothing cached: trivially proven");
});

test("cache proof: new failed and inadmissible transactions keep the proof and move the record to the newest signature", async () => {
  const src = fakeSource({ [addressOf(0)]: [tx("spam-new", 40), tx("failed-new", 35, { InstructionError: 1 }), tx("a0", 10)], [addressOf(1)]: [tx("a1", 20)] });
  const p = await proveCachedSequences(src, STREAM, ["a0", "a1", "seed"], BigInt(2), { judge });
  assert.equal(p.proven, true, p.reason ?? "");
  assert.deepEqual({ changed: p.changed, inadmissible: p.inadmissible }, { changed: 1, inadmissible: 2 });
  assert.deepEqual(p.newest, ["spam-new", "a1", "seed"]);
  assert.deepEqual(src.calls, ["list 1", "tx a0", "list 100 until", "tx spam-new", "list 1"], "the stored transaction is checked first, the failed one is never fetched, the until listing stops at the stored signature");
});

test("cache proof: an endpoint that lists the until signature itself ends the walk there, never paging into the sequence's own anchor", async () => {
  const flood = Array.from({ length: 150 }, (_, i) => tx(`spam-${i}`, 2000 - i, { err: true }));
  const src = fakeSource({ [addressOf(0)]: [...flood, tx("a0", 10), tx("anchor-original", 5)] }, () => true, true);
  const p = await proveCachedSequences(src, STREAM, ["a0", "seed"], BigInt(1), { judge });
  assert.equal(p.proven, true, p.reason ?? "");
  assert.equal(p.inadmissible, 150);
  assert.deepEqual(p.newest, ["spam-0", "seed"]);
  assert.ok(!src.calls.includes("tx anchor-original"), "the anchor older than the stored signature was never judged");
});

test("cache proof: a new admissible anchor under a cached key breaks the proof at that sequence", async () => {
  const src = fakeSource({ [addressOf(0)]: [tx("a0", 10)], [addressOf(1)]: [tx("anchor-rival", 50), tx("a1", 20)], [addressOf(2)]: [tx("a2", 30)] });
  const p = await proveCachedSequences(src, STREAM, ["a0", "a1", "a2", "seed"], BigInt(3), { judge });
  assert.equal(p.proven, false);
  assert.equal(p.sequence, "1");
  assert.match(p.reason ?? "", /new admissible anchor .*anchor-rival/);
  assert.deepEqual(p.newest, ["a0", "a1", "a2", "seed"], "the record of the broken key is not moved");
  assert.equal(p.checked, 2, "the proof stops at the broken key");
});

test("cache proof: a missing record, an empty listing and an unbounded key cannot be proven", async () => {
  const none = await proveCachedSequences(fakeSource({ [addressOf(0)]: [tx("a0", 10)] }), STREAM, ["a0", null, "seed"], BigInt(2), { judge });
  assert.equal(none.proven, false);
  assert.match(none.reason ?? "", /no newest transaction for sequence 1/);
  const pruned = await proveCachedSequences(fakeSource({ [addressOf(0)]: [] }), STREAM, ["a0", "seed"], BigInt(1), { judge });
  assert.equal(pruned.proven, false);
  assert.match(pruned.reason ?? "", /lists no transaction .*history is missing/);
  const lost = await proveCachedSequences(fakeSource({ [addressOf(0)]: [tx("lost", 12), tx("a0", 10)] }), STREAM, ["a0", "seed"], BigInt(1), { judge });
  assert.equal(lost.proven, false);
  assert.match(lost.reason ?? "", /transaction lost under sequence 0 is listed but not retrievable/);
  /* a partial archive that dropped the stored transaction: until is ignored by the RPC and the whole history would come back */
  const partial = await proveCachedSequences(fakeSource({ [addressOf(0)]: [tx("spam-new", 12), tx("anchor-original", 5)] }, (sig) => sig !== "a0"), STREAM, ["a0", "seed"], BigInt(1), { judge });
  assert.equal(partial.proven, false);
  assert.match(partial.reason ?? "", /recorded for sequence 0 .* not retrievable .* archive endpoint/);
  assert.ok(!partial.newest.includes("spam-new"), "the record is not moved");
  const flood = Array.from({ length: 250 }, (_, i) => tx(`spam-${i}`, 1000 - i, { err: true }));
  const unbounded = await proveCachedSequences(fakeSource({ [addressOf(0)]: [...flood, tx("a0", 10)] }), STREAM, ["a0", "seed"], BigInt(1), { judge, maxNew: 200 });
  assert.equal(unbounded.proven, false);
  assert.match(unbounded.reason ?? "", /more than 200 new transactions/);
  const bounded = await proveCachedSequences(fakeSource({ [addressOf(0)]: [...flood, tx("a0", 10)] }), STREAM, ["a0", "seed"], BigInt(1), { judge });
  assert.equal(bounded.proven, true, "250 failed transactions sit inside the default bound");
  assert.equal(bounded.inadmissible, 250);
  assert.ok(CACHE_PROOF_MAX_NEW >= 250);
  const exact = await proveCachedSequences(fakeSource({ [addressOf(0)]: [...flood.slice(0, 200), tx("a0", 10)] }), STREAM, ["a0", "seed"], BigInt(1), { judge, maxNew: 200 });
  assert.equal(exact.proven, true, "exactly the bound is not more than the bound");
  assert.equal(exact.inadmissible, 200);
});

test("the next checkpoint's newest-signature list: the cached part then the keys read, null when anything is missing", () => {
  const read = new Map<bigint, string | null>([[BigInt(0), "r0"], [BigInt(1), "r1"], [BigInt(2), null], [BigInt(3), "r3"]]);
  assert.deepEqual(assembleNewestList([], BigInt(0), BigInt(3), read), ["r0", "r1", null, "r3"], "a full run records every key it read");
  assert.deepEqual(assembleNewestList(["c0", "c1", "c2-old"], BigInt(2), BigInt(3), read), ["c0", "c1", null, "r3"], "a resumed run keeps the cached part and re-reads its seed");
  assert.equal(assembleNewestList(null, BigInt(2), BigInt(3), read), null, "no cached list: nothing is written");
  assert.equal(assembleNewestList(["c0"], BigInt(2), BigInt(3), read), null, "a cached part shorter than the seed");
  assert.equal(assembleNewestList([], BigInt(0), BigInt(5), read), null, "a sequence in the range was not read");
  assert.deepEqual(assembleNewestList(["c0", "c1"], BigInt(1), BigInt(1), read), ["c0", "r1"], "nothing after the seed: the seed's own fresh record");
});
