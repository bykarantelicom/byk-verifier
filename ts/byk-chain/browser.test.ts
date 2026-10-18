/* The in-browser trust chain (byk-chain/browser.ts) against a synthetic stream on a fake network. Every check must
 * PASS on honest data and FAIL on each kind of lie; spam, truncation and outages must read "unavailable", never pass.
 * The fake index behaves like base.easscan.org: one recipient per query, ids ascending, take/skip pages, no marker
 * when a page is cut. Attestation answers are encoded with viem, independent of the hand-written decoder.
 * Keys are derived here for the test only; they are not the public Hardhat keys and hold nothing. */
import assert from "node:assert/strict";
import { test } from "node:test";

import { encodeAbiParameters, type Hex, parseAbiParameters } from "viem";

import { alAuthorize, alCheckpoint, makeBundle } from "../byk/authlog";
import { base58Decode, base58Encode, fromHex, toHex, U64_MAX } from "../byk/bytes";
import { addressOfPrivateKey, keccak256, signDigest } from "../byk/crypto";
import { encodeGenesisCore, encodeManifest, SOLANA_MAINNET_GENESIS_B58, WITNESS_KIND, witnessKey } from "../byk/stream";
import { EAS_AL_SCHEMA, EAS_DATA_SCHEMA, EAS_GENESIS_SCHEMA, easDataOf, easSchemaUid, memoData, SPL_MEMO_PROGRAM_ID, type WitnessPayload } from "../byk/witness";
import { admissibleAttestation, BASE_READ_BUDGET, BROWSER_NETS, checkDataAnchor, decodeAttestation, INDEX_MAX_PAGES, INDEX_PAGE, MAINNET_STREAM_ID, type PostJson, readTrustChain, signerAuthorizedOnChain, type TrustChain } from "./browser";

const NET = BROWSER_NETS.mainnet; // endpoints only; the fake network answers on these urls
// each synthetic stream is pinned the way the mainnet stream is pinned in production
const netFor = (w: { streamId: Uint8Array }) => ({ ...BROWSER_NETS.mainnet, pinnedStreamId: toHex(w.streamId) });
const key = (label: string) => keccak256(new TextEncoder().encode(`byk-browser-test:${label}`));
const GOV = key("governance");
const SIGNER = key("data-signer");
const STRANGER = key("stranger");
const SIGNER2 = key("second-signer");
const T0 = BigInt(1_789_700_000_000 - (1_789_700_000_000 % 300_000));
const T0S = Number(T0 / BigInt(1000));
const endOf = (seq: number) => T0S + (seq + 1) * 300; // window end of a sequence, seconds
const NOW = Number(T0) + 3 * 86_400_000; // three days after genesis: seq 5 is "old"

type Att = { uid: string; schema: string; data: Uint8Array; recipient: Uint8Array; time: number; revocable?: boolean; expiration?: bigint; ref?: Uint8Array };

function encodeAtt(a: Att): string {
  const tuple = parseAbiParameters("(bytes32 uid, bytes32 schema, uint64 time, uint64 expirationTime, uint64 revocationTime, bytes32 refUID, address recipient, address attester, bool revocable, bytes data)");
  return encodeAbiParameters(tuple, [{
    uid: a.uid as Hex, schema: ("0x" + toHex(easSchemaUid(a.schema))) as Hex, time: BigInt(a.time), expirationTime: a.expiration ?? BigInt(0), revocationTime: BigInt(0),
    refUID: ("0x" + toHex(a.ref ?? new Uint8Array(32))) as Hex, recipient: ("0x" + toHex(a.recipient)) as Hex, attester: "0x00000000000000000000000000000000000000aa",
    revocable: a.revocable ?? false, data: ("0x" + toHex(a.data)) as Hex,
  }]);
}

/** A fake Base node + EAS index + Solana node. Anything can be overridden per test to tell a lie. */
function world(opts: { chainId?: bigint; alSigner?: Uint8Array; revokeAt?: bigint; genesisOther?: boolean; checkpoint?: { seq: bigint; commitment: Uint8Array }; secondSigner?: boolean } = {}) {
  const gin = (gov: Uint8Array, name: string, chainId: bigint) => encodeGenesisCore({ threshold: 1, governance: [addressOfPrivateKey(gov)], genesisEpochStartMs: T0, streamName: name, baseChainId: chainId, solanaGenesisHash: base58Decode(SOLANA_MAINNET_GENESIS_B58), baseEasAddress: fromHex("4200000000000000000000000000000000000021") });
  const core = gin(GOV, "BYK.TEST.BROWSER", opts.chainId ?? BigInt(8453));
  const streamId = keccak256(core);
  const atts: Att[] = [];
  let uidN = 0;
  const add = (schema: string, p: WitnessPayload, recipientKey: Uint8Array, time: number, extra: Partial<Att> = {}, uidPrefix = "5") => {
    // uids sort by their first hex digit: "0" junk before, "5" honest, "f" after
    const uid = "0x" + uidPrefix + toHex(keccak256(new TextEncoder().encode(`uid${uidN++}`))).slice(1);
    atts.push({ uid, schema, data: easDataOf(p).data, recipient: recipientKey.subarray(12), time, ...extra });
    return uid;
  };
  const junk = (recipientKey: Uint8Array, count: number, uidPrefix = "0") => {
    for (let i = 0; i < count; i++) atts.push({ uid: "0x" + uidPrefix + toHex(keccak256(new TextEncoder().encode(`junk${uidN++}`))).slice(1), schema: EAS_DATA_SCHEMA, data: new Uint8Array(64).fill(7), recipient: recipientKey.subarray(12), time: T0S });
  };
  const gKey = witnessKey(streamId, WITNESS_KIND.GENESIS, BigInt(0));
  add(EAS_GENESIS_SCHEMA, { kind: "genesis", core: opts.genesisOther ? gin(STRANGER, "BYK.OTHER", BigInt(8453)) : core }, gKey, T0S);
  const e1 = alAuthorize(BigInt(1), streamId, new Uint8Array(32), addressOfPrivateKey(SIGNER), BigInt(0), U64_MAX);
  add(EAS_AL_SCHEMA, { kind: "al", entry: e1, bundle: makeBundle(keccak256(e1), [opts.alSigner ?? GOV]) }, witnessKey(streamId, WITNESS_KIND.AL, BigInt(1)), T0S + 10);
  let prev = keccak256(e1);
  let seqAl = BigInt(2);
  if (opts.revokeAt !== undefined) {
    const e2 = alAuthorize(seqAl, streamId, prev, addressOfPrivateKey(SIGNER), BigInt(0), opts.revokeAt);
    add(EAS_AL_SCHEMA, { kind: "al", entry: e2, bundle: makeBundle(keccak256(e2), [GOV]) }, witnessKey(streamId, WITNESS_KIND.AL, seqAl), T0S + 20, {}, "f");
    prev = keccak256(e2);
    seqAl++;
  }
  if (opts.checkpoint) {
    const e3 = alCheckpoint(seqAl, streamId, prev, opts.checkpoint.seq, opts.checkpoint.commitment);
    add(EAS_AL_SCHEMA, { kind: "al", entry: e3, bundle: makeBundle(keccak256(e3), [GOV]) }, witnessKey(streamId, WITNESS_KIND.AL, seqAl), T0S + 30);
    prev = keccak256(e3);
    seqAl++;
  }
  if (opts.secondSigner) {
    const e4 = alAuthorize(seqAl, streamId, prev, addressOfPrivateKey(SIGNER2), BigInt(0), U64_MAX);
    add(EAS_AL_SCHEMA, { kind: "al", entry: e4, bundle: makeBundle(keccak256(e4), [GOV]) }, witnessKey(streamId, WITNESS_KIND.AL, seqAl), T0S + 40);
    prev = keccak256(e4);
    seqAl++;
  }
  // well-formed log entries that nobody in governance signed, at the next keys: they must not be walked
  const junkLog = (count: number) => {
    for (let i = 0; i < count; i++) {
      const n = seqAl + BigInt(i);
      const e = alAuthorize(n, streamId, keccak256(new TextEncoder().encode(`x${i}`)), addressOfPrivateKey(STRANGER), BigInt(0), U64_MAX);
      add(EAS_AL_SCHEMA, { kind: "al", entry: e, bundle: makeBundle(keccak256(e), [STRANGER]) }, witnessKey(streamId, WITNESS_KIND.AL, n), T0S + 50);
    }
  };
  const manifestOf = (seq: bigint, rootLabel = "root") => encodeManifest({ status: 0, sequence: seq, epochStartMs: T0 + seq * BigInt(300_000), epochEndMs: T0 + (seq + BigInt(1)) * BigInt(300_000), recordCount: 35, streamId, merkleRoot: keccak256(new TextEncoder().encode(rootLabel)), previousCommitment: new Uint8Array(32), schemaHash: new Uint8Array(32).fill(1), methodologyHash: new Uint8Array(32).fill(2) });
  const sign = (m: Uint8Array, k = SIGNER) => signDigest(k, keccak256(m));
  const solana = new Map<string, unknown>();
  const sigsByAddress = new Map<string, string[]>();
  const solanaAnchor = (m: Uint8Array, s: Uint8Array, id: string, blockTimeSec: number, err: unknown = null) => {
    const seq = BigInt(new DataView(m.buffer, m.byteOffset + 8, 8).getBigUint64(0));
    const address = base58Encode(witnessKey(streamId, WITNESS_KIND.DATA, seq));
    solana.set(id, { slot: 1, blockTime: blockTimeSec, meta: { err }, transaction: { message: { accountKeys: ["FeePayer1111111111111111111111111111111111", address, SPL_MEMO_PROGRAM_ID], instructions: [{ programIdIndex: 2, data: base58Encode(new TextEncoder().encode(memoData(m, s))) }] } } });
    sigsByAddress.set(address, [id, ...(sigsByAddress.get(address) ?? [])]); // newest first, as the RPC lists them
  };
  const solanaJunk = (seq: bigint, count: number) => {
    const address = base58Encode(witnessKey(streamId, WITNESS_KIND.DATA, seq));
    for (let i = 0; i < count; i++) {
      const id = `junk${seq}-${i}`;
      solana.set(id, { slot: 1, blockTime: endOf(Number(seq)) + 500, meta: { err: null }, transaction: { message: { accountKeys: ["FeePayer1111111111111111111111111111111111", address], instructions: [] } } });
      sigsByAddress.set(address, [id, ...(sigsByAddress.get(address) ?? [])]);
    }
  };
  let indexDown = false;
  let baseDown = false;
  let signaturesError = false;
  let firstBlock = 0; // an archive node by default
  let firstBlockTimeSec = 0;
  let blockTimeFails = 0; // how many getBlockTime calls answer "cleaned up" before one succeeds
  const hidden = new Set<string>(); // listed but not returned by getTransaction
  const calls = { index: 0, base: 0, solanaTx: 0 };
  const post: PostJson = async (url, body) => {
    const b = body as { method?: string; params?: unknown[]; variables?: { r: string; k: number } };
    if (url === NET.easGraphql) {
      calls.index++;
      if (indexDown) throw new Error("HTTP 503");
      const rows = atts.filter((a) => "0x" + toHex(a.recipient) === b.variables!.r).sort((x, y) => (x.uid < y.uid ? -1 : 1)).slice(b.variables!.k, b.variables!.k + INDEX_PAGE);
      return { data: { attestations: rows.map((a) => ({ id: a.uid, recipient: "0x" + toHex(a.recipient).toUpperCase(), schemaId: "0x" + toHex(easSchemaUid(a.schema)), data: "0x" + toHex(a.data) })) } };
    }
    if (NET.baseRpc.includes(url)) {
      calls.base++;
      if (baseDown) throw new Error("HTTP 502");
      const uid = "0x" + (b.params![0] as { data: string }).data.slice(10);
      const a = atts.find((x) => x.uid === uid);
      return { result: a ? encodeAtt(a) : encodeAtt({ uid: "0x" + "00".repeat(32), schema: EAS_DATA_SCHEMA, data: new Uint8Array(0), recipient: new Uint8Array(20), time: 0 }) };
    }
    if (url === NET.solanaRpc) {
      if (b.method === "getTransaction") {
        calls.solanaTx++;
        const id = b.params![0] as string;
        return { result: hidden.has(id) ? null : solana.get(id) ?? null };
      }
      if (b.method === "getFirstAvailableBlock") return { result: firstBlock };
      if (b.method === "getBlockTime") {
        if (blockTimeFails > 0) {
          blockTimeFails--;
          return { jsonrpc: "2.0", error: { code: -32001, message: `Block ${b.params![0]} cleaned up, does not exist on node. First available block: ${firstBlock + 5}` } };
        }
        return { result: firstBlockTimeSec };
      }
      if (b.method === "getSignaturesForAddress") {
        if (signaturesError) return { jsonrpc: "2.0", error: { code: 429, message: "Too many requests" } };
        const all = sigsByAddress.get(b.params![0] as string) ?? [];
        const o = b.params![1] as { limit: number; before?: string };
        const from = o.before ? all.indexOf(o.before) + 1 : 0;
        return { result: all.slice(from, from + o.limit).map((signature) => ({ signature, err: null })) };
      }
    }
    throw new Error(`unexpected ${url}`);
  };
  return {
    streamId, atts, add, junk, junkLog, manifestOf, sign, solanaAnchor, solanaJunk, post, gKey, calls, hidden,
    down: (i: boolean, bd: boolean) => { indexDown = i; baseDown = bd; },
    sigError: (v: boolean) => { signaturesError = v; },
    retention: (fromSec: number) => { firstBlock = 1_000; firstBlockTimeSec = fromSec; },
    blockTimeFailing: (n: number) => { blockTimeFails = n; },
  };
}

async function ready(w: ReturnType<typeof world>): Promise<Extract<TrustChain, { ok: true }>> {
  const chain = await readTrustChain(w.post, netFor(w), w.streamId);
  if (!chain.ok) assert.fail(`trust chain: ${chain.step} ${chain.reason}`);
  return chain;
}
const reasonOf = (r: { state: string; reason?: string }) => (r.state === "fail" ? r.reason ?? "" : r.state);

test("decodeAttestation reads exactly what viem encodes, and rejects a truncated answer", () => {
  const w = world();
  const a = w.atts[0]!;
  const d = decodeAttestation(encodeAtt(a));
  assert.equal("0x" + toHex(d.uid), a.uid);
  assert.equal(toHex(d.recipient), toHex(a.recipient));
  assert.equal(toHex(d.data), toHex(a.data));
  assert.equal(d.revocable, false);
  assert.throws(() => decodeAttestation(encodeAtt(a).slice(0, 200)));
});

test("honest stream: genesis, log and signer come from the chain; Solana and Base anchors pass", async () => {
  const w = world();
  const chain = await ready(w);
  assert.equal(chain.entries, 1);
  assert.equal(signerAuthorizedOnChain(chain, addressOfPrivateKey(SIGNER), BigInt(5)), true);
  assert.equal(signerAuthorizedOnChain(chain, addressOfPrivateKey(STRANGER), BigInt(5)), false);
  const m = w.manifestOf(BigInt(5));
  const s = w.sign(m);
  w.solanaAnchor(m, s, "sigA", endOf(5) + 50);
  assert.deepEqual(await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m, s, "sigA", NOW), { state: "pass", via: "solana", timeMs: (endOf(5) + 50) * 1000, secondsAfterWindow: 50 });
  // the Solana node no longer has the named id: the daily Base attestation carries the proof instead
  const m7 = w.manifestOf(BigInt(7));
  const s7 = w.sign(m7);
  w.add(EAS_DATA_SCHEMA, { kind: "data", manifest: m7, signature: s7 }, witnessKey(w.streamId, WITNESS_KIND.DATA, BigInt(7)), endOf(7) + 40);
  const viaBase = await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m7, s7, "pruned", NOW);
  assert.equal(viaBase.state === "pass" && viaBase.via, "base");
});

test("the verifier refuses a stream other than the one built into it", async () => {
  const w = world();
  const pinned = { ...BROWSER_NETS.mainnet };
  assert.equal(pinned.pinnedStreamId, MAINNET_STREAM_ID);
  const chain = await readTrustChain(w.post, pinned, w.streamId);
  assert.equal(!chain.ok && chain.step, "genesis");
  assert.equal(!chain.ok && chain.unavailable, false);
});

test("no genesis of this stream on the index is 'unavailable', a genesis naming other networks is 'fail'", async () => {
  const honest = world();
  const other = await readTrustChain(world({ genesisOther: true }).post, netFor(honest), honest.streamId);
  assert.equal(!other.ok && other.step, "genesis");
  assert.equal(!other.ok && other.unavailable, true);
  const w = world({ chainId: BigInt(84532) });
  const wrongNet = await readTrustChain(w.post, netFor(w), w.streamId);
  assert.equal(!wrongNet.ok && wrongNet.unavailable, false);
  assert.match(!wrongNet.ok ? wrongNet.reason : "", /other networks/);
});

test("an authorization signed by someone other than governance authorizes nobody and applies no entry", async () => {
  const w = world({ alSigner: STRANGER });
  const chain = await ready(w);
  assert.equal(chain.entries, 0);
  assert.equal(chain.attested, 0, "a bundle no governance member signed is screened out before it costs a Base read");
  assert.equal(signerAuthorizedOnChain(chain, addressOfPrivateKey(SIGNER), BigInt(5)), false);
});

test("a signer whose authorization governance ended is refused after the end, accepted before it", async () => {
  const chain = await ready(world({ revokeAt: BigInt(10) }));
  assert.equal(chain.entries, 2);
  assert.equal(signerAuthorizedOnChain(chain, addressOfPrivateKey(SIGNER), BigInt(9)), true);
  assert.equal(signerAuthorizedOnChain(chain, addressOfPrivateKey(SIGNER), BigInt(10)), false);
});

test("spam cannot hide the genesis or a revocation: listings are paged per key, junk is screened, overflow is unavailable", async () => {
  // 150 junk attestations sorted before the genesis under its own key, and 250 before the revocation under AL key 2
  const w = world({ revokeAt: BigInt(10) });
  w.junk(w.gKey, 150);
  w.junk(witnessKey(w.streamId, WITNESS_KIND.AL, BigInt(2)), 250);
  const chain = await ready(w);
  assert.equal(chain.entries, 2);
  assert.equal(signerAuthorizedOnChain(chain, addressOfPrivateKey(SIGNER), BigInt(20)), false, "the revocation is still seen");
  // a key flooded past the page budget makes the log unprovable: unavailable, never a shorter log
  const f = world({ revokeAt: BigInt(10) });
  f.junk(witnessKey(f.streamId, WITNESS_KIND.AL, BigInt(2)), INDEX_PAGE * INDEX_MAX_PAGES);
  const flooded = await readTrustChain(f.post, netFor(f), f.streamId);
  assert.equal(!flooded.ok && flooded.step, "log");
  assert.equal(!flooded.ok && flooded.unavailable, true);
});

test("inadmissible attestations are ignored: revocable, expiring, with a ref, sent elsewhere, or moved to another key", () => {
  const w = world();
  const g = w.atts[0]!;
  const ok = decodeAttestation(encodeAtt(g));
  assert.ok(admissibleAttestation(ok, EAS_GENESIS_SCHEMA, w.gKey, w.streamId));
  for (const bad of [{ revocable: true }, { expiration: BigInt(1) }, { ref: new Uint8Array(32).fill(7) }, { recipient: new Uint8Array(20).fill(9) }]) {
    assert.equal(admissibleAttestation(decodeAttestation(encodeAtt({ ...g, ...bad })), EAS_GENESIS_SCHEMA, w.gKey, w.streamId), null);
  }
  assert.equal(admissibleAttestation(ok, EAS_AL_SCHEMA, w.gKey, w.streamId), null, "a schema other than the one indexed");
  const m6 = w.manifestOf(BigInt(6));
  const k5 = witnessKey(w.streamId, WITNESS_KIND.DATA, BigInt(5));
  const moved = decodeAttestation(encodeAtt({ uid: "0x" + "11".repeat(32), schema: EAS_DATA_SCHEMA, data: easDataOf({ kind: "data", manifest: m6, signature: w.sign(m6) }).data, recipient: k5.subarray(12), time: 1 }));
  assert.equal(admissibleAttestation(moved, EAS_DATA_SCHEMA, k5, w.streamId), null);
});

test("the anchor must carry this manifest, its earliest copy must follow the window, and no authorized rival may exist", async () => {
  // the named transaction carries a different manifest
  const a = world();
  const ca = await ready(a);
  const m = a.manifestOf(BigInt(5));
  const other = a.manifestOf(BigInt(5), "other-root");
  a.solanaAnchor(other, a.sign(other), "sigOther", endOf(5) + 30);
  assert.equal((await checkDataAnchor(a.post, netFor(a), ca, a.streamId, m, a.sign(m), "sigOther", NOW)).state, "fail");
  // an earlier copy of the same manifest, posted before the window closed, is the anchor's real position
  const b = world();
  const cb = await ready(b);
  const mb = b.manifestOf(BigInt(5));
  const sb = b.sign(mb);
  b.solanaAnchor(mb, sb, "sigEarly", endOf(5) - 5);
  b.solanaAnchor(mb, sb, "sigLate", endOf(5) + 50);
  assert.match(reasonOf(await checkDataAnchor(b.post, netFor(b), cb, b.streamId, mb, sb, "sigLate", NOW)), /before its window closed/);
  // a rival signed by the authorized signer, hidden behind 120 junk signatures on Solana
  const c = world();
  const cc = await ready(c);
  const mc = c.manifestOf(BigInt(5));
  const sc = c.sign(mc);
  const rival = c.manifestOf(BigInt(5), "rival");
  c.solanaAnchor(rival, c.sign(rival), "sigRival", endOf(5) + 60);
  c.solanaJunk(BigInt(5), 120);
  c.solanaAnchor(mc, sc, "sigMine", endOf(5) + 40);
  assert.match(reasonOf(await checkDataAnchor(c.post, netFor(c), cc, c.streamId, mc, sc, "sigMine", NOW)), /equivocation/);
  // a rival that sits only on Base, while Solana passes
  const d = world();
  const cd = await ready(d);
  const md = d.manifestOf(BigInt(5));
  const sd = d.sign(md);
  d.solanaAnchor(md, sd, "sigMine", endOf(5) + 40);
  const rivalD = d.manifestOf(BigInt(5), "base-rival");
  d.add(EAS_DATA_SCHEMA, { kind: "data", manifest: rivalD, signature: d.sign(rivalD) }, witnessKey(d.streamId, WITNESS_KIND.DATA, BigInt(5)), endOf(5) + 90);
  assert.match(reasonOf(await checkDataAnchor(d.post, netFor(d), cd, d.streamId, md, sd, "sigMine", NOW)), /equivocation/);
  // a rival signed by a stranger is spam, not equivocation
  const e = world();
  const ce = await ready(e);
  const me = e.manifestOf(BigInt(5));
  const se = e.sign(me);
  e.solanaAnchor(me, se, "sigMine", endOf(5) + 40);
  const spam = e.manifestOf(BigInt(5), "spam");
  e.solanaAnchor(spam, e.sign(spam, STRANGER), "sigSpam", endOf(5) + 70);
  assert.equal((await checkDataAnchor(e.post, netFor(e), ce, e.streamId, me, se, "sigMine", NOW)).state, "pass");
});

test("a Solana listing that errors or runs past its budget is unavailable, never a pass", async () => {
  const w = world();
  const chain = await ready(w);
  const m = w.manifestOf(BigInt(5));
  const s = w.sign(m);
  w.solanaAnchor(m, s, "sigMine", endOf(5) + 40);
  w.sigError(true);
  const errored = await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m, s, "sigMine", NOW);
  assert.equal(errored.state === "unavailable" && errored.cause, "unreachable");
  w.sigError(false);
  w.solanaJunk(BigInt(5), 250);
  const flooded = await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m, s, "sigMine", NOW);
  assert.equal(flooded.state === "unavailable" && flooded.cause, "flooded");
});

test("a manifest outside the stream's time or against a governance checkpoint fails", async () => {
  const w = world();
  const chain = await ready(w);
  const m = w.manifestOf(BigInt(5));
  assert.match(reasonOf(await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m, w.sign(m), null, Number(T0) + 60_000)), /later than time allows/);
  const cp = world({ checkpoint: { seq: BigInt(5), commitment: keccak256(w.manifestOf(BigInt(5), "checkpointed")) } });
  const cchain = await ready(cp);
  const mine = cp.manifestOf(BigInt(5));
  assert.match(reasonOf(await checkDataAnchor(cp.post, netFor(cp), cchain, cp.streamId, mine, cp.sign(mine), null, NOW)), /checkpointed a different manifest/);
});

test("unreachable and unreadable sources are unavailable with the right cause", async () => {
  const w = world();
  const chain = await ready(w);
  const m = w.manifestOf(BigInt(5));
  const s = w.sign(m);
  w.down(true, false);
  const noIndex = await readTrustChain(w.post, netFor(w), w.streamId);
  assert.equal(!noIndex.ok && noIndex.unavailable, true);
  w.down(false, true);
  const noBase = await readTrustChain(w.post, netFor(w), w.streamId);
  assert.equal(!noBase.ok && noBase.unavailable, true);
  w.down(false, false);
  const archive = await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m, s, "pruned", NOW);
  assert.equal(archive.state === "unavailable" && archive.cause, "no_anchor", "an archive node that has nothing: no anchor, not pruning");
  const w2 = world();
  const chain2 = await ready(w2);
  w2.retention(endOf(5) + 3600);
  const m2 = w2.manifestOf(BigInt(5));
  const pruned = await checkDataAnchor(w2.post, netFor(w2), chain2, w2.streamId, m2, w2.sign(m2), "pruned", NOW);
  assert.equal(pruned.state === "unavailable" && pruned.cause, "not_in_browser");
  const unnamed = await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m, s, null, NOW);
  assert.equal(unnamed.state === "unavailable" && unnamed.cause, "no_anchor");
  const young = await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m, s, null, (endOf(5) + 60) * 1000);
  assert.equal(young.state === "unavailable" && young.cause, "not_final");
  w.down(true, false);
  const gone = await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m, s, "pruned", NOW);
  assert.equal(gone.state === "unavailable" && gone.cause, "unreachable");
});

test("a failed Solana transaction anchors nothing", async () => {
  const w = world();
  const chain = await ready(w);
  const m = w.manifestOf(BigInt(5));
  const s = w.sign(m);
  w.solanaAnchor(m, s, "sigFailed", endOf(5) + 40, { InstructionError: [0, "Custom"] });
  assert.equal((await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m, s, "sigFailed", NOW)).state, "fail");
});

test("a network with no stream built in is refused", async () => {
  const w = world();
  const chain = await readTrustChain(w.post, { ...BROWSER_NETS.devnet }, w.streamId);
  assert.equal(!chain.ok && chain.unavailable, false);
  assert.match(!chain.ok ? chain.reason : "", /no stream is built into this check/);
});

test("the Solana witness key is enumerated even when our API names no transaction, and an unreadable listed one is unavailable", async () => {
  const w = world();
  const chain = await ready(w);
  const m = w.manifestOf(BigInt(7));
  const s = w.sign(m);
  w.add(EAS_DATA_SCHEMA, { kind: "data", manifest: m, signature: s }, witnessKey(w.streamId, WITNESS_KIND.DATA, BigInt(7)), endOf(7) + 40);
  const rival = w.manifestOf(BigInt(7), "rival");
  w.solanaAnchor(rival, w.sign(rival), "sigRival", endOf(7) + 60);
  assert.match(reasonOf(await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m, s, null, NOW)), /equivocation/);
  const w2 = world();
  const chain2 = await ready(w2);
  const m2 = w2.manifestOf(BigInt(7));
  const s2 = w2.sign(m2);
  w2.solanaAnchor(m2, s2, "sigMine", endOf(7) + 40);
  w2.solanaAnchor(w2.manifestOf(BigInt(7), "r2"), w2.sign(w2.manifestOf(BigInt(7), "r2")), "sigHidden", endOf(7) + 70);
  w2.hidden.add("sigHidden");
  const hiddenRival = await checkDataAnchor(w2.post, netFor(w2), chain2, w2.streamId, m2, s2, "sigMine", NOW);
  assert.equal(hiddenRival.state === "unavailable" && hiddenRival.cause, "unreachable");
});

test("an earlier copy of the same manifest signed by another authorized key is the anchor's position", async () => {
  const w = world({ secondSigner: true });
  const chain = await ready(w);
  const m = w.manifestOf(BigInt(5));
  const s = w.sign(m);
  w.solanaAnchor(m, w.sign(m, SIGNER2), "sigEarlyOtherKey", endOf(5) - 60);
  w.solanaAnchor(m, s, "sigServed", endOf(5) + 30);
  const r = await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m, s, "sigServed", NOW);
  assert.equal(r.state === "fail" && r.code, "early");
});

test("junk log entries end the log walk at once, and re-posted copies cost one Base read", async () => {
  const w = world();
  w.junkLog(40);
  const before = w.calls.index;
  const chain = await ready(w);
  assert.equal(chain.entries, 1);
  assert.ok(w.calls.index - before <= 4, `index queries ${w.calls.index - before}`);
  const c = world();
  const g = c.atts[0]!;
  for (let i = 0; i < 500; i++) c.atts.push({ ...g, uid: "0xf" + toHex(keccak256(new TextEncoder().encode(`copy${i}`))).slice(1), time: g.time + 100 + i });
  const baseBefore = c.calls.base;
  await ready(c);
  assert.ok(c.calls.base - baseBefore <= 3, `Base reads ${c.calls.base - baseBefore}`);
});

test("unsigned junk never counts against the read budget; only signed payloads can flood a key", async () => {
  // 61 well-formed payloads signed by a stranger on the data key: free, the epoch still passes
  const w = world();
  const chain = await ready(w);
  const m = w.manifestOf(BigInt(5));
  const s = w.sign(m);
  w.solanaAnchor(m, s, "sigMine", endOf(5) + 40);
  for (let i = 0; i <= BASE_READ_BUDGET; i++) {
    const spam = w.manifestOf(BigInt(5), `spam${i}`);
    w.add(EAS_DATA_SCHEMA, { kind: "data", manifest: spam, signature: w.sign(spam, STRANGER) }, witnessKey(w.streamId, WITNESS_KIND.DATA, BigInt(5)), endOf(5) + 90);
  }
  assert.equal((await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m, s, "sigMine", NOW)).state, "pass");
  // 61 well-formed log entries for the next log_seq, signed by a stranger: the trust chain is unaffected
  const a = world();
  for (let i = 0; i <= BASE_READ_BUDGET; i++) {
    const e = alAuthorize(BigInt(2), a.streamId, keccak256(new TextEncoder().encode(`h${i}`)), addressOfPrivateKey(STRANGER), BigInt(0), U64_MAX);
    a.add(EAS_AL_SCHEMA, { kind: "al", entry: e, bundle: makeBundle(keccak256(e), [STRANGER]) }, witnessKey(a.streamId, WITNESS_KIND.AL, BigInt(2)), T0S + 60);
  }
  assert.equal((await ready(a)).entries, 1);
  // 61 distinct manifests signed by the AUTHORIZED key: that key is flooded, the answer is unavailable, never a pass
  const f = world();
  const cf = await ready(f);
  const mf = f.manifestOf(BigInt(5));
  const sf = f.sign(mf);
  for (let i = 0; i <= BASE_READ_BUDGET; i++) {
    const other = f.manifestOf(BigInt(5), `signed${i}`);
    f.add(EAS_DATA_SCHEMA, { kind: "data", manifest: other, signature: f.sign(other) }, witnessKey(f.streamId, WITNESS_KIND.DATA, BigInt(5)), endOf(5) + 90);
  }
  const r = await checkDataAnchor(f.post, netFor(f), cf, f.streamId, mf, sf, null, NOW);
  assert.equal(r.state === "unavailable" && r.cause, "flooded");
});

test("the Solana history probe is asked only when nothing was found, and its failures never hide a result", async () => {
  // an anchor that is found passes even while the probe would fail
  const w = world();
  const chain = await ready(w);
  const m = w.manifestOf(BigInt(5));
  const s = w.sign(m);
  w.solanaAnchor(m, s, "sigMine", endOf(5) + 40);
  w.retention(1);
  w.blockTimeFailing(10);
  assert.equal((await checkDataAnchor(w.post, netFor(w), chain, w.streamId, m, s, "sigMine", NOW)).state, "pass");
  // nothing found, the probe hits a pruned backend once: it retries with the slot the error names
  const v = world();
  const cv = await ready(v);
  const mv = v.manifestOf(BigInt(5));
  v.retention(endOf(5) + 3600);
  v.blockTimeFailing(1);
  // 20 hours after the window: only the retried answer (history starts after the window) can say "not in browser";
  // the age fallback alone would say "no anchor"
  const twentyHours = (endOf(5) + 20 * 3600) * 1000;
  const once = await checkDataAnchor(v.post, netFor(v), cv, v.streamId, mv, v.sign(mv), "gone", twentyHours);
  assert.equal(once.state === "unavailable" && once.cause, "not_in_browser");
  // the probe fails for good: the cause falls back on the epoch's age, the step is still only unavailable
  const x = world();
  const cx = await ready(x);
  const mx = x.manifestOf(BigInt(5));
  x.retention(endOf(5) + 3600);
  x.blockTimeFailing(10);
  const fallback = await checkDataAnchor(x.post, netFor(x), cx, x.streamId, mx, x.sign(mx), "gone", NOW);
  assert.equal(fallback.state === "unavailable" && fallback.cause, "not_in_browser");
});
