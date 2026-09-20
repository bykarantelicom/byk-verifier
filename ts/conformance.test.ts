/* Conformance of src/lib/byk with BYK Data Layer v1.0.0-rc6.
 *
 * The vector file is the UNMODIFIED output of the Python reference generator (byk_gen_vectors.py); its SHA-256
 * is pinned below. This test rebuilds every structure of Sections 17.1 to 17.10 and Annex A from first
 * principles with the TypeScript library, in the same order as the generator, and compares byte for byte.
 *
 * The private keys below are the PUBLIC Hardhat/Anvil development keys (accounts 0 to 5), the same ones the
 * reference generator uses. They are needed to prove that signing is deterministic and byte-identical
 * (RFC 6979, low-S). They are worthless as secrets and MUST NEVER sign anything outside this test. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import * as B from "./index";

const VECTOR_PATH = path.join(__dirname, "vectors", "byk_v1_test_vectors.json");
const VECTOR_SHA256 = "a826aa48092184959b0fe32c52bb4d3da263f912fe9db885110e081b9670e870";
const raw = fs.readFileSync(VECTOR_PATH);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const V: any = JSON.parse(raw.toString("utf8"));

const hx = B.toHex;
const big = (x: number | string | bigint) => BigInt(x);
const SAFE = BigInt(Number.MAX_SAFE_INTEGER);

/** Library values in the JSON shape of the vector file: bytes as hex, maps as objects, integers beyond
 *  +-(2^53 - 1) as decimal strings (Section 17 note), everything else unchanged. */
function norm(o: unknown): unknown {
  if (typeof o === "bigint") return B.absBig(o) > SAFE ? o.toString() : Number(o);
  if (o instanceof Uint8Array) return hx(o);
  if (o instanceof Map) return Object.fromEntries([...o.entries()].map(([k, v]) => [String(k), norm(v)]));
  if (Array.isArray(o)) return o.map(norm);
  if (o && typeof o === "object") return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined).map(([k, v]) => [k, norm(v)]));
  return o;
}

function key(hex: string, expected: string): Uint8Array {
  const k = B.fromHex(hex);
  assert.equal("0x" + hx(B.addressOfPrivateKey(k)), expected.toLowerCase());
  return k;
}
const S1 = key("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const G1 = key("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
const G2 = key("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a", "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
const G3 = key("7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6", "0x90F79bf6EB2c4f870365E785982E1f101E93b906");
const G4 = key("47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a", "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65");
const S2 = key("8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba", "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc");
const A = B.addressOfPrivateKey;
const sorted = (xs: Uint8Array[]) => [...xs].sort(B.compare);

// ---------------------------------------------------------------- shared fixtures, built like the generator
const T0 = big(1_789_257_600_000);
const E = B.EPOCH_MS;
const GOV = sorted([A(G1), A(G2), A(G3)]);
const core = B.encodeGenesisCore({
  threshold: 2, governance: GOV, genesisEpochStartMs: T0, streamName: "BYK.DATALAYER.TESTVECTORS", baseChainId: B.BASE_SEPOLIA_CHAIN_ID,
  solanaGenesisHash: B.base58Decode(B.SOLANA_DEVNET_GENESIS_B58), baseEasAddress: B.fromHex(B.BASE_EAS_ADDRESS_HEX),
});
const genesis = B.parseGenesisCore(core);
const STREAM = genesis.streamId;

const PRM: Record<string, unknown> = V.annex_a.parameters;
type CatalogRow = [string, string, number, "A" | "B"];
const CATALOG: CatalogRow[] = V.audit.catalog;
const catalog: B.CatalogEntry[] = CATALOG.map(([feed, asset, decimals, dataClass]) => ({ feed, asset, decimals, dataClass }));

const snapshots = new Map<string, B.ClassASnapshot>();
for (const [k, s] of Object.entries<{ T: number; parameters: Record<string, unknown>; venues: B.FundingVenueInput[] }>(V.audit.class_a_snapshots)) {
  snapshots.set(k, { T: big(s.T), parameters: s.parameters, venues: s.venues });
}

type Mutation = Partial<Record<"status" | "value" | "dispersion" | "sourceCount" | "coverageBps" | "outlierCount" | "maxSourceAgeMs", number | bigint>>;
/** Leaves of the OK/DEGRADED epoch `seq` ending at `tx`: Class A leaves computed from their snapshots, the
 *  Class B leaf fixed. `drop` and `mutate` build the adversarial variants of Section 17.9. */
function epochRecords(tx: bigint, seq: number, drop?: string, mutate?: Record<string, Mutation>) {
  const recs: Array<{ feed: string; asset: string; leaf: Uint8Array }> = [];
  for (const [feed, asset, decimals, cls] of CATALOG) {
    if (drop === feed) continue;
    let f: Omit<B.Leaf, "decimals" | "feedId" | "assetId" | "observedAtMs">;
    if (cls === "A") {
      const snap = snapshots.get(B.snapshotKey(big(seq), feed, asset))!;
      assert.equal(snap.T, tx);
      const lf = B.fundingComposite(snap.venues, PRM, tx).leaf;
      f = { status: B.STATUS[lf.status], value: lf.value, sourceCount: lf.source_count, expectedSourceCount: lf.expected_source_count, coverageBps: lf.coverage_bps, outlierCount: lf.outlier_count, maxSourceAgeMs: lf.max_source_age_ms, dispersion: lf.dispersion };
    } else {
      f = { status: 0, value: big(6872), sourceCount: 11, expectedSourceCount: 11, coverageBps: 10000, outlierCount: 0, maxSourceAgeMs: 812, dispersion: big(0) };
    }
    const mut = mutate?.[feed] ?? {};
    const merged = { ...f, ...Object.fromEntries(Object.entries(mut).map(([k, v]) => [k, k === "value" || k === "dispersion" ? big(v as number) : Number(v)])) } as typeof f;
    recs.push({ feed, asset, leaf: B.encodeLeaf({ ...merged, decimals, feedId: B.id32(feed), assetId: B.id32(asset), observedAtMs: tx }) });
  }
  recs.sort((a, b) => B.compare(B.leafKey(a.leaf), B.leafKey(b.leaf)));
  const status = recs.every((r) => r.leaf[1] === 0) ? 0 : 1;
  return { recs, leaves: recs.map((r) => r.leaf), status };
}

const schemaHash = B.keccak256(B.ascii("BYK test vector schema document v1"));
const methodologyHash = B.keccak256(B.ascii("BYK test vector methodology registry v1"));
const EMPTY = B.keccak256(new Uint8Array(0));
const manifest = (status: number, sequence: bigint, start: bigint, end: bigint, recordCount: number, root: Uint8Array, prev: Uint8Array) =>
  B.encodeManifest({ status, sequence, epochStartMs: start, epochEndMs: end, recordCount, streamId: STREAM, merkleRoot: root, previousCommitment: prev, schemaHash, methodologyHash });
const mul = (n: number) => E * big(n);

const M0 = manifest(3, big(0), T0, T0 + E, 0, EMPTY, B.ZERO32);
const C0 = B.keccak256(M0);
const e1End = T0 + mul(2);
const epoch1 = epochRecords(e1End, 1);
const root1 = B.merkleRoot(epoch1.leaves);
const M1 = manifest(epoch1.status, big(1), T0 + E, e1End, epoch1.leaves.length, root1, C0);
const C1 = B.keccak256(M1);
const sigM0 = B.signDigest(S1, C0);
const sigM1 = B.signDigest(S1, C1);

const M2a = manifest(3, big(2), T0 + mul(2), T0 + mul(3), 0, EMPTY, C1);
const M2b = manifest(3, big(2), T0 + mul(2), T0 + mul(4), 0, EMPTY, C1);
const M2bad = manifest(3, big(2), T0 + mul(2), T0 + mul(3), 0, EMPTY, C0);
const [C2a, C2b, C2bad] = [M2a, M2b, M2bad].map(B.keccak256) as [Uint8Array, Uint8Array, Uint8Array];
const M3 = manifest(3, big(3), T0 + mul(3), T0 + mul(4), 0, EMPTY, C2a);
const C3 = B.keccak256(M3);
const M4 = manifest(3, big(4), T0 + mul(4), T0 + mul(5), 0, EMPTY, C3);
const C4 = B.keccak256(M4);
const M5 = manifest(3, big(5), T0 + mul(5), T0 + mul(6), 0, EMPTY, C4);
const C5 = B.keccak256(M5);
const M1x = manifest(3, big(1), T0 + E, T0 + mul(2), 0, EMPTY, C0);
const C1x = B.keccak256(M1x);
const FAR_SEQ = big(1_000_000_000);
const Mfar = manifest(3, FAR_SEQ, T0 + FAR_SEQ * E, T0 + (FAR_SEQ + big(1)) * E, 0, EMPTY, C0);
const MAX_START = ((B.U64_MAX - E) / E) * E;
const Mmax = manifest(3, B.U64_MAX, MAX_START, MAX_START + E, 0, EMPTY, C0);
const GARBAGE_SIG = new Uint8Array(65).fill(1);
const T_TEST = T0 + mul(6) + big(60_000);
const sign = (k: Uint8Array, m: Uint8Array) => B.signDigest(k, B.keccak256(m));
const sig = { M2a: sign(S1, M2a), M2b: sign(S1, M2b), M2bad: sign(S1, M2bad), M3: sign(S1, M3), M4: sign(S1, M4), M5: sign(S1, M5), M_far: sign(S1, Mfar), M_max: sign(S1, Mmax) };
const sigS2 = { M2a: sign(S2, M2a), M3: sign(S2, M3) };
const NAMES = new Map<string, string>([[hx(C0), "C0"], [hx(C1), "C1"], [hx(C2a), "C2a"], [hx(C2b), "C2b"], [hx(C2bad), "C2bad"], [hx(C3), "C3"], [hx(C4), "C4"], [hx(C5), "C5"], [hx(C1x), "C1x"]]);
const pay = (m: Uint8Array, s: Uint8Array): B.AnchoredPayload => ({ manifest: m, signature: s });
const P_BASE = [pay(M0, sigM0), pay(M1, sigM1)];
const P_FORK = [...P_BASE, pay(M2a, sig.M2a), pay(M2b, sig.M2b), pay(M3, sig.M3)];
const P_BADLINK = [...P_BASE, pay(M2a, sig.M2a), pay(M2bad, sig.M2bad), pay(M3, sig.M3)];

type Found = { entry: Uint8Array; bundle: Uint8Array };
const entry = (eb: Uint8Array, signers: Uint8Array[]): Found => ({ entry: eb, bundle: B.makeBundle(B.keccak256(eb), signers) });
const E1 = entry(B.alAuthorize(big(1), STREAM, B.ZERO32, A(S1), big(0), B.U64_MAX), [G2, G1]);
const h1 = B.keccak256(E1.entry);
const E2b = entry(B.alCheckpoint(big(2), STREAM, h1, big(2), C2a), [G1, G3]);
const E2c = entry(B.alCheckpoint(big(2), STREAM, h1, big(2), C2b), [G2, G3]);
const E2d = entry(B.alAuthorize(big(2), STREAM, h1, A(S1), big(0), big(2)), [G1, G2]);
const E3d = entry(B.alAuthorize(big(3), STREAM, B.keccak256(E2d.entry), A(S2), big(2), B.U64_MAX), [G1, G2]);
const E2bad = entry(B.alCheckpoint(big(2), STREAM, h1, big(2), C2bad), [G1, G2]);
const E2restart = entry(B.alCheckpoint(big(2), STREAM, h1, big(3), C3), [G1, G2]);
const GOV2 = sorted([A(G1), A(G2), A(G4)]);
const E2e = entry(B.alGovernanceUpdate(big(2), STREAM, h1, 2, GOV2), [G2, G3]);
const E3eBytes = B.alAuthorize(big(3), STREAM, B.keccak256(E2e.entry), A(S2), big(4), B.U64_MAX);
const E3eNew = entry(E3eBytes, [G1, G4]);
const E3eOld = entry(E3eBytes, [G1, G3]);
const ACKb = B.alAck(big(3), STREAM, B.keccak256(E2b.entry));
const ACKc = B.alAck(big(3), STREAM, B.keccak256(E2c.entry));
const ACKbAll = entry(ACKb, [G1, G2, G3]);
const ACKbTwo = entry(ACKb, [G1, G2]);
const ACKcAll = entry(ACKc, [G1, G2, G3]);
const CPcont = B.alCheckpoint(big(3), STREAM, B.keccak256(E2b.entry), big(1), C1);
const CPcontAll = entry(CPcont, [G1, G2, G3]);

function run(log: Found[], payloads: B.AnchoredPayload[]) {
  const al = B.buildAuthorizationLog(genesis, log);
  if (al.status !== "OK") return { al_status: al.status, head_log_seq: Number(al.head.logSeq) };
  const res = B.resolveCanonical(al.state, B.collectCandidates(al.state, genesis, payloads, T_TEST), genesis, T_TEST);
  const canonical: Record<string, { commitment: string; flags: string[] }> = {};
  for (const [s, r] of res) canonical[String(s)] = { commitment: r.commitment ? NAMES.get(hx(r.commitment))! : "UNRESOLVED", flags: r.flags };
  return { al_status: al.status, head_log_seq: Number(al.head.logSeq), canonical };
}
function short(r: ReturnType<typeof run>) {
  if (r.al_status !== "OK" || !r.canonical) return r.al_status;
  return Object.fromEntries(Object.entries(r.canonical).map(([s, v]) => [s, v.commitment + (v.flags.length ? `[${v.flags.join(",")}]` : "")]));
}

// ---------------------------------------------------------------- tests
test("the vector file is the unmodified rc6 reference output", () => {
  assert.equal(createHash("sha256").update(raw).digest("hex"), VECTOR_SHA256);
  assert.equal(V.version, "1.0.0-rc6");
});

test("17.1 encoding and network constants", () => {
  const e = V.encoding;
  assert.equal(hx(B.keccak256(new Uint8Array(0))), e["keccak256('')"]);
  assert.equal(hx(B.keccak256(B.ascii("abc"))), e["keccak256('abc')"]);
  assert.equal(hx(B.id32("BYK.BTC.FUNDING.COMPOSITE")), e["id32('BYK.BTC.FUNDING.COMPOSITE')"]);
  assert.equal(hx(B.id32("BTC")), e["id32('BTC')"]);
  assert.equal(hx(B.i64(big(-48750))), e["int64(-48750)"]);
  assert.equal(hx(B.i64(big(6872))), e["int64(6872)"]);
  assert.equal(Number(B.truncDiv(big(-7), big(2))), e["trunc_div(-7,2)"]);
  assert.equal(Number(B.truncDiv(big(7), big(-2))), e["trunc_div(7,-2)"]);
  assert.equal(Number(B.truncDiv(big(-7), big(-2))), e["trunc_div(-7,-2)"]);
  for (const bad of ["", "BTC ", "B TC", "BT\nC", "BTÇ", "BT\x7f", "₿TC"]) assert.throws(() => B.id32(bad), B.BykError, JSON.stringify(bad)); // N19
  const n = V.network_constants;
  assert.equal(Number(B.BASE_MAINNET_CHAIN_ID), n.base_mainnet_chain_id);
  assert.equal(Number(B.BASE_SEPOLIA_CHAIN_ID), n.base_sepolia_chain_id);
  assert.equal(hx(B.base58Decode(B.SOLANA_MAINNET_GENESIS_B58)), n.solana_mainnet_beta_genesis_hash_hex);
  assert.equal(hx(B.base58Decode(B.SOLANA_DEVNET_GENESIS_B58)), n.solana_devnet_genesis_hash_hex);
  assert.equal(B.base58Encode(B.fromHex(n.solana_mainnet_beta_genesis_hash_hex)), n.solana_mainnet_beta_genesis_hash_b58);
  assert.equal("0x" + B.BASE_EAS_ADDRESS_HEX, n.base_eas_address);
  assert.equal(B.base58Encode(Uint8Array.of(0, 0, 1)), "112");
  assert.deepEqual([...B.base58Decode("112")], [0, 0, 1]);
  assert.throws(() => B.i64(B.I64_MAX + big(1)), B.BykError);
  assert.throws(() => B.u64(B.U64_MAX + big(1)), B.BykError);
  assert.throws(() => B.u16(65536), B.BykError);
});

test("17.2 genesis core, stream_id and witness keys", () => {
  const g = V.genesis_core;
  assert.equal(hx(core), g.genesis_core_hex);
  assert.equal(core.length, g.genesis_core_length);
  assert.equal(hx(STREAM), g.stream_id);
  assert.deepEqual(GOV.map((a) => "0x" + hx(a)), g.governance_sorted);
  assert.equal(genesis.threshold, g.threshold);
  assert.equal(Number(genesis.genesisEpochStartMs), g.genesis_epoch_start_ms);
  assert.equal(Number(genesis.baseChainId), g.base_chain_id);
  assert.equal(hx(genesis.streamNameId), hx(B.id32(g.stream_name)));
  const wk = (kind: B.WitnessKind, n: number) => {
    const k = B.witnessKey(STREAM, kind, big(n));
    return { key_hex: hx(k), solana_address_b58: B.base58Encode(k), base_recipient: "0x" + hx(k.subarray(12)) };
  };
  assert.deepEqual({ data_sequence_0: wk(1, 0), data_sequence_1: wk(1, 1), al_log_seq_1: wk(2, 1), genesis: wk(3, 0) }, V.witness_keys);
});

test("17.2 negative: genesis core reserved bytes, length, governance bounds and order (N3, N4, N23)", () => {
  for (const at of [7, 108, 111]) {
    const b = core.slice();
    b[at] = 1;
    assert.throws(() => B.parseGenesisCore(b), B.BykError, `reserved byte ${at}`);
  }
  assert.throws(() => B.parseGenesisCore(B.concat(core, Uint8Array.of(0))), B.BykError);
  assert.throws(() => B.parseGenesisCore(core.subarray(0, core.length - 1)), B.BykError);
  const unaligned = core.slice();
  unaligned[15] = unaligned[15]! ^ 1;
  assert.throws(() => B.parseGenesisCore(unaligned), B.BykError);
  const bounds: Record<string, string> = {};
  const all4 = sorted([A(G1), A(G2), A(G3), A(G4)]);
  for (const [label, thr, members] of [["2-of-2", 2, sorted([A(G1), A(G2)])], ["3-of-4", 3, all4], ["2-of-3", 2, GOV], ["1-of-1", 1, [A(G1)]], ["2-of-4", 2, all4]] as Array<[string, number, Uint8Array[]]>) {
    try {
      B.encodeGenesisCore({ threshold: thr, governance: members, genesisEpochStartMs: T0, streamName: "BYK.DATALAYER.TESTVECTORS", baseChainId: B.BASE_SEPOLIA_CHAIN_ID, solanaGenesisHash: new Uint8Array(32), baseEasAddress: new Uint8Array(20) });
      bounds[label] = "valid";
    } catch (err) {
      assert.ok(err instanceof B.BykError);
      bounds[label] = "invalid";
    }
  }
  assert.deepEqual(bounds, V.resolution.governance_bounds);
  assert.throws(() => B.checkGovernance(2, [GOV[1]!, GOV[0]!, GOV[2]!]), B.BykError);
  assert.throws(() => B.checkGovernance(2, [GOV[0]!, GOV[0]!, GOV[2]!]), B.BykError);
  assert.throws(() => B.checkGovernance(0, [GOV[0]!]), B.BykError);
});

test("17.3 epoch 1 records and Merkle tree: Class A leaves recomputed from their snapshots", () => {
  const ev = V.epoch1;
  assert.equal(epoch1.recs.length, ev.leaves.length);
  epoch1.recs.forEach((r, i) => {
    const want = ev.leaves[i];
    assert.equal(r.feed, want.feed);
    assert.equal(r.asset, want.asset);
    assert.equal(hx(r.leaf), want.leaf_hex);
    assert.equal(hx(B.leafHash(r.leaf)), want.leaf_hash);
    const p = B.auditPath(i, epoch1.leaves);
    assert.deepEqual(p.map(hx), want.audit_path);
    assert.ok(B.verifyInclusion(i, epoch1.leaves.length, B.leafHash(r.leaf), p, root1));
    assert.deepEqual(norm(B.parseLeaf(r.leaf)), norm(B.parseLeaf(B.fromHex(want.leaf_hex))));
  });
  assert.equal(hx(B.nodeHash(B.leafHash(epoch1.leaves[0]!), B.leafHash(epoch1.leaves[1]!))), ev.internal_node_0_1);
  assert.equal(hx(root1), ev.merkle_root);
  assert.deepEqual(B.sortLeaves([...epoch1.leaves].reverse()).map(hx), epoch1.leaves.map(hx));
  assert.throws(() => B.sortLeaves([epoch1.leaves[0]!, epoch1.leaves[0]!]), B.BykError);
});

test("17.3 negative: any flipped leaf bit breaks inclusion (N2); tree size must be record_count (N12); leaf rules (N5)", () => {
  const leaves = epoch1.leaves;
  const p = B.auditPath(1, leaves);
  for (let bit = 0; bit < 104 * 8; bit += 37) {
    const t = leaves[1]!.slice();
    t[bit >> 3] = t[bit >> 3]! ^ (1 << (bit & 7));
    assert.equal(B.verifyInclusion(1, leaves.length, B.leafHash(t), p, root1), false, `bit ${bit}`);
  }
  assert.equal(B.verifyInclusion(1, leaves.length, B.leafHash(leaves[1]!), p.slice(0, -1), root1), false);
  assert.equal(B.verifyInclusion(leaves.length, leaves.length, B.leafHash(leaves[1]!), p, root1), false);
  const five = [0, 1, 2, 3, 4].map((i) => B.concat(Uint8Array.of(1, 0, 0, 0), new Uint8Array(100).fill(i)));
  assert.equal(B.verifyInclusion(0, 6, B.leafHash(five[0]!), B.auditPath(0, five), B.merkleRoot(five)), V.tree_size_finding.verifies);
  for (let size = 1; size <= 9; size++) {
    const ls = Array.from({ length: size }, (_, i) => B.concat(Uint8Array.of(1, 0, 0, 0), new Uint8Array(100).fill(i + 1)));
    const root = B.merkleRoot(ls);
    ls.forEach((l, i) => assert.ok(B.verifyInclusion(i, size, B.leafHash(l), B.auditPath(i, ls), root), `size ${size} index ${i}`));
  }
  assert.equal(hx(B.merkleRoot([])), hx(EMPTY));
  const ok = B.parseLeaf(leaves[0]!);
  assert.throws(() => B.encodeLeaf({ ...ok, status: 2, value: big(1), dispersion: big(0) }), B.BykError);
  assert.throws(() => B.encodeLeaf({ ...ok, status: 3, value: big(0), dispersion: big(1) }), B.BykError);
  assert.throws(() => B.encodeLeaf({ ...ok, status: 4 }), B.BykError);
  assert.throws(() => B.encodeLeaf({ ...ok, dispersion: big(-1) }), B.BykError);
  assert.throws(() => B.encodeLeaf({ ...ok, coverageBps: 10001 }), B.BykError);
  for (const at of [0, 3]) {
    const t = leaves[0]!.slice();
    t[at] = 9;
    assert.throws(() => B.validateLeaf(t), B.BykError);
  }
  assert.throws(() => B.validateLeaf(leaves[0]!.subarray(0, 103)), B.BykError);
});

test("17.4 manifests, commitments and deterministic canonical signatures", () => {
  assert.equal(hx(M0), V.genesis_manifest.manifest_hex);
  assert.equal(hx(C0), V.genesis_manifest.commitment);
  assert.equal(hx(sigM0), V.genesis_manifest.signature_S1);
  const ev = V.epoch1;
  assert.equal(hx(M1), ev.manifest_hex);
  assert.equal(hx(C1), ev.commitment);
  assert.equal(hx(B.commitmentOf(M1)), ev.commitment);
  assert.equal(hx(sigM1), ev.signature_S1);
  assert.equal(hx(sigM1.subarray(0, 32)), ev.signature_r);
  assert.equal(hx(sigM1.subarray(32, 64)), ev.signature_s);
  assert.equal(sigM1[64], ev.recovery_id);
  assert.equal(sigM1[64]! + 27, ev.evm_v);
  assert.equal("0x" + hx(B.recoverAddress(C1, sigM1)), ev.signer_S1);
  assert.equal(hx(B.signDigest(S1, C1)), hx(sigM1), "signing twice gives the same bytes");
  assert.equal(hx(B.highSVariant(sigM1)), ev.high_s_variant_must_be_rejected);
  assert.throws(() => B.recoverAddress(C1, B.fromHex(ev.high_s_variant_must_be_rejected)), B.BykError); // N1
  const badV = sigM1.slice();
  badV[64] = 27;
  assert.throws(() => B.recoverAddress(C1, badV), B.BykError);
  assert.throws(() => B.recoverAddress(C1, sigM1.subarray(0, 64)), B.BykError);
  // 65 bytes of 0x01 are canonical in FORM (low s, recovery id 1): they either fail to recover or recover to
  // an address nobody authorized. Validity always comes from the authorization log, never from the form.
  let garbageSigner = "";
  try {
    garbageSigner = hx(B.recoverAddress(C1, GARBAGE_SIG));
  } catch (err) {
    assert.ok(err instanceof B.BykError);
  }
  assert.notEqual(garbageSigner, hx(A(S1)));
  const zeroR = sigM1.slice();
  zeroR.fill(0, 0, 32);
  assert.throws(() => B.recoverAddress(C1, zeroR), B.BykError);
  assert.notEqual(hx(B.recoverAddress(M1.subarray(0, 32), sigM1)), hx(A(S1)), "a signature over the commitment does not verify over other bytes (N11)");
  const m = B.parseManifest(M1);
  assert.equal(m.recordCount, 4);
  assert.equal(m.sequence, big(1));
  assert.equal(hx(m.previousCommitment), hx(C0));
});

test("17.4 negative: manifest structure (N3, N4, N6) and the stream sequence rule (N22)", () => {
  for (const at of [6, 7, 36, 39]) {
    const b = M1.slice();
    b[at] = 1;
    assert.throws(() => B.parseManifest(b), B.BykError, `reserved byte ${at}`);
  }
  assert.throws(() => B.parseManifest(B.concat(M1, Uint8Array.of(0))), B.BykError);
  assert.throws(() => B.parseManifest(M1.subarray(0, 199)), B.BykError);
  const base = B.parseManifest(M1);
  assert.throws(() => B.encodeManifest({ ...base, status: 3 }), B.BykError, "NO_DATA with records");
  assert.throws(() => B.encodeManifest({ ...base, status: 0, recordCount: 0, merkleRoot: EMPTY }), B.BykError, "OK without records");
  assert.throws(() => B.encodeManifest({ ...base, status: 2 }), B.BykError);
  assert.throws(() => B.encodeManifest({ ...base, epochEndMs: base.epochEndMs + E }), B.BykError, "OK window longer than one epoch");
  assert.throws(() => B.encodeManifest({ ...base, epochStartMs: base.epochStartMs + big(1) }), B.BykError);
  assert.throws(() => B.encodeManifest({ ...B.parseManifest(M0), merkleRoot: root1 }), B.BykError, "empty tree root");
  assert.throws(() => B.encodeManifest({ ...B.parseManifest(M0), previousCommitment: C1 }), B.BykError, "genesis previous commitment");
  assert.throws(() => B.validateManifestInStream(B.parseManifest(Mmax), genesis), B.BykError);
  B.validateManifestInStream(B.parseManifest(Mfar), genesis); // structurally valid, excluded only by T
  assert.throws(() => B.validateManifestInStream({ ...B.parseManifest(M0), streamId: C1 }, genesis), B.BykError);
  assert.equal(B.maxSequence(genesis, T_TEST), big(V.resolution.S_max_at_T_TEST));
  assert.equal(B.maxSequence(genesis, T0 + E - big(1)), big(-1));
  assert.equal(B.maxSequence(genesis, T0 + E), big(0));
});

test("17.5 authorization log entries and bundles", () => {
  const a = V.authorization_log;
  const pairs: Array<[Found | Uint8Array, string, string?]> = [
    [E1, "E1_authorize_S1_hex", "E1_bundle_G1_G2"], [E2b, "E2b_checkpoint_seq2_C2a_hex", "E2b_bundle"], [E2c, "E2c_checkpoint_seq2_C2b_hex", "E2c_bundle"],
    [E2d, "E2d_revoke_S1_from_seq2_hex", "E2d_bundle"], [E3d, "E3d_authorize_S2_from_seq2_hex", "E3d_bundle"], [E2bad, "E2bad_checkpoint_seq2_C2bad_hex", "E2bad_bundle"],
    [E2restart, "E2restart_checkpoint_seq3_C3_hex", "E2restart_bundle"], [E2e, "E2e_governance_update_hex", "E2e_bundle_old_set_G2_G3"],
    [E3eNew, "E3e_authorize_S2_from_seq4_hex", "E3e_bundle_new_set_G1_G4"], [E3eOld, "E3e_authorize_S2_from_seq4_hex", "E3e_bundle_removed_member_G1_G3_must_fail"],
    [ACKbAll, "ACK3_on_E2b_hex", "ACK3_on_E2b_bundle_G1_G2_G3"], [ACKbTwo, "ACK3_on_E2b_hex", "ACK3_on_E2b_bundle_G1_G2_only"], [ACKcAll, "ACK3_on_E2c_hex", "ACK3_on_E2c_bundle_G1_G2_G3"],
    [CPcontAll, "CHECKPOINT3_on_E2b_non_ack_continuation_hex", "CHECKPOINT3_on_E2b_bundle_G1_G2_G3"],
  ];
  for (const [f, entryKey, bundleKey] of pairs) {
    const found = f as Found;
    assert.equal(hx(found.entry), a[entryKey], entryKey);
    assert.equal(hx(found.bundle), a[bundleKey!], bundleKey);
  }
  assert.equal(hx(h1), a.E1_hash);
  assert.deepEqual(GOV2.map((x) => "0x" + hx(x)), a.new_governance_sorted);
  assert.equal("0x" + hx(A(S2)), a.S2);
  const parsed = B.parseAlEntry(E1.entry);
  assert.ok(parsed.entryType === 1 && hx(parsed.signer) === hx(A(S1)) && parsed.validFrom === big(0) && parsed.validUntil === B.U64_MAX);
  // signatures collected one by one (each member on their own machine) join into the same bundle
  const d = B.keccak256(E1.entry);
  assert.equal(hx(B.joinBundle(d, [B.signDigest(G1, d), B.signDigest(G2, d)])), hx(E1.bundle));
  assert.equal(hx(B.joinBundle(d, [B.signDigest(G2, d), B.signDigest(G1, d)])), hx(E1.bundle));

  const ok = B.buildAuthorizationLog(genesis, [E1, E2e, E3eNew]);
  const bad = B.buildAuthorizationLog(genesis, [E1, E2e, E3eOld]);
  assert.deepEqual({ "log[E1,E2e,E3e(new set G1,G4)]": Number(ok.head.logSeq), "log[E1,E2e,E3e(G1,G3)]": Number(bad.head.logSeq) }, a.expected_heads_governance_update);
  assert.equal(ok.status, "OK");
  assert.equal(bad.status, "OK");
  const revoked = B.buildAuthorizationLog(genesis, [E1, E2d, E3d]).state;
  assert.ok(B.authorized(revoked, A(S1), big(1)) && !B.authorized(revoked, A(S1), big(2)) && B.authorized(revoked, A(S2), big(2)));
  assert.equal(B.authorized(revoked, A(G1), big(0)), false);
});

test("17.5 negative: entry structure (N3, N4) and bundles (N7)", () => {
  const e = E1.entry;
  for (const at of [100, 103]) { // AUTHORIZE reserved bytes 20..24 of the body
    const b = e.slice();
    b[at] = 1;
    assert.throws(() => B.parseAlEntry(b), B.BykError);
  }
  assert.throws(() => B.parseAlEntry(B.concat(e, Uint8Array.of(0))), B.BykError);
  const ackWithBody = B.concat(ACKb, Uint8Array.of(0));
  ackWithBody[7] = 1; // body_len says 1: still not a valid ACK
  assert.throws(() => B.parseAlEntry(ackWithBody), B.BykError);
  const unknown = e.slice();
  unknown[5] = 9;
  assert.throws(() => B.parseAlEntry(unknown), B.BykError);
  const gu = E2e.entry.slice();
  gu[82] = 1; // GOVERNANCE_UPDATE reserved
  assert.throws(() => B.parseAlEntry(gu), B.BykError);
  const shortGu = B.concat(E2e.entry.subarray(0, 81));
  shortGu[7] = 1;
  assert.throws(() => B.parseAlEntry(shortGu), B.BykError, "a body shorter than its fixed part is a structure error, not a crash");

  const d = B.keccak256(e);
  const s1 = B.signDigest(G1, d);
  const s2 = B.signDigest(G2, d);
  const s4 = B.signDigest(G4, d);
  const asc = hx(B.joinBundle(d, [s1, s2]));
  const [lo, hi] = asc.startsWith(hx(s1)) ? [s1, s2] : [s2, s1];
  assert.equal(B.verifyBundle(d, B.concat(lo, hi), GOV, 2), true);
  assert.equal(B.verifyBundle(d, B.concat(hi, lo), GOV, 2), false, "unsorted");
  assert.equal(B.verifyBundle(d, B.concat(lo, lo), GOV, 2), false, "duplicated");
  assert.equal(B.verifyBundle(d, lo, GOV, 2), false, "below threshold");
  assert.equal(B.verifyBundle(d, B.joinBundle(d, [s1, s4]), GOV, 2), false, "non-member");
  assert.equal(B.verifyBundle(d, new Uint8Array(0), GOV, 1), false);
  assert.equal(B.verifyBundle(d, lo.subarray(0, 64), GOV, 1), false);
  assert.equal(B.verifyBundle(d, B.concat(lo, B.highSVariant(hi)), GOV, 2), false, "high-S member signature");
  // an entry of another stream and an unparseable entry are ignored, not fatal
  const other = entry(B.alAuthorize(big(1), C1, B.ZERO32, A(S2), big(0), B.U64_MAX), [G1, G2]);
  const al = B.buildAuthorizationLog(genesis, [other, { entry: Uint8Array.of(1, 2, 3), bundle: new Uint8Array(0) }, E1]);
  assert.equal(al.status, "OK");
  assert.equal(al.head.logSeq, big(1));
  assert.equal(B.authorized(al.state, A(S2), big(0)), false);
});

test("17.7 canonical resolution: fork, checkpoint, revocation, governance fork and adversarial scenarios", () => {
  const S: Record<string, ReturnType<typeof run>> = {
    A_fork_no_action: run([E1], P_FORK),
    B_checkpoint_C2a: run([E1, E2b], P_FORK),
    C_checkpoint_C2b: run([E1, E2c], P_FORK),
    D_revoke_and_resign: run([E1, E2d, E3d], [...P_FORK, pay(M2a, sigS2.M2a), pay(M3, sigS2.M3)]),
    E0_orphan_does_not_block: run([E1], P_BADLINK),
    E1_checkpoint_non_linking: run([E1, E2bad], P_BADLINK),
    F_restart_after_unresolved: run([E1, E2restart], [...P_FORK, pay(M4, sig.M4), pay(M5, sig.M5)]),
    G1_governance_fork: run([E1, E2b, E2c], P_FORK),
    G2_fork_resolved_by_ack_3of3: run([E1, E2b, E2c, ACKbAll], P_FORK),
    G3_ack_below_fork_threshold: run([E1, E2b, E2c, ACKbTwo], P_FORK),
    G4_conflicting_acks: run([E1, E2b, E2c, ACKbAll, ACKcAll], P_FORK),
    G5_non_ack_continuation: run([E1, E2b, E2c, CPcontAll], P_FORK),
    G6_same_ack_two_bundles: run([E1, E2b, E2c, ACKbAll, ACKbTwo], P_FORK),
    H_signature_binding: run([E1], [P_BASE[0]!, pay(M1, GARBAGE_SIG), pay(M1x, sigM1)]),
    I_far_sequence_dos: run([E1], [...P_FORK, pay(Mfar, sig.M_far), pay(Mmax, sig.M_max)]),
  };
  assert.deepEqual(Object.keys(S), Object.keys(V.resolution.scenarios));
  for (const k of Object.keys(S)) assert.deepEqual(S[k], V.resolution.scenarios[k], k);
  assert.deepEqual(Object.fromEntries(Object.entries(S).map(([k, v]) => [k, short(v)])), V.resolution.summary);

  const r = V.resolution;
  assert.deepEqual({ M2a_hex: hx(M2a), C2a: hx(C2a), M2b_hex: hx(M2b), C2b: hx(C2b), M2bad_hex: hx(M2bad), C2bad: hx(C2bad), M3_hex: hx(M3), C3: hx(C3) }, r.manifests);
  assert.deepEqual({ M4_hex: hx(M4), C4: hx(C4), M5_hex: hx(M5), C5: hx(C5), M1x_hex: hx(M1x), C1x: hx(C1x), M_far_hex: hx(Mfar), M_max_hex: hx(Mmax) }, r.more_manifests);
  assert.deepEqual(norm(sig), r.signatures_S1);
  assert.deepEqual(norm(sigS2), r.signatures_S2);
  assert.equal(hx(GARBAGE_SIG), r.garbage_signature);
  assert.equal(Number(T_TEST), r.as_of_ms_T_TEST);

  // DoS bound (N22): far manifests are never candidates and the resolver range comes from T alone
  const al = B.buildAuthorizationLog(genesis, [E1]);
  const cands = B.collectCandidates(al.state, genesis, [...P_FORK, pay(Mfar, sig.M_far), pay(Mmax, sig.M_max)], T_TEST);
  assert.deepEqual([...cands.keys()].map(Number).sort(), [0, 1, 2, 3]);
  const res = B.resolveCanonical(al.state, cands, genesis, T_TEST);
  assert.equal(res.size, 6);
  assert.equal(B.resolveCanonical(al.state, cands, genesis, T_TEST, big(1)).size, 2);
  assert.equal(B.resolveCanonical(al.state, cands, genesis, T_TEST, FAR_SEQ).size, 6);
  // a manifest whose window ends after T is not a candidate yet
  assert.equal(B.collectCandidates(al.state, genesis, P_FORK, T0 + mul(2)).has(big(2)), false);
});

test("17.8 witness time", () => {
  const w = V.witness_time;
  const slots = new Map<number, number | null>(Object.entries<number | null>(w.solana_slot_times_sec).map(([k, v]) => [Number(k), v]));
  const blocks = new Map<number, number>(Object.entries<number>(w.base_block_timestamps_sec).map(([k, v]) => [Number(k), v]));
  assert.equal(B.solanaAsOfSlot(slots, 1_789_258_202_000), w["solana_as_of_slot(T=1789258202000)"]);
  assert.equal(B.solanaAsOfSlot(slots, 1_789_258_203_000), w["solana_as_of_slot(T=1789258203000)"]);
  assert.equal(B.baseAsOfBlock(blocks, 1_789_258_203_000), w["base_as_of_block(T=1789258203000)"]);
  for (const slot of [100, 101, 103]) {
    const r = B.solanaReportedTime(slots, slot);
    assert.deepEqual([r.timeMs, r.status], w[`solana_reported_time(${slot})`]);
  }
  assert.equal(B.solanaAsOfSlot(slots, 1), null);
  assert.equal(B.baseAsOfBlock(blocks, 1), null);
});

test("17.6 witness payloads: EAS schema UIDs, ABI encodings, memos and the Solana size model", () => {
  const w = V.witness_payloads;
  assert.equal(B.EAS_DATA_SCHEMA, w.eas_schema_data);
  assert.equal(B.EAS_AL_SCHEMA, w.eas_schema_al);
  assert.equal(B.EAS_GENESIS_SCHEMA, w.eas_schema_genesis);
  assert.equal(hx(B.easSchemaUid(B.EAS_DATA_SCHEMA)), w.eas_schema_uid_data);
  assert.equal(hx(B.easSchemaUid(B.EAS_AL_SCHEMA)), w.eas_schema_uid_al);
  assert.equal(hx(B.easSchemaUid(B.EAS_GENESIS_SCHEMA)), w.eas_schema_uid_genesis);
  assert.equal("0x" + hx(B.witnessKey(STREAM, 1, big(1)).subarray(12)), w.eas_data_epoch1_recipient);
  assert.equal(hx(B.abiU64B32BytesBytes(big(1), C1, M1, sigM1)), w.eas_data_epoch1_abi);
  assert.equal(hx(B.abiU64B32BytesBytes(big(1), h1, E1.entry, E1.bundle)), w.eas_al_E1_abi);
  assert.equal(hx(B.abiB32Bytes(STREAM, core)), w.eas_genesis_abi);
  assert.equal(B.memoData(M1, sigM1), w.memo_data_epoch1);
  assert.equal(B.memoAl(E1.entry, E1.bundle), w.memo_al_E1);
  assert.equal(B.memoGenesis(core), w.memo_genesis);
  assert.deepEqual({
    memo_data: B.memoData(M1, sigM1).length, memo_al_E1: B.memoAl(E1.entry, E1.bundle).length, memo_genesis_test: B.memoGenesis(core).length,
    memo_al_max: B.MAX_AL_MEMO_BYTES, memo_genesis_max: B.MAX_GENESIS_MEMO_BYTES, solana_tx_overhead_model: B.SOLANA_TX_OVERHEAD, max_memo_bytes: B.MAX_MEMO_BYTES,
  }, w.sizes);
  assert.ok(B.MAX_AL_MEMO_BYTES <= B.MAX_MEMO_BYTES && B.MAX_GENESIS_MEMO_BYTES <= B.MAX_MEMO_BYTES);
});

test("12.6 admissibility: memos and EAS data parse strictly, belong under their witness key, reject variants (N14, N15)", () => {
  const w = V.witness_payloads;
  const data = B.parseMemo(w.memo_data_epoch1)!;
  assert.ok(data.kind === "data" && hx(data.manifest) === hx(M1) && hx(data.signature) === hx(sigM1));
  const al = B.parseMemo(w.memo_al_E1)!;
  assert.ok(al.kind === "al" && hx(al.entry) === hx(E1.entry) && hx(al.bundle) === hx(E1.bundle));
  const gen = B.parseMemo(w.memo_genesis)!;
  assert.ok(gen.kind === "genesis" && hx(gen.core) === hx(core));
  for (const p of [data, al, gen]) assert.equal(B.memoOf(p), p.kind === "data" ? w.memo_data_epoch1 : p.kind === "al" ? w.memo_al_E1 : w.memo_genesis);
  assert.equal(hx(B.witnessKeyOf(data, STREAM)!), V.witness_keys.data_sequence_1.key_hex);
  assert.equal(hx(B.witnessKeyOf(al, STREAM)!), V.witness_keys.al_log_seq_1.key_hex);
  assert.equal(hx(B.witnessKeyOf(gen, STREAM)!), V.witness_keys.genesis.key_hex);
  assert.equal(B.witnessKeyOf(data, C1), null, "a payload of another stream has no place under our keys");
  assert.equal(B.witnessKeyOf(gen, C1), null);
  const memo: string = w.memo_data_epoch1;
  for (const bad of [memo + " ", " " + memo, memo.replace("BYK1 ", "BYK1  "), memo.toUpperCase(), memo.replace("BYK1", "BYK2"), memo.slice(0, -2), memo + "00", memo.replace(" ", "\t"), "BYK1 0x" + memo.slice(5), memo + "\n", "", "BYKG1 00"]) {
    assert.equal(B.parseMemo(bad), null, JSON.stringify(bad.slice(0, 24)));
  }
  const reserved = M1.slice();
  reserved[6] = 1;
  assert.equal(B.parseMemo(B.memoData(reserved, sigM1)), null, "the payload must parse exactly");

  const easData = B.fromHex(w.eas_data_epoch1_abi);
  const d2 = B.parseEasData(B.EAS_DATA_SCHEMA, easData)!;
  assert.ok(d2.kind === "data" && hx(d2.manifest) === hx(M1) && hx(d2.signature) === hx(sigM1));
  const a2 = B.parseEasData(B.EAS_AL_SCHEMA, B.fromHex(w.eas_al_E1_abi))!;
  assert.ok(a2.kind === "al" && hx(a2.entry) === hx(E1.entry));
  const g2 = B.parseEasData(B.EAS_GENESIS_SCHEMA, B.fromHex(w.eas_genesis_abi))!;
  assert.ok(g2.kind === "genesis" && hx(g2.core) === hx(core));
  assert.equal(hx(B.easDataOf(d2).data), w.eas_data_epoch1_abi);
  const wrongSeq = easData.slice();
  wrongSeq[31] = 2; // outer sequence 2, inner manifest sequence 1
  assert.equal(B.parseEasData(B.EAS_DATA_SCHEMA, wrongSeq), null);
  const wrongHash = easData.slice();
  wrongHash[40] = wrongHash[40]! ^ 1;
  assert.equal(B.parseEasData(B.EAS_DATA_SCHEMA, wrongHash), null);
  assert.equal(B.parseEasData(B.EAS_DATA_SCHEMA, B.concat(easData, new Uint8Array(32))), null, "trailing bytes are not canonical ABI");
  const dirtyPadding = easData.slice();
  dirtyPadding[dirtyPadding.length - 1] = 1;
  assert.equal(B.parseEasData(B.EAS_DATA_SCHEMA, dirtyPadding), null);
  assert.equal(B.parseEasData(B.EAS_AL_SCHEMA, easData), null, "data under the wrong schema");
  assert.equal(B.parseEasData("uint256 x", easData), null);
  assert.equal(B.parseEasData(B.EAS_DATA_SCHEMA, easData.subarray(0, 100)), null);
});

test("17.9 Level 3 audit: AUD1 to AUD10", () => {
  const A2 = manifest(3, big(2), T0 + mul(2), T0 + mul(4), 0, EMPTY, C1); // a gap manifest spanning two windows
  const CA2 = B.keccak256(A2);
  const T3 = T0 + mul(5);
  const epoch3 = (drop?: string, mutate?: Record<string, Mutation>) => {
    const r = epochRecords(T3, 3, drop, mutate);
    const mb = manifest(r.status, big(3), T0 + mul(4), T3, r.leaves.length, B.merkleRoot(r.leaves), CA2);
    return { manifest: mb, commitment: B.keccak256(mb), leaves: r.leaves };
  };
  const A3 = epoch3();
  const variants: Record<string, ReturnType<typeof epoch3>> = {
    A3bad_missing_catalog_leaf: epoch3("BYK.BTC.VPIN"),
    A3_tampered_value: epoch3(undefined, { "BYK.BTC.FUNDING.COMPOSITE": { value: 118867 } }),
    A3_tampered_source_count: epoch3(undefined, { "BYK.BTC.FUNDING.COMPOSITE": { sourceCount: 6 } }),
    A3_no_data_despite_inputs: epoch3(undefined, { "BYK.BTC.FUNDING.COMPOSITE": { status: 3, value: 0, dispersion: 0, sourceCount: 0, coverageBps: 0, outlierCount: 0, maxSourceAgeMs: 0 } }),
    A3_insufficient_wrong_quality: epoch3(undefined, { "BYK.ETH.FUNDING.COMPOSITE": { coverageBps: 9999, sourceCount: 4 } }),
  };
  const av = V.audit;
  assert.deepEqual({ A2_gap_hex: hx(A2), CA2: hx(CA2), A3_hex: hx(A3.manifest), CA3: hx(A3.commitment) }, av.manifests);
  assert.deepEqual(A3.leaves.map(hx), av.leaves_A3);
  assert.deepEqual({ A2: hx(B.signDigest(S1, CA2)), A3: hx(B.signDigest(S1, A3.commitment)) }, av.signatures_S1);
  for (const [k, v] of Object.entries(variants)) {
    assert.deepEqual({ manifest_hex: hx(v.manifest), commitment: hx(v.commitment), leaves: v.leaves.map(hx), signature_S1: hx(B.signDigest(S1, v.commitment)) }, av.variants[k], k);
  }

  const T_AUD = T0 + mul(5) + big(60_000);
  assert.equal(Number(T_AUD), av.as_of_ms);
  const al = B.buildAuthorizationLog(genesis, [E1]);
  const manifests = new Map<string, Uint8Array>([[hx(C0), M0], [hx(C1), M1], [hx(CA2), A2], [hx(A3.commitment), A3.manifest]]);
  const leaves = new Map<string, Uint8Array[]>([[hx(C1), epoch1.leaves], [hx(A3.commitment), A3.leaves]]);
  for (const v of Object.values(variants)) {
    manifests.set(hx(v.commitment), v.manifest);
    leaves.set(hx(v.commitment), v.leaves);
  }
  const audit = (e3: ReturnType<typeof epoch3>, from: number, to: number, snaps = snapshots, params = PRM) => {
    const payloads = [pay(M0, sigM0), pay(M1, sigM1), pay(A2, B.signDigest(S1, CA2)), pay(e3.manifest, B.signDigest(S1, e3.commitment))];
    const resolution = B.resolveCanonical(al.state, B.collectCandidates(al.state, genesis, payloads, T_AUD), genesis, T_AUD);
    return B.auditRange({ genesis, resolution, manifests, leaves, catalog, from: big(from), to: big(to), snapshots: snaps, methodologyParams: params });
  };
  const missingSol = new Map([...snapshots].filter(([k]) => k !== "3|BYK.SOL.FUNDING.COMPOSITE|SOL"));
  const results: Record<string, B.AuditResult> = {
    "AUD1_normal_gap_normal_[0,3]": audit(A3, 0, 3),
    "AUD2_catalog_leaf_missing_[0,3]": audit(variants.A3bad_missing_catalog_leaf!, 0, 3),
    "AUD3_range_includes_unresolved_[0,4]": audit(A3, 0, 4),
    "AUD4_range_starts_after_gap_[3,3]": audit(A3, 3, 3),
    "AUD5_class_a_value_tampered_[0,3]": audit(variants.A3_tampered_value!, 0, 3),
    "AUD6_class_a_source_count_tampered_[0,3]": audit(variants.A3_tampered_source_count!, 0, 3),
    "AUD7_no_data_despite_sufficient_inputs_[0,3]": audit(variants.A3_no_data_despite_inputs!, 0, 3),
    "AUD8_insufficient_with_wrong_quality_[0,3]": audit(variants.A3_insufficient_wrong_quality!, 0, 3),
    "AUD9_class_a_snapshot_missing_[0,3]": audit(A3, 0, 3, missingSol),
    "AUD10_parameters_differ_from_methodology_[0,3]": audit(A3, 0, 3, snapshots, { ...PRM, outlier_k: 6 }),
  };
  assert.deepEqual(results, av.results);
  // every Class A status is covered by the fixtures: DEGRADED (BTC), INSUFFICIENT_COVERAGE (ETH), negative DEGRADED (SOL)
  const byFeed = Object.fromEntries(epochRecords(T3, 3).recs.map((r) => [r.feed, B.parseLeaf(r.leaf)]));
  assert.equal(B.STATUS_NAME[byFeed["BYK.ETH.FUNDING.COMPOSITE"]!.status], "INSUFFICIENT_COVERAGE");
  assert.ok(byFeed["BYK.SOL.FUNDING.COMPOSITE"]!.value < big(0));
});

test("Annex A worked examples, lexemes, units, parameters and exactness", () => {
  const an = V.annex_a;
  const T = big(an.T);
  assert.equal(T, e1End);
  const VENUES: B.FundingVenueInput[] = an.venues_input;
  const KEEP = ["value", "dispersion", "source_count", "expected_source_count", "coverage_bps", "outlier_count", "max_source_age_ms", "status", "median", "mad", "tau", "capped_count", "cap_weight", "max_weight_share_bps", "weights"];
  const summarize = (r: ReturnType<typeof B.fundingComposite>) => ({
    leaf: norm(Object.fromEntries(KEEP.filter((k) => (r.leaf as Record<string, unknown>)[k] !== undefined).map((k) => [k, (r.leaf as Record<string, unknown>)[k]]))),
    venues: r.details.map((d) => norm({ ...d, vid: undefined })),
  });
  const encodable = (leaf: B.FundingLeaf) => B.encodeLeaf({
    status: B.STATUS[leaf.status], decimals: 10, feedId: B.id32("BYK.TEST.FUNDING.COMPOSITE"), assetId: B.id32("TEST"), observedAtMs: T, value: leaf.value,
    sourceCount: leaf.source_count, expectedSourceCount: leaf.expected_source_count, coverageBps: leaf.coverage_bps, outlierCount: leaf.outlier_count, maxSourceAgeMs: leaf.max_source_age_ms, dispersion: leaf.dispersion,
  }).length === B.LEAF_LEN;

  const main = B.fundingComposite(VENUES, PRM, T);
  assert.deepEqual(summarize(main), an.example_main);
  assert.ok(encodable(main.leaf));

  const late = B.fundingComposite(VENUES, PRM, T + big(2 * 24 * 3_600_000));
  assert.deepEqual({ T: Number(T) + 2 * 24 * 3_600_000, ...summarize(late) }, an.example_no_data);
  assert.ok(encodable(late.leaf));

  const insufficientVenues: B.FundingVenueInput[] = snapshots.get("1|BYK.ETH.FUNDING.COMPOSITE|ETH")!.venues;
  const insufficient = B.fundingComposite(insufficientVenues, PRM, T);
  assert.deepEqual({ T: Number(T), note: an.example_insufficient_coverage.note, ...summarize(insufficient) }, an.example_insufficient_coverage);
  assert.ok(encodable(insufficient.leaf));

  const qv = (venue: string, rate: string, oi: string): B.FundingVenueInput => ({
    venue, rate, rate_unit: "FRACTION", interval: "1", interval_unit: "h", settlement_ts: String(T - big(1000)), settlement_ts_unit: "ms", oi_unit: "QUOTE", oi_value: oi,
    contract_size: null, mark_price: null, oi_ts: String(T - big(1000)), oi_ts_unit: "ms", price_ts: null, price_ts_unit: null,
  });
  const overflow = B.fundingComposite([qv("p1", "900000000", "3500"), qv("p2", "900000000", "3500"), qv("n1", "-900000000", "1000"), qv("n2", "-900000000", "1000"), qv("n3", "-900000000", "1000")], PRM, T);
  assert.deepEqual(summarize(overflow), an.example_rc4_overflow_inputs); // N25
  assert.equal(overflow.leaf.status, "NO_DATA");
  assert.ok(encodable(overflow.leaf));

  const HM = "461168601.8427387903"; // units = 2^62 - 1 at a 1 h interval
  const EXT = [qv("p1", HM, "3500"), qv("p2", HM, "3500"), qv("n1", "-" + HM, "1000"), qv("n2", "-" + HM, "1000"), qv("n3", "-" + HM, "1000")];
  const extreme = B.fundingComposite(EXT, PRM, T);
  assert.deepEqual(summarize(extreme), an.example_extreme_hourly_bound);
  assert.ok(extreme.details.every((d) => B.absBig(d.hourly!) === B.HOURLY_MAX));
  assert.ok(extreme.leaf.dispersion <= B.I64_MAX && encodable(extreme.leaf));
  const over = B.fundingComposite([qv("p1", "461168601.8427387904", "3500"), ...EXT.slice(1)], PRM, T);
  assert.match(over.details[0]!.rate_error!, /hourly outside/);

  const PRM_EQ = { ...PRM, min_contributors: 2, max_weight_bps: 5000, min_source_ratio_bps: 0, coverage_ok_bps: 0 };
  const eq = B.fundingComposite([qv("big", "0.0000001", "3000"), qv("small", "0.0000002", "1000")], PRM_EQ, T);
  assert.deepEqual({ parameters: PRM_EQ, ...summarize(eq) }, an.example_cap_equality);
  assert.throws(() => B.validateParams({ ...PRM, min_contributors: 2 }, 7), B.BykError); // N28

  const paramCases: Record<string, string> = {};
  const cases: Array<[string, Record<string, unknown>]> = [
    ["proposed defaults", {}], ["outlier_k = 10^100", { outlier_k: big(10) ** big(100) }], ["outlier_k = 1000", { outlier_k: 1000 }], ["stale_factor = 1001", { stale_factor: 1001 }],
    ["outlier_floor = 2^62", { outlier_floor: big(2) ** big(62) }], ["oi_max_age_ms = 604800001", { oi_max_age_ms: 604_800_001 }], ["min_contributors = 65536", { min_contributors: 65536 }],
    ["outlier_k = true (bool)", { outlier_k: true }], ["extra key", { extra: 1 }],
  ];
  for (const [label, change] of cases) {
    try {
      B.validateParams({ ...PRM, ...change }, 7);
      paramCases[label] = "valid";
    } catch (err) {
      assert.ok(err instanceof B.BykError);
      paramCases[label] = "invalid";
    }
  }
  assert.deepEqual(paramCases, an.parameter_cases); // N30
  const missingKey: Record<string, unknown> = { ...PRM };
  delete missingKey.outlier_k;
  assert.throws(() => B.validateParams(missingKey, 7), B.BykError);
  assert.throws(() => B.validateParams({ ...PRM, outlier_k: 1.5 }, 7), B.BykError);
  assert.throws(() => B.validateParams({ ...PRM, outlier_k: "5" }, 7), B.BykError);
  assert.throws(() => B.validateParams(PRM, 0), B.BykError);

  const lex: Record<string, string> = {};
  const lexCases: Array<[string, boolean]> = [["100000", false], ["0.001", false], ["2900000000.75", false], ["-0.0001", true], ["-0.0001", false], ["1e5", false], ["+1", true], [" 1", false], ["1,000", false], [".5", false], ["5.", false],
    ["1".repeat(25), false], ["0." + "1".repeat(19), false], ["0." + "1".repeat(18), false], ["12345678901234567.89", false]];
  for (const [l, signed] of lexCases) {
    let verdict = "valid";
    try {
      B.parseLexeme(l, signed);
    } catch (err) {
      assert.ok(err instanceof B.BykError);
      verdict = "invalid";
    }
    lex[`'${l}' signed=${signed ? "True" : "False"}`] = verdict;
  }
  assert.deepEqual(lex, an.lexemes); // N24
  for (const bad of ["100\n", "1 ", "١٢٣", "0x10", "", "-", "1.2.3", 5 as unknown as string]) assert.throws(() => B.parseLexeme(bad, true), B.BykError, JSON.stringify(bad));

  const ints: Record<string, unknown> = {};
  const intCases: Array<[string, string, "time" | "interval"]> = [["1789258140", "s", "time"], ["1789258140000", "ms", "time"], ["0001", "ms", "time"], ["12345678901234567890", "ms", "time"], ["-1", "ms", "time"], ["1.0", "s", "time"], ["1e3", "ms", "time"],
    ["9223372036854775", "s", "time"], ["9223372036854776", "s", "time"], ["1789258140", "us", "time"], ["8", "h", "interval"], ["0", "h", "interval"], ["25", "h", "interval"], ["59999", "ms", "interval"], ["86400", "s", "interval"], ["86401", "s", "interval"]];
  for (const [l, unit, scaleName] of intCases) {
    const k = `${l} ${unit} (${scaleName})`;
    try {
      const v = B.parseIntegerLexeme(l, unit, scaleName === "time" ? B.TIME_SCALE : B.INTERVAL_SCALE);
      ints[k] = scaleName === "interval" && (v < B.INTERVAL_MIN_MS || v > B.INTERVAL_MAX_MS) ? "invalid (interval outside [60000, 86400000] ms)" : norm(v);
    } catch (err) {
      assert.ok(err instanceof B.BykError);
      ints[k] = `invalid (${err.message})`;
    }
  }
  assert.deepEqual(ints, an.integer_lexemes); // N27
  assert.throws(() => B.parseIntegerLexeme("1", "toString", B.TIME_SCALE), B.BykError, "inherited property names are not units");

  const rateUnits = Object.fromEntries(([["0.0001", "FRACTION"], ["0.01", "PERCENT"], ["1", "BPS"], ["-0.0375", "PERCENT"]] as Array<[string, string]>).map(([l, u]) => [`${l} ${u}`, norm(B.truncRational(B.scaleRational(B.parseLexeme(l, true), B.RATE_SCALE[u]!)))]));
  assert.deepEqual(rateUnits, an.rate_units);
  const exact = B.truncRational(B.mulRational(B.parseLexeme("12345678901234567.89", false), B.parseLexeme("1.5", false)));
  assert.equal(exact.toString(), an.exactness["oi BASE 12345678901234567.89 x mark 1.5"]);
  assert.notEqual(exact.toString(), an.exactness["binary64 float result (non-conformant)"]);
});
