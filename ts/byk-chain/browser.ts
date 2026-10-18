/* BYK Data Layer · the chain reads of the in-browser check on /proof (2026-09-18, hardened after an adversarial
 * review the same day).
 *
 * The browser used to take the data signer's address from our page. Now it derives who may sign from the chains,
 * starting from the stream id BUILT INTO this module (a page, an API or a database row that names another stream is
 * refused, so a changed stream row cannot bring its own governance):
 *   1. the genesis core, found under its witness key through the public EAS index and READ from a Base node, must
 *      hash to that stream id; it names the governance keys (the owner's, generated off our servers);
 *   2. every authorization log entry the index lists, again read from Base, is checked against that governance
 *      exactly as the protocol's own buildAuthorizationLog does;
 *   3. the record's signer must be authorized for the record's sequence by that log;
 *   4. the manifest must belong to the stream and to a sequence time allows, match any governance checkpoint, and be
 *      anchored under its witness key no earlier than its window end (the earliest copy counts), with no authorized
 *      rival manifest for the same sequence among the anchors this browser can enumerate.
 * The only keyless browser Solana node (PublicNode) keeps about 46 hours and the public Solana endpoint refuses
 * browsers, so older anchors are read from Base, whose EAS contract keeps each attestation in state.
 *
 * The index is used to FIND attestations only. Anyone may attest with our schemas, so a witness key can be spammed:
 * every recipient is listed on its own, page by page, candidates are screened on the data the index returns, and
 * each survivor is re-read from a Base node and checked again. A listing that runs past its page budget makes the
 * answer "unavailable", never a shorter log or a missing genesis. What a browser still cannot prove is that the index
 * itself omitted nothing, or that no log entry sits on Solana alone; the one-file verifier (byk-verify.mjs)
 * enumerates both chains for that.
 *
 * Pure and fetch-injected, unit-tested against honest, tampered, spammed and unreachable answers. A cryptographic
 * mismatch is "fail"; an unreachable, truncated or pruned source is "unavailable", never a silent pass. */
import { type Bytes, base58Decode, base58Encode, equal, fromHex, readBig, toHex } from "../byk/bytes";
import { type AlResult, authorized, buildAuthorizationLog } from "../byk/authlog";
import { keccak256, recoverAddress } from "../byk/crypto";
import { type Genesis, maxSequence, parseGenesisCore, parseManifest, SOLANA_DEVNET_GENESIS_B58, SOLANA_MAINNET_GENESIS_B58, validateManifestInStream, WITNESS_KIND, type WitnessKind, witnessKey } from "../byk/stream";
import { EAS_AL_SCHEMA, EAS_DATA_SCHEMA, EAS_GENESIS_SCHEMA, easSchemaUid, parseEasData, parseMemo, SPL_MEMO_PROGRAM_ID, type WitnessPayload, witnessKeyOf } from "../byk/witness";

export type BrowserNet = { name: "mainnet" | "devnet"; baseRpc: string[]; easGraphql: string; solanaRpc: string; baseChainId: bigint; easAddress: string; solanaGenesis: string; pinnedStreamId: string | null };

const EAS_PREDEPLOY = "0x4200000000000000000000000000000000000021";
/* The mainnet stream (BYK.DATALAYER.BETA1, genesis 2026-09-17 23:50 UTC, governance 1-of-1 0x86f2…9364). It is the
 * one value a reader pins; it is also printed on /proof, in the changelog and in the verifier command. */
export const MAINNET_STREAM_ID = "46b69e107bc75175e86a336662311c6e198bbf0dab271c06bc5248888238f66d";
export const BROWSER_NETS: Record<"mainnet" | "devnet", BrowserNet> = {
  mainnet: { name: "mainnet", baseRpc: ["https://mainnet.base.org", "https://base-rpc.publicnode.com"], easGraphql: "https://base.easscan.org/graphql", solanaRpc: "https://solana-rpc.publicnode.com", baseChainId: BigInt(8453), easAddress: EAS_PREDEPLOY, solanaGenesis: SOLANA_MAINNET_GENESIS_B58, pinnedStreamId: MAINNET_STREAM_ID },
  devnet: { name: "devnet", baseRpc: ["https://sepolia.base.org"], easGraphql: "https://base-sepolia.easscan.org/graphql", solanaRpc: "https://api.devnet.solana.com", baseChainId: BigInt(84532), easAddress: EAS_PREDEPLOY, solanaGenesis: SOLANA_DEVNET_GENESIS_B58, pinnedStreamId: null },
};

/** POST a JSON body, return the parsed JSON; throws on a network error, a timeout or a non-2xx answer. */
export type PostJson = (url: string, body: unknown) => Promise<unknown>;

export const fetchPostJson: PostJson = async (url, body) => {
  // a stalled node must turn into "unavailable", not freeze the page
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), cache: "no-store", signal: AbortSignal.timeout(12_000) });
  if (!r.ok) throw new Error(`HTTP ${r.status} from ${new URL(url).host}`);
  return r.json();
};

const SCHEMAS = [EAS_GENESIS_SCHEMA, EAS_AL_SCHEMA, EAS_DATA_SCHEMA] as const;
const SCHEMA_UID = new Map<string, string>(SCHEMAS.map((s) => ["0x" + toHex(easSchemaUid(s)), s]));
const ZERO32 = new Uint8Array(32);

// ---------------------------------------------------------------- Base: EAS getAttestation, decoded by hand

export type Attestation = { uid: Bytes; schema: Bytes; time: bigint; expirationTime: bigint; revocationTime: bigint; refUID: Bytes; recipient: Bytes; attester: Bytes; revocable: boolean; data: Bytes };

/** ABI-decodes the return of EAS getAttestation(bytes32): one dynamic tuple (bytes32 uid, bytes32 schema, uint64
 *  time, uint64 expirationTime, uint64 revocationTime, bytes32 refUID, address recipient, address attester, bool
 *  revocable, bytes data). Throws on anything malformed. */
export function decodeAttestation(resultHex: string): Attestation {
  const b = fromHex(resultHex.replace(/^0x/, ""));
  const t = Number(readBig(b, 0, 32));
  if (t + 320 > b.length) throw new Error("attestation: short tuple");
  const w = (i: number) => b.subarray(t + 32 * i, t + 32 * (i + 1));
  const n = (i: number) => readBig(b, t + 32 * i, 32);
  const addr = (i: number) => {
    const x = w(i);
    if (!equal(x.subarray(0, 12), new Uint8Array(12))) throw new Error("attestation: dirty address word");
    return x.slice(12);
  };
  const flag = n(8);
  if (flag > BigInt(1)) throw new Error("attestation: bad bool");
  const at = t + Number(n(9));
  if (at + 32 > b.length) throw new Error("attestation: data offset");
  const len = Number(readBig(b, at, 32));
  if (at + 32 + len > b.length) throw new Error("attestation: data length");
  return { uid: w(0).slice(), schema: w(1).slice(), time: n(2), expirationTime: n(3), revocationTime: n(4), refUID: w(5).slice(), recipient: addr(6), attester: addr(7), revocable: flag === BigInt(1), data: b.slice(at + 32, at + 32 + len) };
}

/** Section 12.6 admissibility on Base, exactly as the independent verifier (byk-chain/base.ts readAttestations):
 *  our schema, no expiry, not revocable, no ref, sent to the witness key, canonical payload that implies that key. */
export function admissibleAttestation(a: Attestation, schema: string, key: Bytes, streamId: Bytes): WitnessPayload | null {
  if (!equal(a.schema, easSchemaUid(schema)) || a.expirationTime !== BigInt(0) || a.revocable || !equal(a.refUID, ZERO32) || !equal(a.recipient, key.subarray(12))) return null;
  const p = parseEasData(schema, a.data);
  if (!p) return null;
  const implied = witnessKeyOf(p, streamId);
  return implied && equal(implied, key) ? p : null;
}

async function getAttestation(post: PostJson, net: BrowserNet, uid: string): Promise<Attestation | null> {
  let lastError: unknown = null;
  for (const url of net.baseRpc) {
    try {
      const r = (await post(url, { jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: net.easAddress, data: "0xa3112a64" + uid.replace(/^0x/, "").toLowerCase() }, "latest"] })) as { result?: string; error?: unknown };
      if (typeof r.result !== "string") throw new Error("no result");
      const a = decodeAttestation(r.result);
      return toHex(a.uid) === uid.replace(/^0x/, "").toLowerCase() ? a : null; // an unknown uid decodes to an empty struct
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError instanceof Error ? lastError : new Error("Base unreachable");
}

// ---------------------------------------------------------------- the EAS index: discovery only, paged per recipient

export const INDEX_PAGE = 100;
export const INDEX_MAX_PAGES = 20; // 2,000 listed rows under one witness key before the answer becomes "flooded"
export const BASE_READ_BUDGET = 60; // distinct payloads re-read from Base per witness key

type Listed = { uid: string; schema: string; data: Bytes | null; time: number };

/** Every on-chain attestation the index lists for one recipient (lowercase 0x address) that could be admissible
 *  (our schemas, not offchain, not revocable, no expiry, no ref), page by page in id order. complete=false when the
 *  page budget ran out: the caller must then answer "unavailable", never a shorter answer. */
export async function listRecipient(post: PostJson, net: BrowserNet, recipient: string): Promise<{ hits: Listed[]; complete: boolean }> {
  const query = `query($r: String!, $s: [String!], $k: Int!) { attestations(where: { recipient: { equals: $r }, schemaId: { in: $s }, isOffchain: { equals: false }, revocable: { equals: false }, expirationTime: { equals: 0 }, refUID: { equals: "0x${"0".repeat(64)}" } }, orderBy: [{ id: asc }], take: ${INDEX_PAGE}, skip: $k) { id recipient schemaId data time } }`;
  const hits: Listed[] = [];
  for (let page = 0; page < INDEX_MAX_PAGES; page++) {
    const res = (await post(net.easGraphql, { query, variables: { r: recipient, s: [...SCHEMA_UID.keys()], k: page * INDEX_PAGE } })) as { data?: { attestations?: Array<{ id: string; recipient: string; schemaId: string; data?: string; time?: number }> } };
    const rows = res.data?.attestations;
    if (!Array.isArray(rows)) throw new Error("EAS index answered without data");
    for (const a of rows) {
      const schema = SCHEMA_UID.get(String(a.schemaId).toLowerCase());
      if (!schema || String(a.recipient).toLowerCase() !== recipient) continue;
      let data: Bytes | null = null;
      try {
        data = typeof a.data === "string" ? fromHex(a.data.replace(/^0x/, "")) : null;
      } catch {
        data = null;
      }
      hits.push({ uid: String(a.id).toLowerCase(), schema, data, time: Number(a.time ?? 0) });
    }
    if (rows.length < INDEX_PAGE) return { hits, complete: true };
  }
  return { hits, complete: false };
}

type Under = { found: Array<{ p: WitnessPayload; timeSec: bigint }>; complete: boolean };

/** Admissible payloads under one witness key: listed by the index, screened on the index's own copy of the data
 *  (format, implied key, and `screen`: the signature checks that make a payload matter, so junk costs no chain call
 *  and cannot eat the read budget), identical payloads grouped so a thousand re-posted copies cost one Base read (the
 *  earliest listed copy is the one read), then re-read from a Base node and checked again. `first` stops at the
 *  first admissible payload (the genesis needs one). */
async function admissibleUnder(post: PostJson, net: BrowserNet, key: Bytes, streamId: Bytes, schema: string, screen: (p: WitnessPayload) => boolean, first = false): Promise<Under> {
  const { hits, complete } = await listRecipient(post, net, recipientOf(key));
  const groups = new Map<string, Listed>();
  for (const hit of hits) {
    if (hit.schema !== schema || !hit.data) continue;
    const pre = parseEasData(schema, hit.data);
    const implied = pre ? witnessKeyOf(pre, streamId) : null;
    if (!pre || !implied || !equal(implied, key) || !screen(pre)) continue;
    const g = toHex(hit.data);
    const seen = groups.get(g);
    if (!seen || hit.time < seen.time) groups.set(g, hit);
  }
  if (groups.size > BASE_READ_BUDGET) return { found: [], complete: false };
  const found: Array<{ p: WitnessPayload; timeSec: bigint }> = [];
  for (const hit of [...groups.values()].sort((x, y) => x.time - y.time)) {
    const a = await getAttestation(post, net, hit.uid);
    const p = a ? admissibleAttestation(a, schema, key, streamId) : null;
    if (p && a) {
      found.push({ p, timeSec: a.time });
      if (first) break;
    }
  }
  return { found, complete };
}

const recipientOf = (key: Bytes) => "0x" + toHex(key.subarray(12));
const keyOf = (streamId: Bytes, kind: WitnessKind, n: bigint) => witnessKey(streamId, kind, n);

// ---------------------------------------------------------------- 1 + 2 · genesis and the authorization log

export type TrustChain =
  /* entries: log entries buildAuthorizationLog applied (al.head.logSeq); attested: admissible entry copies seen */
  | { ok: true; genesis: Genesis; al: AlResult; entries: number; attested: number }
  /* flooded: a witness key carries more listed entries than this check reads (the verifier still can) */
  | { ok: false; step: "genesis" | "log"; reason: string; unavailable: boolean; flooded?: boolean };

const AL_MAX = 256;

/** A cheap screen, not the rule: every 65-byte signature in the bundle recovers to a governance member. The threshold
 *  and the chain of entries are judged by buildAuthorizationLog on what survives. */
function bundleByGovernance(entry: Bytes, bundle: Bytes, gov: Set<string>): boolean {
  if (bundle.length === 0 || bundle.length % 65 !== 0) return false;
  const digest = keccak256(entry);
  try {
    for (let i = 0; i < bundle.length; i += 65) if (!gov.has(toHex(recoverAddress(digest, bundle.subarray(i, i + 65))))) return false;
    return true;
  } catch {
    return false;
  }
}

/** Genesis and authorization log of the pinned stream, from Base, found through the index. A network without a
 *  stream built into this module is refused: the trust root never comes from a page or a database. */
export async function readTrustChain(post: PostJson, net: BrowserNet, streamId: Bytes): Promise<TrustChain> {
  if (net.pinnedStreamId === null) return { ok: false, step: "genesis", reason: "no stream is built into this check for this network", unavailable: false };
  if (toHex(streamId) !== net.pinnedStreamId) return { ok: false, step: "genesis", reason: "this page names a stream other than the one built into the verifier", unavailable: false };
  const gKey = keyOf(streamId, WITNESS_KIND.GENESIS, BigInt(0));
  let genesis: Genesis | null = null;
  try {
    const g = await admissibleUnder(post, net, gKey, streamId, EAS_GENESIS_SCHEMA, (x) => x.kind === "genesis" && equal(keccak256(x.core), streamId), true);
    const hit = g.found.find((x) => x.p.kind === "genesis" && equal(keccak256(x.p.core), streamId));
    if (hit && hit.p.kind === "genesis") genesis = parseGenesisCore(hit.p.core);
    else if (!g.complete) return { ok: false, step: "genesis", reason: "the genesis witness key is flooded beyond what this check reads", unavailable: true, flooded: true };
    else return { ok: false, step: "genesis", reason: "the EAS index lists no genesis of this stream on Base", unavailable: true };
  } catch (err) {
    return { ok: false, step: "genesis", reason: `genesis unreachable: ${(err as Error).message}`, unavailable: true };
  }
  if (genesis.baseChainId !== net.baseChainId || !equal(genesis.solanaGenesisHash, base58Decode(net.solanaGenesis)) || "0x" + toHex(genesis.baseEasAddress) !== net.easAddress.toLowerCase()) {
    return { ok: false, step: "genesis", reason: "the genesis core names other networks than the ones this page reads", unavailable: false };
  }

  /* The log: log_seq 1, 2, ... A key is read only while the log keeps growing: once the entries at n do not extend
   * the head, whatever else sits there is not part of the log (well-formed entries with junk signatures cannot walk
   * this loop to its limit). A fork at n needs the ACK at n + 1, so one more key is read then. */
  const found: Array<{ entry: Bytes; bundle: Bytes }> = [];
  let al = buildAuthorizationLog(genesis, found);
  try {
    for (let n = 1; ; n++) {
      if (n > AL_MAX) return { ok: false, step: "log", reason: "authorization log longer than this check reads", unavailable: true };
      const gov = new Set(al.state.governance.map((g) => toHex(g)));
      const r = await admissibleUnder(post, net, keyOf(streamId, WITNESS_KIND.AL, BigInt(n)), streamId, EAS_AL_SCHEMA, (x) => x.kind === "al" && bundleByGovernance(x.entry, x.bundle, gov));
      if (!r.complete) return { ok: false, step: "log", reason: `authorization log key ${n} is flooded beyond what this check reads`, unavailable: true, flooded: true };
      if (r.found.length === 0) break;
      for (const x of r.found) if (x.p.kind === "al") found.push({ entry: x.p.entry, bundle: x.p.bundle });
      const before = al;
      al = buildAuthorizationLog(genesis, found);
      const forkWaiting = al.status === "GOVERNANCE_FORK" && al.head.logSeq === BigInt(n - 1);
      if (!forkWaiting && al.head.logSeq < BigInt(n) && !(before.status === "GOVERNANCE_FORK" && al.head.logSeq > before.head.logSeq)) break;
    }
  } catch (err) {
    return { ok: false, step: "log", reason: `authorization log unreachable: ${(err as Error).message}`, unavailable: true };
  }
  al = buildAuthorizationLog(genesis, found);
  if (al.status !== "OK") return { ok: false, step: "log", reason: `authorization log status ${al.status}`, unavailable: false };
  return { ok: true, genesis, al, entries: Number(al.head.logSeq), attested: found.length };
}

/** Does the authorization log read from the chain authorize this signer for this sequence? */
export function signerAuthorizedOnChain(chain: TrustChain, signer: Bytes, sequence: bigint): boolean {
  return chain.ok && authorized(chain.al.state, signer, sequence);
}

// ---------------------------------------------------------------- 4 · the anchor of one manifest

type SolanaTx = { slot?: number; blockTime?: number | null; meta?: { err: unknown } | null; transaction?: { message?: { accountKeys?: string[]; instructions?: Array<{ programIdIndex: number; data: string }> } } } | null;

/** Section 12.6 on Solana, as the verifier's admissiblePayload, over the JSON encoding a browser receives. */
export function admissibleSolanaJson(tx: SolanaTx, key: Bytes, streamId: Bytes): WitnessPayload | null {
  if (!tx || !tx.meta || tx.meta.err !== null) return null;
  const keys = tx.transaction?.message?.accountKeys ?? [];
  const address = base58Encode(key);
  if (!keys.includes(address)) return null;
  const memos = (tx.transaction?.message?.instructions ?? []).filter((ix) => keys[ix.programIdIndex] === SPL_MEMO_PROGRAM_ID);
  if (memos.length !== 1) return null;
  let data: Bytes;
  try {
    data = base58Decode(memos[0]!.data);
  } catch {
    return null;
  }
  for (const b of data) if (b > 0x7e || b < 0x20) return null;
  const p = parseMemo(String.fromCharCode(...data)); // every byte was just checked to be printable ASCII
  if (!p) return null;
  const implied = witnessKeyOf(p, streamId);
  return implied && equal(implied, key) ? p : null;
}

export type AnchorCause = "not_final" | "not_in_browser" | "no_anchor" | "flooded" | "unreachable";
export type AnchorFail = "named" | "early" | "rival" | "checkpoint" | "manifest";

export type AnchorCheck =
  | { state: "pass"; via: "solana" | "base"; timeMs: number; secondsAfterWindow: number }
  /* named: the Solana transaction our API names carries something else; early: the first copy precedes the window
   * end; rival: an authorized, different manifest for the same epoch (equivocation); checkpoint: governance
   * checkpointed another manifest; manifest: the manifest does not fit the genesis or the clock */
  | { state: "fail"; code: AnchorFail; reason: string }
  /* not_final: still being confirmed; not_in_browser: older than the browser's Solana node keeps and no Base copy;
   * no_anchor: nothing of this manifest under its witness key that this browser can read; flooded: a witness key
   * carries more entries than this check reads; unreachable: a source did not answer */
  | { state: "unavailable"; cause: AnchorCause; reason: string };

const FINALITY_MS = 5 * 60_000; // a window this recent may still be anchoring or finalizing
export const SOLANA_SIGNATURE_BUDGET = 200; // as the verifier's readAnchors bound

async function solanaCall<T>(post: PostJson, net: BrowserNet, method: string, params: unknown[]): Promise<T> {
  const r = (await post(net.solanaRpc, { jsonrpc: "2.0", id: 1, method, params })) as { result?: T; error?: unknown };
  if (!r || typeof r !== "object" || r.error !== undefined || !("result" in r)) {
    const detail = r && typeof r === "object" && r.error && typeof r.error === "object" ? String((r.error as { message?: unknown }).message ?? "") : "";
    throw new Error(`Solana ${method} failed${detail ? `: ${detail}` : ""}`);
  }
  return r.result as T;
}

/** The time the browser's Solana node keeps history from, measured on the node itself (0 = everything). Cached for
 *  ten minutes per transport and endpoint, so a test's fake network never sees another's answer. PublicNode balances
 *  over backends that keep different history, so getBlockTime(first) can land on one that already dropped that slot
 *  ("cleaned up ... First available block: N"): it is then asked once more for N. Callers treat a throw as unknown. */
const retentionCache = new WeakMap<PostJson, Map<string, { atMs: number; fromMs: number }>>();
async function solanaHistoryFromMs(post: PostJson, net: BrowserNet): Promise<number> {
  const perPost = retentionCache.get(post) ?? new Map<string, { atMs: number; fromMs: number }>();
  retentionCache.set(post, perPost);
  const c = perPost.get(net.solanaRpc);
  if (c && Date.now() - c.atMs < 10 * 60_000) return c.fromMs;
  const first = await solanaCall<number>(post, net, "getFirstAvailableBlock", []);
  let fromMs = 0;
  if (first > 0) {
    let sec: number | null;
    try {
      sec = await solanaCall<number | null>(post, net, "getBlockTime", [first]);
    } catch (err) {
      const later = /First available block: (\d+)/.exec((err as Error).message)?.[1];
      if (!later) throw err;
      sec = await solanaCall<number | null>(post, net, "getBlockTime", [Number(later)]);
    }
    fromMs = (sec ?? Math.floor(Date.now() / 1000)) * 1000;
  }
  perPost.set(net.solanaRpc, { atMs: Date.now(), fromMs });
  return fromMs;
}

/**
 * Finds the manifest on chain and judges it. Solana: every signature under the witness key (paged, bounded) is
 * read, whatever our API says; the transaction the API names is only a hint and must, when present, carry this
 * manifest. Base: every attestation the index lists under the key. A copy is any admissible payload with this
 * manifest's commitment and an authorized signature (signature bytes may differ); its earliest time is the anchor's
 * position and must not precede the window end. An authorized, different manifest is a rival.
 */
export async function checkDataAnchor(post: PostJson, net: BrowserNet, chain: TrustChain, streamId: Bytes, manifest: Bytes, signature: Bytes, solanaTxId: string | null, nowMs: number = Date.now()): Promise<AnchorCheck> {
  if (!chain.ok) return { state: "unavailable", cause: "unreachable", reason: "no trust chain" };
  const m = parseManifest(manifest);
  try {
    validateManifestInStream(m, chain.genesis);
  } catch {
    return { state: "fail", code: "manifest", reason: "the manifest does not fit this stream's genesis" };
  }
  if (m.sequence > maxSequence(chain.genesis, BigInt(nowMs))) return { state: "fail", code: "manifest", reason: "the manifest claims a sequence later than time allows" };
  const commitment = keccak256(manifest);
  const checkpoint = chain.al.state.checkpoints.get(m.sequence);
  if (checkpoint && !equal(checkpoint, commitment)) return { state: "fail", code: "checkpoint", reason: "governance checkpointed a different manifest for this epoch" };
  const key = keyOf(streamId, WITNESS_KIND.DATA, m.sequence);
  const windowEnd = Number(m.epochEndMs);
  const authorizedSig = (c: Bytes, sig: Bytes) => {
    try {
      return signerAuthorizedOnChain(chain, recoverAddress(c, sig), m.sequence);
    } catch {
      return false;
    }
  };
  /* "copy" and "rival" for any admissible data payload of this sequence; spam (unauthorized) is neither */
  const judgePayload = (p: WitnessPayload | null): "copy" | "rival" | null => {
    if (!p || p.kind !== "data") return null;
    const pm = parseManifest(p.manifest);
    if (pm.sequence !== m.sequence) return null;
    const c = keccak256(p.manifest);
    if (!authorizedSig(c, p.signature)) return null;
    return equal(c, commitment) ? "copy" : "rival";
  };
  const rival: AnchorCheck = { state: "fail", code: "rival", reason: "a second, differently signed manifest exists for this epoch (equivocation)" };
  // `signature` (the served one) was judged at step 7; any authorized copy of this manifest anchors it
  if (signature.length !== 65) return { state: "fail", code: "manifest", reason: "the served signature is malformed" };

  // Solana: the whole witness key, as far as the browser's node keeps it
  let solanaAt: number | null = null;
  try {
    let before: string | undefined;
    let examined = 0;
    let namedSeen = false;
    for (;;) {
      const page = await solanaCall<Array<{ signature: string; err: unknown }>>(post, net, "getSignaturesForAddress", [base58Encode(key), { limit: 100, commitment: "finalized", ...(before ? { before } : {}) }]);
      if (!Array.isArray(page)) throw new Error("Solana signature list malformed");
      for (const s of page) {
        examined++;
        if (s.err !== null) continue;
        const txParams = [s.signature, { encoding: "json", commitment: "finalized", maxSupportedTransactionVersion: 0 }];
        // a load-balanced node can answer from a backend that dropped the slot: ask once more before giving up
        const tx = (await solanaCall<SolanaTx>(post, net, "getTransaction", txParams)) ?? (await solanaCall<SolanaTx>(post, net, "getTransaction", txParams));
        if (!tx) return { state: "unavailable", cause: "unreachable", reason: "a listed Solana transaction could not be read, so the witness key cannot be enumerated" };
        const verdict = judgePayload(admissibleSolanaJson(tx, key, streamId));
        if (s.signature === solanaTxId) {
          namedSeen = true;
          if (verdict !== "copy") return { state: "fail", code: "named", reason: "the named Solana transaction does not carry this manifest under its witness key" };
        }
        if (verdict === "rival") return rival;
        if (verdict === "copy" && typeof tx.blockTime === "number") solanaAt = solanaAt === null ? tx.blockTime * 1000 : Math.min(solanaAt, tx.blockTime * 1000);
      }
      if (page.length < 100) break;
      if (examined >= SOLANA_SIGNATURE_BUDGET) return { state: "unavailable", cause: "flooded", reason: "the witness key carries more Solana transactions than this check reads" };
      before = page[page.length - 1]!.signature;
    }
    // a named transaction the listing did not show: read it directly; it must carry this manifest if it exists
    if (solanaTxId && !namedSeen) {
      const tx = await solanaCall<SolanaTx>(post, net, "getTransaction", [solanaTxId, { encoding: "json", commitment: "finalized", maxSupportedTransactionVersion: 0 }]);
      if (tx) {
        const verdict = judgePayload(admissibleSolanaJson(tx, key, streamId));
        if (verdict !== "copy") return { state: "fail", code: "named", reason: "the named Solana transaction does not carry this manifest under its witness key" };
        if (typeof tx.blockTime === "number") solanaAt = solanaAt === null ? tx.blockTime * 1000 : Math.min(solanaAt, tx.blockTime * 1000);
      }
    }
  } catch (err) {
    return { state: "unavailable", cause: "unreachable", reason: `Solana unreachable: ${(err as Error).message}` };
  }

  // Base, always: an earlier copy, or a rival, can sit there even when Solana answered
  let baseAt: number | null = null;
  try {
    const r = await admissibleUnder(post, net, key, streamId, EAS_DATA_SCHEMA, (x) => judgePayload(x) !== null);
    if (!r.complete) return { state: "unavailable", cause: "flooded", reason: "the witness key is flooded on Base beyond what this check reads" };
    for (const x of r.found) {
      const verdict = judgePayload(x.p);
      if (verdict === "rival") return rival;
      if (verdict === "copy") baseAt = baseAt === null ? Number(x.timeSec) * 1000 : Math.min(baseAt, Number(x.timeSec) * 1000);
    }
  } catch (err) {
    return { state: "unavailable", cause: "unreachable", reason: `Base unreachable: ${(err as Error).message}` };
  }

  const at = solanaAt === null ? baseAt : baseAt === null ? solanaAt : Math.min(solanaAt, baseAt);
  if (at === null) {
    // only now is the node's history depth worth a question, and a failed answer must not hide the result
    let historyFromMs: number | null = null;
    try {
      historyFromMs = await solanaHistoryFromMs(post, net);
    } catch {
      historyFromMs = null;
    }
    const pruned = historyFromMs === null ? nowMs - windowEnd > 40 * 3_600_000 : historyFromMs > windowEnd;
    const cause: AnchorCause = nowMs - windowEnd < FINALITY_MS ? "not_final" : pruned ? "not_in_browser" : "no_anchor";
    return { state: "unavailable", cause, reason: "no anchor of this manifest that this browser can read" };
  }
  if (at < windowEnd) return { state: "fail", code: "early", reason: `anchored at ${new Date(at).toISOString()}, before its window closed` };
  return { state: "pass", via: solanaAt !== null && solanaAt === at ? "solana" : "base", timeMs: at, secondsAfterWindow: Math.round((at - windowEnd) / 1000) };
}
