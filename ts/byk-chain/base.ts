/* BYK Data Layer · Base witness through the Ethereum Attestation Service (rc6 Section 12.5 to 12.7).
 *
 * EAS is a predeploy on Base and Base Sepolia (0x42...21, schema registry 0x42...20). An anchor is one
 * attestation: schema = one of the three protocol schemas (zero resolver, not revocable), recipient = the last
 * 20 bytes of the witness key, data = the payload ABI-encoded in schema order, everything else zero. Anyone can
 * find it again with eth_getLogs on the Attested event filtered by recipient and schema.
 * Beta profile: data manifests go to Base once a day (manifests are hash-chained, so that one anchor covers
 * the day); the genesis core and every authorization log entry go to Base as they happen. */
import { createPublicClient, createWalletClient, type Hex, http, parseAbi, parseAbiItem, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base, baseSepolia } from "viem/chains";

import { type Bytes, easDataOf, easSchemaUid, EAS_AL_SCHEMA, EAS_DATA_SCHEMA, EAS_GENESIS_SCHEMA, equal, fromHex, parseEasData, toHex, type WitnessPayload, witnessKeyOf } from "../index";

export const SCHEMA_REGISTRY_ADDRESS = "0x4200000000000000000000000000000000000020" as const;
export const BASE_SEPOLIA_RPC = "https://sepolia.base.org";
export const BASE_MAINNET_RPC = "https://mainnet.base.org";
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;
const ZERO_BYTES32 = ("0x" + "00".repeat(32)) as Hex;
const SCHEMAS = [EAS_DATA_SCHEMA, EAS_AL_SCHEMA, EAS_GENESIS_SCHEMA];

const registryAbi = parseAbi([
  "function register(string schema, address resolver, bool revocable) returns (bytes32)",
  "function getSchema(bytes32 uid) view returns ((bytes32 uid, address resolver, bool revocable, string schema))",
]);
const easAbi = parseAbi([
  "function attest((bytes32 schema, (address recipient, uint64 expirationTime, bool revocable, bytes32 refUID, bytes data, uint256 value) data) request) payable returns (bytes32)",
  "function getAttestation(bytes32 uid) view returns ((bytes32 uid, bytes32 schema, uint64 time, uint64 expirationTime, uint64 revocationTime, bytes32 refUID, address recipient, address attester, bool revocable, bytes data))",
]);
const attestedEvent = parseAbiItem("event Attested(address indexed recipient, address indexed attester, bytes32 uid, bytes32 indexed schemaUID)");

const hex = (b: Bytes): Hex => ("0x" + toHex(b)) as Hex;

export type BaseNetwork = { chainId: bigint; rpcUrl: string; easAddress: Bytes };

function chainOf(n: BaseNetwork) {
  if (n.chainId === BigInt(base.id)) return base;
  if (n.chainId === BigInt(baseSepolia.id)) return baseSepolia;
  throw new Error("base_chain_id of the genesis core is neither Base nor Base Sepolia");
}

export function baseClients(n: BaseNetwork, privateKeyHex?: string) {
  const chain = chainOf(n);
  const transport = http(n.rpcUrl, { timeout: 20_000, retryCount: 2 });
  const publicClient = createPublicClient({ chain, transport });
  const wallet = privateKeyHex ? createWalletClient({ account: privateKeyToAccount(("0x" + privateKeyHex.replace(/^0x/, "")) as Hex), chain, transport }) : null;
  return { publicClient, wallet };
}

/** Section 12.2: the endpoint must be the chain the genesis core names. */
export async function assertBaseNetwork(client: PublicClient, n: BaseNetwork): Promise<void> {
  if (BigInt(await client.getChainId()) !== n.chainId) throw new Error("RPC endpoint is not the chain named in the genesis core");
}

/** Registers the three protocol schemas if they are not there yet (permissionless, once per network).
 *  The UID is a pure function of (schema, resolver, revocable), so it is checked, never trusted. */
export async function ensureSchemas(n: BaseNetwork, privateKeyHex: string): Promise<Array<{ schema: string; uid: string; registered: "already" | string }>> {
  const { publicClient, wallet } = baseClients(n, privateKeyHex);
  await assertBaseNetwork(publicClient as PublicClient, n);
  const out: Array<{ schema: string; uid: string; registered: "already" | string }> = [];
  for (const schema of SCHEMAS) {
    const uid = hex(easSchemaUid(schema));
    const existing = await publicClient.readContract({ address: SCHEMA_REGISTRY_ADDRESS, abi: registryAbi, functionName: "getSchema", args: [uid] });
    if (existing.uid === uid) {
      out.push({ schema, uid, registered: "already" });
      continue;
    }
    const txHash = await wallet!.writeContract({ address: SCHEMA_REGISTRY_ADDRESS, abi: registryAbi, functionName: "register", args: [schema, ZERO_ADDRESS, false] });
    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash, timeout: 120_000 });
    if (receipt.status !== "success") throw new Error(`schema registration reverted: ${txHash}`);
    out.push({ schema, uid, registered: txHash });
  }
  return out;
}

/** Sends one attestation and returns as soon as the node has the transaction. The caller records the hash
 *  BEFORE waiting, so a restart in between never sends the same anchor twice. */
export async function sendAttestation(n: BaseNetwork, privateKeyHex: string, payload: WitnessPayload, streamId: Bytes): Promise<{ txHash: string }> {
  const witnessKey = witnessKeyOf(payload, streamId);
  if (!witnessKey) throw new Error("payload does not belong to this stream");
  const { wallet } = baseClients(n, privateKeyHex);
  const { schema, data } = easDataOf(payload);
  const request = { schema: hex(easSchemaUid(schema)), data: { recipient: hex(witnessKey.subarray(12)), expirationTime: BigInt(0), revocable: false, refUID: ZERO_BYTES32, data: hex(data), value: BigInt(0) } };
  const txHash = await wallet!.writeContract({ address: hex(n.easAddress), abi: easAbi, functionName: "attest", args: [request] });
  return { txHash };
}

export type AttestationReceipt = { status: "success" | "reverted"; uid: string; blockNumber: bigint; gasUsed: bigint; feeWei: bigint; timeSec: number };

/** The receipt of a sent attestation, or null while the transaction is not in a block yet. The fee includes
 *  the L1 data fee that OP Stack chains report next to the L2 execution fee. */
/* What the chain says about a transaction we sent. The old probe turned EVERY failure into "no receipt yet",
 * so ten minutes of a throttled or unreachable endpoint looked exactly like a dropped transaction and the
 * attestation was paid for a second time. Only a node that answers and does not know the hash means dropped. */
export type AttestationProbe =
  | { state: "mined"; receipt: AttestationReceipt }
  | { state: "in_mempool" }
  | { state: "unknown_to_node" }
  | { state: "rpc_error"; message: string };

const errName = (err: unknown): string => (err && typeof err === "object" && "name" in err ? String((err as { name: unknown }).name) : "");
const errText = (err: unknown): string => (err instanceof Error ? err.message : String(err)).replace(/\s+/g, " ").slice(0, 200);

export async function probeAttestation(n: BaseNetwork, txHash: string): Promise<AttestationProbe> {
  const { publicClient } = baseClients(n);
  try {
    const receipt = await attestationReceipt(n, txHash);
    return { state: "mined", receipt };
  } catch (err) {
    if (errName(err) !== "TransactionReceiptNotFoundError") return { state: "rpc_error", message: errText(err) };
  }
  try {
    await publicClient.getTransaction({ hash: txHash as Hex });
    return { state: "in_mempool" };
  } catch (err) {
    return errName(err) === "TransactionNotFoundError" ? { state: "unknown_to_node" } : { state: "rpc_error", message: errText(err) };
  }
}

/** The receipt of a MINED attestation. Throws viem's TransactionReceiptNotFoundError while it is not mined. */
export async function attestationReceipt(n: BaseNetwork, txHash: string): Promise<AttestationReceipt> {
  const { publicClient } = baseClients(n);
  const receipt = await publicClient.getTransactionReceipt({ hash: txHash as Hex });
  const log = receipt.logs.find((l) => l.address.toLowerCase() === hex(n.easAddress).toLowerCase() && l.topics.length === 4);
  const l1Fee = (receipt as unknown as { l1Fee?: bigint | null }).l1Fee ?? BigInt(0);
  const block = await publicClient.getBlock({ blockNumber: receipt.blockNumber });
  return { status: receipt.status, uid: log ? log.data.slice(0, 66) : "", blockNumber: receipt.blockNumber, gasUsed: receipt.gasUsed, feeWei: receipt.gasUsed * receipt.effectiveGasPrice + l1Fee, timeSec: Number(block.timestamp) };
}

export async function finalizedBlockNumber(n: BaseNetwork): Promise<bigint> {
  const { publicClient } = baseClients(n);
  return (await publicClient.getBlock({ blockTag: "finalized" })).number;
}

export async function baseBalanceWei(n: BaseNetwork, privateKeyHex: string): Promise<{ address: string; wei: bigint }> {
  const { publicClient, wallet } = baseClients(n, privateKeyHex);
  const address = wallet!.account.address;
  return { address, wei: await publicClient.getBalance({ address }) };
}

export type BaseAnchor = { uid: string; txHash: string; blockNumber: bigint; timeSec: number; attester: string; payload: WitnessPayload };

type Attestation = { uid: Hex; schema: Hex; time: bigint; expirationTime: bigint; revocable: boolean; refUID: Hex; recipient: Hex; attester: Hex; data: Hex };
/** Section 12.5 and 12.6 for one attestation read back from the contract: one of the three protocol schemas, never
 *  expiring, not revocable, no reference, data that is the canonical ABI of a payload of the pinned stream, and the
 *  recipient is the last 20 bytes of the witness key that payload implies. The anchor and its witness key, or null. */
export function admissibleEasAttestation(a: Attestation, schemaUids: readonly Hex[], streamId: Bytes, log: { transactionHash?: Hex | null; blockNumber?: bigint | null }): { key: Bytes; anchor: BaseAnchor } | null {
  const schema = SCHEMAS[schemaUids.indexOf(a.schema)];
  if (!schema || a.expirationTime !== BigInt(0) || a.revocable !== false || a.refUID !== ZERO_BYTES32) return null;
  const payload = parseEasData(schema, fromHex(a.data));
  const key = payload ? witnessKeyOf(payload, streamId) : null;
  if (!payload || !key) return null; // another stream, or not ours at all
  if (hex(key.subarray(12)).toLowerCase() !== a.recipient.toLowerCase()) return null;
  return { key, anchor: { uid: a.uid, txHash: log.transactionHash ?? "", blockNumber: log.blockNumber ?? BigInt(0), timeSec: Number(a.time), attester: a.attester, payload } };
}

/** Section 12.6 and 12.7 for one witness key: Attested events of the EAS contract with this recipient and one
 *  of the three schema UIDs, each attestation read back and accepted only when every field is as Section 12.5
 *  says and the data is canonical ABI of a payload that belongs under this key. */
export async function readAttestations(n: BaseNetwork, witnessKey: Bytes, streamId: Bytes, opts: { fromBlock?: bigint; toBlock?: bigint | "latest" | "finalized" } = {}): Promise<{ anchors: BaseAnchor[]; inadmissible: number }> {
  const { publicClient } = baseClients(n);
  const recipient = hex(witnessKey.subarray(12));
  const anchors: BaseAnchor[] = [];
  let inadmissible = 0;
  const uids = SCHEMAS.map((schema) => hex(easSchemaUid(schema)));
  for (const uid of uids) {
    const logs = await publicClient.getLogs({ address: hex(n.easAddress), event: attestedEvent, args: { recipient, schemaUID: uid }, fromBlock: opts.fromBlock ?? "earliest", toBlock: opts.toBlock ?? "finalized" });
    for (const l of logs) {
      const a = await publicClient.readContract({ address: hex(n.easAddress), abi: easAbi, functionName: "getAttestation", args: [l.args.uid!] });
      const admissible = admissibleEasAttestation(a, uids, streamId, l);
      if (admissible && equal(admissible.key, witnessKey)) anchors.push(admissible.anchor);
      else inadmissible++;
    }
  }
  anchors.sort((x, y) => (x.blockNumber < y.blockNumber ? -1 : x.blockNumber > y.blockNumber ? 1 : 0));
  return { anchors, inadmissible };
}

/** Every admissible anchor of one stream on Base, found in ONE pass instead of one query per witness key.
 *  Public endpoints cap eth_getLogs at 10,000 blocks, so the range is walked in chunks; the filter is the
 *  Attested topic plus the three schema UIDs (topic 3), and each hit is read back from the contract and kept
 *  only when it is admissible AND its recipient is the witness key its own payload implies (Section 12.6).
 *  `fromBlock` comes from the genesis time: Base produces a block every 2 seconds. */
/** How many blocks one eth_getLogs call may span. Every endpoint has its own cap and they do not agree: Base
 *  Sepolia answers 10,000, Base mainnet refuses anything above 2,000, others use different words for the same
 *  refusal. So the scan starts wide, reads the limit out of the error when the endpoint states one, otherwise
 *  halves, and remembers what worked. A verifier that stops at the first "range too large" would leave the
 *  flagship "check us without us" tool broken on the only chain that matters. */
/* How endpoints say "too many blocks" (each wording met on a live endpoint): Base mainnet "limited to a 2,000 range", 1rpc
 * "limited to 0 - 50 blocks range", Alchemy's free tier "up to a 10 block range", nodies "maximum allowed is 50 blocks",
 * Tatum "over limit of 100", Infura "more than 10000 results", and "2K" or "10k" where a provider abbreviates. The first
 * pattern recognises a refusal; the second reads the number out of it when there is one. A bare HTTP 400 (dRPC, Blast) is
 * NOT taken as a refusal: it would pin the window at the halved size for the rest of the run on a transient error, and an
 * endpoint that says nothing is reported as unreadable instead. */
const RANGE_REFUSAL = /limited to .*range|block range (?:is )?too (?:large|wide)|block range limit|max(?:imum)? (?:block )?range|range (?:is )?(?:too (?:large|wide)|exceeds|over)|exceeds? (?:the )?max|up to (?:an?\s+)?[\d,_]+\s*[kK]?\s*blocks?|maximum allowed is [\d,_]+|over (?:the )?limit of [\d,_]+|(?:returned |than )[\d,_]+ results/i;
/* A wording nodes also use for another complaint (a toBlock beyond a lagging backend's head answers "invalid block range"
 * too): taken as a range refusal only when it states a number. */
const RANGE_REFUSAL_WITH_NUMBER = /invalid block range/i;
const STATED_BLOCK_LIMIT = /(?:limited to (?:an?\s+)?(?:\d+\s*-\s*)?|up to (?:an?\s+)?|maximum allowed is |over (?:the )?limit of |max(?:imum)? (?:block )?range(?: is|:| of)? |max(?:imum)? )([\d,_]+)\s*([kK])?(?![\w])/i;
/* Ten blocks (a span of nine) is the smallest cap met on a live endpoint (Alchemy's free tier, 18 Oct 2026); below it the
 * refusal was about something else and surfaces. */
export const MIN_LOG_CHUNK = BigInt(9);
/* 1,999 is what Base mainnet allows and Base Sepolia accepts, so the common case costs no refused call. */
export const DEFAULT_LOG_CHUNK = BigInt(1_999);
/* Growth ceiling for the adaptive chunk (2026-09-20): public Base RPCs answer up to 10,000 blocks per
 * eth_getLogs (some 2,000); at 1,999 a full scan cost 22 calls a day and the 600-call budget ran out
 * after 27 days of stream life. The scan now grows the window after consecutive successes and stops
 * growing at the first refusal, so the budget covers months instead of weeks. */
export const MAX_LOG_CHUNK = BigInt(9_999);
export const GROW_AFTER_SUCCESSES = 2;

/** Next window after a successful call: doubles (plus one) after GROW_AFTER_SUCCESSES in a row, never above
 *  `ceiling` (the last refused size minus one, or MAX_LOG_CHUNK). Pure, so the policy is unit-tested. */
export function nextChunkAfterSuccess(span: bigint, successes: number, ceiling: bigint): bigint {
  if (successes < GROW_AFTER_SUCCESSES || span >= ceiling) return span;
  const grown = span * BigInt(2) + BigInt(1);
  return grown > ceiling ? ceiling : grown;
}
/* "request limit reached" is mainnet.base.org's wording (2026-10-18 reading: the previous pattern missed it, the scan threw and
 * the verifier exited 1 for an outside reader on the default command); "exceeded its compute units per second capacity" is
 * Alchemy's, sent as a JSON-RPC error whose code is 429 (the HTTP status stays 200), so the code on the error object is read
 * as well as the text. -32005 is the "limit exceeded" code of the Ethereum JSON-RPC error table. */
const RATE_LIMIT = /rate limit|request limit|too many requests|throttl|quota|compute units|per second|capacity|status: 429\b/i;
export const messageOf = (err: unknown): string => (err instanceof Error ? err.message : String(err));
/** The words of an error without the request it quotes: viem repeats the URL and the request body (block numbers, topics)
 *  in every message, and a pattern must never match inside those. */
const wordsOf = (message: string): string => message.replace(/^(?:URL|Request body):.*$/gm, "");
export function rateLimited(err: unknown): boolean {
  const e = err as { code?: unknown; status?: unknown; cause?: unknown } | null;
  for (let o = e, depth = 0; o && typeof o === "object" && depth < 4; o = o.cause as typeof e, depth++) {
    if (o.code === 429 || o.code === -32005 || o.status === 429) return true;
  }
  return RATE_LIMIT.test(wordsOf(messageOf(err)));
}
/* Politeness before every call after the first: public endpoints throttle bursts, and a free keyed endpoint meters compute
 * units per second (Alchemy's free tier allows about four eth_getLogs a second), so the pace is the same at every chunk
 * size and across windows, and a throttle that still happens is waited out above. */
const PAUSE_BETWEEN_CALLS_MS = 150;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function chunkFromRangeRefusal(rawMessage: string, current: bigint): bigint | null {
  const message = wordsOf(rawMessage);
  const m = STATED_BLOCK_LIMIT.exec(message);
  if (!RANGE_REFUSAL.test(message) && !(m && RANGE_REFUSAL_WITH_NUMBER.test(message))) return null;
  const n = m ? BigInt(m[1]!.replace(/[,_]/g, "")) * (m[2] ? BigInt(1000) : BigInt(1)) : BigInt(0);
  /* A stated limit under the current window is taken as is; a limit we already respect, or none, halves the window. The
   * floor applies to both paths (18 Oct 2026: it applied only to the stated one, so a refusal that named a limit above a
   * window of nine returned four). */
  const stated = n > BigInt(0) ? n - BigInt(1) : null;
  const next = stated !== null && stated < current ? stated : current / BigInt(2);
  return next < MIN_LOG_CHUNK ? MIN_LOG_CHUNK : next;
}

export type BaseScanStop = "max_calls" | "rate_limited" | "error";
/** The endpoint named by the network is the chain the genesis core names (Section 12.2), checked before any scan. */
export async function assertBaseRpc(n: BaseNetwork): Promise<void> {
  const { publicClient } = baseClients(n);
  await assertBaseNetwork(publicClient as PublicClient, n);
}

export type ScanOptions = { chunk?: bigint; maxCalls?: number; rateLimitWaitMs?: number; maxRateLimitWaits?: number; maxErrorRetries?: number };
type Hit = { key: string; anchor: BaseAnchor };

function groupHits(hits: Hit[]): Map<string, BaseAnchor[]> {
  const byWitnessKey = new Map<string, BaseAnchor[]>();
  for (const h of hits) {
    const list = byWitnessKey.get(h.key) ?? [];
    list.push(h.anchor);
    byWitnessKey.set(h.key, list);
  }
  return byWitnessKey;
}

/* One adaptive walker shared by the range scan and the windows scan (2026-10-18). The eth_getLogs window grows after
 * consecutive successes and shrinks to what the endpoint states in a refusal, throttling is waited out a bounded number of
 * times, every hit is read back from the contract and judged for admissibility (Section 12.6), and a budget of calls ends the
 * work with an honest stop reason instead of an exception. The state (window size, ceiling, budget, stop) carries across
 * walks, so a cap learned in the first window holds for the rest and a walker that stopped stays stopped. */
function makeWalker(n: BaseNetwork, streamId: Bytes, opts: ScanOptions) {
  const maxCalls = opts.maxCalls ?? 1500;
  const waitMs = opts.rateLimitWaitMs ?? 2_000;
  const maxWaits = opts.maxRateLimitWaits ?? 8; // in a row: a call that succeeds resets the count
  const { publicClient } = baseClients(n);
  const uids = SCHEMAS.map((schema) => hex(easSchemaUid(schema)));
  const maxErrorRetries = opts.maxErrorRetries ?? 3; // in a row, on top of the transport's own two: a transient 5xx or reset is not the end of the pass
  const state = { span: opts.chunk ?? DEFAULT_LOG_CHUNK, ceiling: MAX_LOG_CHUNK, successes: 0, calls: 0, reads: 0, inadmissible: 0, rateLimitWaits: 0, errorRetries: 0, stopReason: null as BaseScanStop | null };
  // every call of the walker after its first pays the pause: getLogs, the read-back of a hit, a block
  const paced = async () => {
    if (state.calls + state.reads > 0) await sleep(PAUSE_BETWEEN_CALLS_MS);
  };
  /* Throttling on any single read (an attestation read back, a block) waits the same way as a throttled getLogs, and any
   * other error is tried again a bounded number of times before it surfaces. null means throttled for good: the caller
   * ends with what it has, like a throttled getLogs. */
  const read = async <T,>(fn: () => Promise<T>): Promise<T | null> => {
    for (;;) {
      try {
        await paced();
        state.reads++;
        const out = await fn();
        state.rateLimitWaits = 0; // a call that succeeds resets the counts, here as after a chunk
        state.errorRetries = 0;
        return out;
      } catch (err) {
        if (rateLimited(err)) {
          if (state.rateLimitWaits < maxWaits) {
            state.rateLimitWaits++;
            await sleep(waitMs * state.rateLimitWaits);
            continue;
          }
          return null;
        }
        if (state.errorRetries < maxErrorRetries) {
          state.errorRetries++;
          await sleep(waitMs * state.errorRetries);
          continue;
        }
        throw err;
      }
    }
  };
  const readBack = (uid: `0x${string}`) => read(() => publicClient.readContract({ address: hex(n.easAddress), abi: easAbi, functionName: "getAttestation", args: [uid] }));
  /** Walks the blocks `from` to `to` inclusive, optionally for one recipient (a witness key). `covered` is the last block
   *  actually read (`from` minus one when none); `stopped` when the budget, the throttling or an error ended the walk, which
   *  also ends every later walk of this walker; `error` carries an error that is neither a range refusal nor throttling (a
   *  bare 400, a timeout, a 5xx), with what was read before it. A chunk whose hits were not all read back is not covered:
   *  the next run reads it again. */
  async function walk(from: bigint, to: bigint, recipient?: Hex): Promise<{ covered: bigint; hits: Hit[]; stopped: boolean; error: unknown }> {
    const hits: Hit[] = [];
    let covered = from - BigInt(1);
    if (state.stopReason !== null) return { covered, hits, stopped: true, error: null };
    for (let at = from; at <= to; ) {
      const end = at + state.span > to ? to : at + state.span;
      if (state.calls >= maxCalls) {
        state.stopReason = "max_calls"; // an honest stop, never a silent one: the caller says INCOMPLETE for the Base side
        return { covered, hits, stopped: true, error: null };
      }
      let logs;
      try {
        await paced();
        state.calls++;
        logs = await publicClient.getLogs({ address: hex(n.easAddress), event: attestedEvent, args: recipient ? { recipient, schemaUID: uids } : { schemaUID: uids }, fromBlock: at, toBlock: end });
      } catch (err) {
        // a throttle first (its code or status is unambiguous), a range refusal second: a throttle worded with "limit" and "range" is waited out, not halved
        if (rateLimited(err)) {
          if (state.rateLimitWaits < maxWaits) {
            state.rateLimitWaits++;
            await sleep(waitMs * state.rateLimitWaits); // public endpoints throttle hard and recover quickly
            continue;
          }
          state.stopReason = "rate_limited"; // throttled for good: an honest INCOMPLETE on the Base side, not an abort of the whole run
          return { covered, hits, stopped: true, error: null };
        }
        const next = chunkFromRangeRefusal(messageOf(err), state.span);
        if (next !== null && next < state.span) {
          state.ceiling = next; // the RPC just told us its limit: never try above it again
          state.span = next;
          state.successes = 0;
          continue; // same `at`, a narrower window
        }
        if (state.errorRetries < maxErrorRetries) {
          state.errorRetries++; // a transient failure (a 5xx, a reset, a timeout past the transport's own retries): once more, a little later
          await sleep(waitMs * state.errorRetries);
          continue;
        }
        state.stopReason = "error"; // not a range refusal and not throttling, and it kept failing: handed to the caller with what was read
        return { covered, hits, stopped: true, error: err };
      }
      for (const l of logs) {
        let a;
        try {
          a = await readBack(l.args.uid!);
        } catch (err) {
          state.stopReason = "error";
          return { covered, hits, stopped: true, error: err };
        }
        if (a === null) {
          state.stopReason = "rate_limited";
          return { covered, hits, stopped: true, error: null };
        }
        const admissible = admissibleEasAttestation(a, uids, streamId, l);
        if (!admissible) {
          state.inadmissible++;
          continue;
        }
        hits.push({ key: toHex(admissible.key), anchor: admissible.anchor });
      }
      // the window grows only on calls that exercised the whole span: a short window proves nothing about a wider one
      if (end - at === state.span) {
        state.successes++;
        state.span = nextChunkAfterSuccess(state.span, state.successes, state.ceiling);
      }
      state.rateLimitWaits = 0;
      state.errorRetries = 0;
      covered = end;
      at = end + BigInt(1);
    }
    return { covered, hits, stopped: false, error: null };
  }
  const budgetLeft = () => state.calls < maxCalls;
  return { walk, read, budgetLeft, state, publicClient };
}

/** Range mode: every admissible anchor of one stream on Base from `fromBlock` to the latest block, found in ONE pass instead of
 *  one query per witness key. The filter is the Attested topic plus the three schema UIDs (topic 3); the full enumeration of
 *  Section 12.7 when the endpoint allows thousands of blocks per call (public endpoints cap eth_getLogs at 2,000 or 10,000
 *  blocks, a free keyed one at ten, and this pass costs a call per cap). A bounded amount of work: beyond it the Base side is
 *  reported INCOMPLETE. 600 calls of 1,999 blocks covered 27.8 days on a 2,000-block endpoint and the stream passed that age
 *  on 18 Oct 2026; 1,500 keeps a full scan from genesis under the cap for about 69 days there (years on a 10,000-block
 *  endpoint), and a reader checkpoint bounds a daily run anyway. */
export type RangeScan = { byWitnessKey: Map<string, BaseAnchor[]>; inadmissible: number; scannedFrom: bigint; scannedTo: bigint; latestBlock: bigint; latestTimeMs: bigint; chunkUsed: bigint; calls: number; complete: boolean; stopReason: BaseScanStop | null };
export async function scanStreamAttestations(n: BaseNetwork, streamId: Bytes, fromBlock: bigint, opts: ScanOptions = {}): Promise<RangeScan> {
  const w = makeWalker(n, streamId, opts);
  const start = fromBlock < BigInt(0) ? BigInt(0) : fromBlock;
  // the latest block goes through the same throttle wait as every other read; throttled for good, the scan is an honest nothing
  const latest = await w.read(() => w.publicClient.getBlock({ blockTag: "latest" }));
  if (latest === null) w.state.stopReason = "rate_limited";
  const r = latest === null ? { hits: [], covered: start - BigInt(1), stopped: true, error: null } : await w.walk(start, latest.number);
  if (r.error !== null) throw r.error; // range mode keeps its contract: an error that is neither a refusal nor throttling surfaces
  return { byWitnessKey: groupHits(r.hits), inadmissible: w.state.inadmissible, scannedFrom: start, scannedTo: r.covered, latestBlock: latest?.number ?? BigInt(-1), latestTimeMs: latest ? latest.timestamp * BigInt(1000) : BigInt(-1), chunkUsed: w.state.span, calls: w.state.calls, complete: !r.stopped, stopReason: w.state.stopReason };
}

/* Windows mode (2026-10-18). Under the beta profile the engine sends the Base copy of an anchor in the same tick as its
 * Solana copy (measured on the live stream: 1 to 34 seconds after it, the daily manifest 49 to 63 seconds after midnight),
 * so a verifier that has read the Solana anchors knows where every Base copy is expected: a short block range around the
 * time the engine sent it. For a data manifest that time is the end of its window (the engine seals at T+45 s and anchors
 * at once; a Solana transaction that is dropped and sent again lands later, which is why the Solana block time alone would
 * place the window too late), for the genesis core and a log entry it is the Solana anchor's block time. Each expected copy
 * is looked for with the per-key filter of Section 12.7 (topic 1 = recipient, topic 3 = schema UID) inside that range, which
 * costs one call on a 2,000-block endpoint and about fifty on a free keyed one that caps eth_getLogs at ten blocks; a full
 * run over a month-old stream stays around two thousand calls either way. What it does not do is enumerate a witness key
 * over the whole chain: a copy outside its window (sent hours late, or by someone else, or with no Solana twin) is only
 * seen by range mode, so a window with no copy is reported as MISSING and the range pass remains the full enumeration.
 * Base blocks are two seconds apart, so a time maps to a block by arithmetic from the latest block; each window's start is
 * checked against a real block (one read per copy) and the window moves by the difference, so a stretch of slower or
 * faster blocks shifts only the windows it touches instead of every one. A copy is one expected
 * attestation; the placement in windows.ts gives each copy one window today, and the pass accepts several per copy (the
 * copy is found when any of them finds it, extended only at its last one), so a placement may split a window later
 * without touching the pass. */
export type WindowSpec = { key: Bytes; kind: "genesis" | "al" | "data"; n: bigint; atMs: bigint; untilMs?: bigint; beforeMs?: bigint };
/** found: a copy was read; open: the range runs to the chain head, the copy may not be there yet; not_walked: the pass
 *  stopped (budget, throttling, an endpoint error) before this range was read to the end; missing: read to the end and
 *  beyond, nothing. One copy may have several windows (a manifest anchored long after its window end gets one at the
 *  window end and one at the Solana anchor): the copy is found when any window found it, open or not walked when any
 *  window is, missing only when every window is. */
export type CopyStatus = "found" | "missing" | "open" | "not_walked";
/** `to` is the last block this window was read to: its end, its extension's end, or where the pass stopped; both null for
 *  a window the pass never reached. */
export type WindowResult = { kind: "genesis" | "al" | "data"; n: string; from: string | null; to: string | null; found: number; calls: number; extended: boolean; status: CopyStatus };
export type CopyResult = { kind: "genesis" | "al" | "data"; n: string; status: CopyStatus; windows: number; found: number };
export type WindowsOptions = ScanOptions & { beforeMs?: bigint; afterMs?: bigint; extensionMs?: bigint; maxExtensions?: number };
/** `driftBlocks`: the largest correction any window needed (signed, the one farthest from zero); `driftRejected`: a window's
 *  measured drift beyond an hour, not believed, that window placed by the arithmetic alone. */
export type WindowsScan = { byWitnessKey: Map<string, BaseAnchor[]>; inadmissible: number; windows: WindowResult[]; copies: CopyResult[]; found: number; missing: number; open: number; notWalked: number; calls: number; chunkUsed: bigint; complete: boolean; stopReason: BaseScanStop | null; error: string | null; latestBlock: bigint; driftBlocks: bigint; driftRejected: bigint | null };
/** Two minutes before the expected send time: the copy was never seen earlier than the tick that sent it. */
export const WINDOW_BEFORE_MS = BigInt(120_000);
/** Thirty minutes before for a window placed from a Solana block time alone (the genesis core, a log entry): a Solana
 *  transaction that is not seen after 150 s is sent again on a later tick, up to five attempts on the live stream. */
export const FIXED_WINDOW_BEFORE_MS = BigInt(1_800_000);
/** Fifteen minutes after: the engine resends a copy that did not land after ten minutes, so a resend still falls inside. */
export const WINDOW_AFTER_MS = BigInt(900_000);
/** A copy that is not where it is expected: look six more hours ahead (the engine keeps resending through an outage of
 *  its Base endpoint), for every such window; the call budget bounds the total, and a window the budget cuts short is
 *  reported not walked, never missing. */
export const WINDOW_EXTENSION_MS = BigInt(21_600_000);
export const BASE_BLOCK_MS = BigInt(2_000);
/** About 52 calls per daily copy on an endpoint that answers ten blocks per call: this covers a year of daily windows,
 *  or a shorter stream with a few extensions, in well under an hour at the endpoint's pace. */
export const WINDOWS_MAX_CALLS = 20_000;

/** The block that was current at `timeMs` on a chain with a fixed block time, by arithmetic from the latest block. */
export function blockNumberAt(latest: { number: bigint; timestamp: bigint }, timeMs: bigint, blockMs = BASE_BLOCK_MS): bigint {
  const latestMs = latest.timestamp * BigInt(1000);
  const behind = timeMs < latestMs ? (latestMs - timeMs) / blockMs : BigInt(0);
  const b = latest.number - behind;
  return b < BigInt(0) ? BigInt(0) : b;
}

const copyKey = (x: { kind: string; n: string | bigint }) => `${x.kind}:${x.n.toString()}`;

function summariseCopies(specs: WindowSpec[], windows: WindowResult[]): CopyResult[] {
  const order: string[] = [];
  const byCopy = new Map<string, WindowResult[]>();
  for (const spec of specs) {
    const k = copyKey(spec);
    if (!byCopy.has(k)) {
      byCopy.set(k, []);
      order.push(k);
    }
  }
  for (const w of windows) byCopy.get(copyKey(w))!.push(w);
  return order.map((k) => {
    const ws = byCopy.get(k)!;
    const found = ws.reduce((m, w) => m + w.found, 0);
    const status: CopyStatus = found > 0 ? "found" : ws.some((w) => w.status === "not_walked") ? "not_walked" : ws.some((w) => w.status === "open") ? "open" : "missing";
    const [kind, n] = k.split(":") as [CopyResult["kind"], string];
    return { kind, n, status, windows: ws.length, found };
  });
}

export async function scanWitnessWindows(n: BaseNetwork, streamId: Bytes, specs: WindowSpec[], opts: WindowsOptions = {}): Promise<WindowsScan> {
  const w = makeWalker(n, streamId, { ...opts, maxCalls: opts.maxCalls ?? WINDOWS_MAX_CALLS });
  const after = opts.afterMs ?? WINDOW_AFTER_MS;
  const extension = opts.extensionMs ?? WINDOW_EXTENSION_MS;
  const maxExtensions = opts.maxExtensions ?? Number.POSITIVE_INFINITY;
  const windows: WindowResult[] = [];
  const hits: Hit[] = [];
  const notWalkedRest = (fromIndex: number) => {
    for (const rest of specs.slice(fromIndex)) windows.push({ kind: rest.kind, n: rest.n.toString(), from: null, to: null, found: 0, calls: 0, extended: false, status: "not_walked" });
  };
  let error: string | null = null;
  let driftRejected: bigint | null = null;
  const finish = (latestBlock: bigint, driftBlocks: bigint): WindowsScan => {
    const copies = summariseCopies(specs, windows);
    const count = (st: CopyStatus) => copies.filter((c) => c.status === st).length;
    // complete: every window read to its end; a pass that stopped after finding a copy read the rest of that window no further
    return { byWitnessKey: groupHits(hits), inadmissible: w.state.inadmissible, windows, copies, found: count("found"), missing: count("missing"), open: count("open"), notWalked: count("not_walked"), calls: w.state.calls, chunkUsed: w.state.span, complete: windows.every((x) => x.status !== "not_walked") && w.state.stopReason === null, stopReason: w.state.stopReason, error, latestBlock, driftBlocks, driftRejected };
  };
  /* A read that fails or is throttled for good before the first window is reported the way a failure inside one is: every
   * window not walked, the reason on the result, never an exception out of the pass. */
  const stoppedEarly = (reason: BaseScanStop, err: unknown, latestBlock: bigint, fromIndex: number, driftBlocks: bigint): WindowsScan => {
    if (err !== null) error = messageOf(err);
    w.state.stopReason = reason;
    notWalkedRest(fromIndex);
    return finish(latestBlock, driftBlocks);
  };
  /** One block, or the finished pass when the read failed or was throttled for good (the windows from `fromIndex` on not walked). */
  const readOrStop = async (which: { blockTag: "latest" } | { blockNumber: bigint }, latestBlock: bigint, fromIndex: number, driftBlocks: bigint): Promise<{ block: { number: bigint; timestamp: bigint } } | { stop: WindowsScan }> => {
    try {
      const block = await w.read(() => w.publicClient.getBlock(which));
      return block === null ? { stop: stoppedEarly("rate_limited", null, latestBlock, fromIndex, driftBlocks) } : { block };
    } catch (err) {
      return { stop: stoppedEarly("error", err, latestBlock, fromIndex, driftBlocks) };
    }
  };
  const latest = await readOrStop({ blockTag: "latest" }, BigInt(-1), 0, BigInt(0));
  if ("stop" in latest) return latest.stop;
  const head = latest.block;
  const latestMs = head.timestamp * BigInt(1000);
  let driftBlocks = BigInt(0);
  const clamp = (b: bigint) => (b < BigInt(0) ? BigInt(0) : b > head.number ? head.number : b);
  const blockAt = (ms: bigint, drift = BigInt(0)): bigint => clamp(blockNumberAt(head, ms) - drift);
  const foundCopies = new Set<string>();
  // the last window of each copy, found in one pass: only that one is extended
  const lastIndexOfCopy = new Map<string, number>();
  for (const [i, x] of specs.entries()) lastIndexOfCopy.set(copyKey(x), i);
  let extensions = 0;
  for (const [index, spec] of specs.entries()) {
    const fromMs = spec.atMs - (spec.beforeMs ?? opts.beforeMs ?? WINDOW_BEFORE_MS);
    const toMs = (spec.untilMs ?? spec.atMs) + after;
    let open = toMs > latestMs; // the copy may simply not be there yet
    if (w.state.stopReason !== null || !w.budgetLeft()) {
      if (w.state.stopReason === null) w.state.stopReason = "max_calls";
      notWalkedRest(index);
      break;
    }
    if (foundCopies.has(copyKey(spec))) {
      // an earlier window of the same copy found it: nothing to look for here, not even a probe
      windows.push({ kind: spec.kind, n: spec.n.toString(), from: blockAt(fromMs).toString(), to: (open ? head.number : blockAt(toMs)).toString(), found: 0, calls: 0, extended: false, status: "found" });
      continue;
    }
    /* One real block checks the arithmetic for this window: the block the arithmetic gives for its start, read, and the
     * window moved by the difference. A start that the arithmetic puts at the head is not probed (the endpoint's own lag
     * would read as drift); a drift beyond an hour is not believed, the arithmetic stands, and the value is reported. */
    let drift = BigInt(0);
    const guess = blockAt(fromMs);
    if (guess < head.number) {
      const probe = await readOrStop({ blockNumber: guess }, head.number, index, driftBlocks);
      if ("stop" in probe) return probe.stop;
      const measured = (probe.block.timestamp * BigInt(1000) - fromMs) / BASE_BLOCK_MS; // positive: the chain is later than the arithmetic says, so the window moves back
      if (measured > BigInt(-1800) && measured < BigInt(1800)) drift = measured;
      else driftRejected = measured;
      if ((drift < BigInt(0) ? -drift : drift) > (driftBlocks < BigInt(0) ? -driftBlocks : driftBlocks)) driftBlocks = drift;
    }
    const from = blockAt(fromMs, drift);
    const to = open ? head.number : blockAt(toMs, drift);
    const recipient = hex(spec.key.subarray(12));
    const keyHex = toHex(spec.key);
    const callsBefore = w.state.calls;
    let found = 0;
    let stopped = false;
    let end = to;
    let extended = false;
    let extensionSkipped = false;
    /** One walk of this copy's range: its hits kept, the ones for this key counted, where it stopped recorded. */
    const part = async (partFrom: bigint, partTo: bigint) => {
      const r = await w.walk(partFrom, partTo, recipient);
      hits.push(...r.hits);
      found += r.hits.filter((h) => h.key === keyHex).length;
      stopped = r.stopped;
      end = stopped ? r.covered : partTo;
      if (r.error !== null) error = messageOf(r.error); // neither a refusal nor throttling: kept with what was read, reported, never thrown
    };
    // a copy with another window still ahead is not extended here: its last window extends, if it comes to that
    const lastWindowOfCopy = lastIndexOfCopy.get(copyKey(spec)) === index;
    await part(from, to);
    if (!stopped && found === 0 && !open && lastWindowOfCopy) {
      const extToMs = toMs + extension;
      const extTo = blockAt(extToMs, drift);
      if (extTo > to) {
        if (extensions < maxExtensions) {
          extensions++;
          extended = true;
          await part(to + BigInt(1), extTo);
        } else extensionSkipped = true; // the hours beyond were not read: honest not_walked, never missing
      }
      // the hours beyond the window are not over yet (whether or not any of them could be read): not missing, not passed by a checkpoint
      if (found === 0 && !stopped && extToMs > latestMs) open = true;
    }
    const status: CopyStatus = found > 0 ? "found" : stopped || extensionSkipped ? "not_walked" : open ? "open" : "missing";
    if (found > 0) foundCopies.add(copyKey(spec));
    windows.push({ kind: spec.kind, n: spec.n.toString(), from: from.toString(), to: end.toString(), found, calls: w.state.calls - callsBefore, extended, status });
    if (error !== null) {
      notWalkedRest(index + 1);
      break;
    }
  }
  return finish(head.number, driftBlocks);
}

/** The block that was current at `timeMs`, from the fixed 2-second block time, with a safety margin. */
export async function blockAtOrBefore(n: BaseNetwork, timeMs: bigint, marginBlocks = BigInt(900)): Promise<bigint> {
  const { publicClient } = baseClients(n);
  const latest = await publicClient.getBlock({ blockTag: "latest" });
  const guess = blockNumberAt(latest, timeMs) - marginBlocks;
  return guess > BigInt(0) ? guess : BigInt(0);
}
