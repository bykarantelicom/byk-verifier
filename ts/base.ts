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

import { type Bytes, easDataOf, easSchemaUid, EAS_AL_SCHEMA, EAS_DATA_SCHEMA, EAS_GENESIS_SCHEMA, equal, fromHex, parseEasData, toHex, type WitnessPayload, witnessKeyOf } from "../byk";

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

/** Section 12.6 and 12.7 for one witness key: Attested events of the EAS contract with this recipient and one
 *  of the three schema UIDs, each attestation read back and accepted only when every field is as Section 12.5
 *  says and the data is canonical ABI of a payload that belongs under this key. */
export async function readAttestations(n: BaseNetwork, witnessKey: Bytes, streamId: Bytes, opts: { fromBlock?: bigint; toBlock?: bigint | "latest" | "finalized" } = {}): Promise<{ anchors: BaseAnchor[]; inadmissible: number }> {
  const { publicClient } = baseClients(n);
  const recipient = hex(witnessKey.subarray(12));
  const anchors: BaseAnchor[] = [];
  let inadmissible = 0;
  for (const schema of SCHEMAS) {
    const uid = hex(easSchemaUid(schema));
    const logs = await publicClient.getLogs({ address: hex(n.easAddress), event: attestedEvent, args: { recipient, schemaUID: uid }, fromBlock: opts.fromBlock ?? "earliest", toBlock: opts.toBlock ?? "finalized" });
    for (const l of logs) {
      const a = await publicClient.readContract({ address: hex(n.easAddress), abi: easAbi, functionName: "getAttestation", args: [l.args.uid!] });
      const payload = a.schema === uid && a.expirationTime === BigInt(0) && a.revocable === false && a.refUID === ZERO_BYTES32 && a.recipient.toLowerCase() === recipient.toLowerCase() ? parseEasData(schema, fromHex(a.data)) : null;
      const expected = payload ? witnessKeyOf(payload, streamId) : null;
      if (payload && expected && equal(expected, witnessKey)) anchors.push({ uid: a.uid, txHash: l.transactionHash ?? "", blockNumber: l.blockNumber ?? BigInt(0), timeSec: Number(a.time), attester: a.attester, payload });
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
const RANGE_REFUSAL = /limited to (?:an?\s+)?([\d,_]+)\s*(?:blocks?)?\s*range|block range (?:is )?too (?:large|wide)|range exceeds|exceeds? the maximum|up to ([\d,_]+) blocks|(?:returned |than )([\d,_]+) results/i;
const MIN_LOG_CHUNK = BigInt(199);
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
const RATE_LIMIT = /rate limit|too many requests|429|throttl/i;
const PAUSE_BETWEEN_CHUNKS_MS = 150;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function chunkFromRangeRefusal(message: string, current: bigint): bigint | null {
  const m = RANGE_REFUSAL.exec(message);
  if (!m) return null;
  const stated = [m[1], m[2], m[3]].find(Boolean);
  const n = stated ? BigInt(stated.replace(/[,_]/g, "")) : BigInt(0);
  const next = n > BigInt(0) ? n - BigInt(1) : current / BigInt(2);
  return next < MIN_LOG_CHUNK ? MIN_LOG_CHUNK : next < current ? next : current / BigInt(2);
}

/** Every admissible anchor of one stream on Base, found in ONE pass instead of one query per witness key.
 *  The filter is the Attested topic plus the three schema UIDs (topic 3), and each hit is read back from the
 *  contract and kept only when it is admissible AND its recipient is the witness key its own payload implies
 *  (Section 12.6). `fromBlock` comes from the genesis time: Base produces a block every 2 seconds. */
export async function scanStreamAttestations(n: BaseNetwork, streamId: Bytes, fromBlock: bigint, opts: { chunk?: bigint; maxCalls?: number } = {}): Promise<{ byWitnessKey: Map<string, BaseAnchor[]>; inadmissible: number; scannedFrom: bigint; scannedTo: bigint; chunkUsed: bigint; calls: number; complete: boolean }> {
  const maxCalls = opts.maxCalls ?? 600; // a bounded amount of work: beyond it the Base side is reported INCOMPLETE
  const { publicClient } = baseClients(n);
  const latest = (await publicClient.getBlock({ blockTag: "latest" })).number;
  const uids = SCHEMAS.map((schema) => hex(easSchemaUid(schema)));
  const byWitnessKey = new Map<string, BaseAnchor[]>();
  let inadmissible = 0;
  let span = opts.chunk ?? DEFAULT_LOG_CHUNK;
  let ceiling = MAX_LOG_CHUNK;
  let successes = 0;
  let calls = 0;
  let complete = true;
  let rateLimitWaits = 0;
  for (let from = fromBlock < BigInt(0) ? BigInt(0) : fromBlock; from <= latest; ) {
    const to = from + span > latest ? latest : from + span;
    if (calls >= maxCalls) {
      complete = false; // an honest stop, never a silent one: the caller says INCOMPLETE for the Base side
      break;
    }
    let logs;
    try {
      calls++;
      logs = await publicClient.getLogs({ address: hex(n.easAddress), event: attestedEvent, args: { schemaUID: uids }, fromBlock: from, toBlock: to });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const next = chunkFromRangeRefusal(message, span);
      if (next !== null && next < span) {
        ceiling = next; // the RPC just told us its limit: never try above it again
        span = next;
        successes = 0;
        continue; // same `from`, a narrower window
      }
      if (RATE_LIMIT.test(message) && rateLimitWaits < 8) {
        rateLimitWaits++;
        await sleep(2_000 * rateLimitWaits); // public endpoints throttle hard and recover quickly
        continue;
      }
      throw err; // not a range refusal and not throttling: let it surface
    }
    for (const l of logs) {
      const a = await publicClient.readContract({ address: hex(n.easAddress), abi: easAbi, functionName: "getAttestation", args: [l.args.uid!] });
      const schema = SCHEMAS[uids.indexOf(a.schema)];
      const payload = schema && a.expirationTime === BigInt(0) && a.revocable === false && a.refUID === ZERO_BYTES32 ? parseEasData(schema, fromHex(a.data)) : null;
      const key = payload ? witnessKeyOf(payload, streamId) : null;
      if (!payload || !key) continue; // another stream, or not ours at all
      if (hex(key.subarray(12)).toLowerCase() !== a.recipient.toLowerCase()) {
        inadmissible++;
        continue;
      }
      const list = byWitnessKey.get(toHex(key)) ?? [];
      list.push({ uid: a.uid, txHash: l.transactionHash ?? "", blockNumber: l.blockNumber ?? BigInt(0), timeSec: Number(a.time), attester: a.attester, payload });
      byWitnessKey.set(toHex(key), list);
    }
    successes++;
    span = nextChunkAfterSuccess(span, successes, ceiling);
    from = to + BigInt(1);
    if (from <= latest) await sleep(PAUSE_BETWEEN_CHUNKS_MS);
  }
  return { byWitnessKey, inadmissible, scannedFrom: fromBlock, scannedTo: latest, chunkUsed: span, calls, complete };
}

/** The block that was current at `timeMs`, from the fixed 2-second block time, with a safety margin. */
export async function blockAtOrBefore(n: BaseNetwork, timeMs: bigint, marginBlocks = BigInt(900)): Promise<bigint> {
  const { publicClient } = baseClients(n);
  const latest = await publicClient.getBlock({ blockTag: "latest" });
  const behind = (latest.timestamp * BigInt(1000) - timeMs) / BigInt(2000);
  const guess = latest.number - (behind > BigInt(0) ? behind : BigInt(0)) - marginBlocks;
  return guess > BigInt(0) ? guess : BigInt(0);
}
