/* BYK Data Layer v1 (rc6) · Section 12: witness payloads (Solana SPL Memo text, Base EAS ABI data and schema
 * UIDs), the Solana size model and the witness-time helpers of Section 12.9. */
import { BykError, type Bytes, concat, equal, fromHex, readBig, toHex, word } from "./bytes";
import { parseAlEntry } from "./authlog";
import { keccak256 } from "./crypto";
import { GENESIS_FIXED_LEN, MANIFEST_LEN, MAX_GOV_N, parseGenesisCore, parseManifest, WITNESS_KIND, type WitnessKind, witnessKey } from "./stream";

export const SPL_MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

export const EAS_DATA_SCHEMA = "uint64 sequence,bytes32 commitment,bytes manifest,bytes signature";
export const EAS_AL_SCHEMA = "uint64 logSeq,bytes32 entryHash,bytes entry,bytes governanceSignatures";
export const EAS_GENESIS_SCHEMA = "bytes32 streamId,bytes genesisCore";

/** A dynamic `bytes` value: length word, data, zero padding to a 32-byte boundary. */
function dyn(b: Bytes): Bytes {
  return concat(word(BigInt(b.length)), b, new Uint8Array((32 - (b.length % 32)) % 32));
}

/** abi.encode(uint64, bytes32, bytes, bytes): the data and AL schemas. */
export function abiU64B32BytesBytes(n: bigint, b32: Bytes, x: Bytes, y: Bytes): Bytes {
  if (b32.length !== 32) throw new BykError("bytes32 expected");
  const tx = dyn(x);
  return concat(word(n), b32, word(BigInt(4 * 32)), word(BigInt(4 * 32 + tx.length)), tx, dyn(y));
}

/** abi.encode(bytes32, bytes): the genesis schema. */
export function abiB32Bytes(b32: Bytes, x: Bytes): Bytes {
  if (b32.length !== 32) throw new BykError("bytes32 expected");
  return concat(b32, word(BigInt(2 * 32)), dyn(x));
}

/** SchemaRegistry._getUID: keccak256(abi.encodePacked(schema, resolver, revocable)). The protocol registers
 *  its schemas with the zero resolver and revocable = false. */
export function easSchemaUid(schema: string, resolver: Bytes = new Uint8Array(20), revocable = false): Bytes {
  if (resolver.length !== 20) throw new BykError("resolver must be 20 bytes");
  return keccak256(concat(new TextEncoder().encode(schema), resolver, Uint8Array.of(revocable ? 1 : 0)));
}

export const memoData = (manifest: Bytes, signature: Bytes): string => `BYK1 ${toHex(manifest)} ${toHex(signature)}`;
export const memoAl = (entry: Bytes, bundle: Bytes): string => `BYKL1 ${toHex(entry)} ${toHex(bundle)}`;
export const memoGenesis = (core: Bytes): string => `BYKG1 ${toHex(core)}`;

/** What an anchor carries, whichever witness it came from. */
export type WitnessPayload =
  | { kind: "data"; manifest: Bytes; signature: Bytes }
  | { kind: "al"; entry: Bytes; bundle: Bytes }
  | { kind: "genesis"; core: Bytes };

const HEX = "[0-9a-f]+";
const MEMO_DATA = new RegExp(`^BYK1 (${HEX}) (${HEX})$`);
const MEMO_AL = new RegExp(`^BYKL1 (${HEX}) (${HEX})$`);
const MEMO_GENESIS = new RegExp(`^BYKG1 (${HEX})$`);

/** Section 12.4: ASCII, single 0x20 separators, lower-case hex without 0x, nothing else. Returns null for
 *  anything that is not exactly one of the three formats with exactly parsing contents (Section 12.6). */
export function parseMemo(text: string): WitnessPayload | null {
  try {
    let m = MEMO_DATA.exec(text);
    if (m) {
      const manifest = fromHex(m[1]!);
      const signature = fromHex(m[2]!);
      if (manifest.length !== MANIFEST_LEN || signature.length !== 65) return null;
      parseManifest(manifest);
      return { kind: "data", manifest, signature };
    }
    m = MEMO_AL.exec(text);
    if (m) {
      const entry = fromHex(m[1]!);
      const bundle = fromHex(m[2]!);
      if (bundle.length === 0 || bundle.length % 65 !== 0) return null;
      parseAlEntry(entry);
      return { kind: "al", entry, bundle };
    }
    m = MEMO_GENESIS.exec(text);
    if (m) {
      const core = fromHex(m[1]!);
      parseGenesisCore(core);
      return { kind: "genesis", core };
    }
    return null;
  } catch (err) {
    if (err instanceof BykError) return null;
    throw err;
  }
}

export function memoOf(p: WitnessPayload): string {
  return p.kind === "data" ? memoData(p.manifest, p.signature) : p.kind === "al" ? memoAl(p.entry, p.bundle) : memoGenesis(p.core);
}

/** The witness key a payload belongs under, for the pinned stream; null when the payload is of another
 *  stream (Section 12.6: embedded stream_id equals the pinned value, key kind and number match the payload). */
export function witnessKeyOf(p: WitnessPayload, streamId: Bytes): Bytes | null {
  if (p.kind === "data") {
    const m = parseManifest(p.manifest);
    return equal(m.streamId, streamId) ? witnessKey(streamId, WITNESS_KIND.DATA, m.sequence) : null;
  }
  if (p.kind === "al") {
    const e = parseAlEntry(p.entry);
    return equal(e.streamId, streamId) ? witnessKey(streamId, WITNESS_KIND.AL, e.logSeq) : null;
  }
  return equal(keccak256(p.core), streamId) ? witnessKey(streamId, WITNESS_KIND.GENESIS, BigInt(0)) : null;
}

export function witnessKindOf(p: WitnessPayload): WitnessKind {
  return p.kind === "data" ? WITNESS_KIND.DATA : p.kind === "al" ? WITNESS_KIND.AL : WITNESS_KIND.GENESIS;
}

/** EAS attestation data of a payload, in schema order. */
export function easDataOf(p: WitnessPayload): { schema: string; data: Bytes } {
  if (p.kind === "data") return { schema: EAS_DATA_SCHEMA, data: abiU64B32BytesBytes(parseManifest(p.manifest).sequence, keccak256(p.manifest), p.manifest, p.signature) };
  if (p.kind === "al") return { schema: EAS_AL_SCHEMA, data: abiU64B32BytesBytes(parseAlEntry(p.entry).logSeq, keccak256(p.entry), p.entry, p.bundle) };
  return { schema: EAS_GENESIS_SCHEMA, data: abiB32Bytes(keccak256(p.core), p.core) };
}

function readDyn(data: Bytes, offset: bigint): Bytes {
  const o = Number(offset);
  if (!Number.isSafeInteger(o) || o + 32 > data.length) throw new BykError("ABI offset outside data");
  const len = Number(readBig(data, o, 32));
  if (!Number.isSafeInteger(len) || o + 32 + len > data.length) throw new BykError("ABI length outside data");
  return data.slice(o + 32, o + 32 + len);
}

/** Section 12.6 (Base): decodes attestation data of one of the three schemas and accepts it only when it is
 *  canonical ABI (re-encoding reproduces it byte for byte) and the outer fields match the inner payload. */
export function parseEasData(schema: string, data: Bytes): WitnessPayload | null {
  try {
    let p: WitnessPayload;
    if (schema === EAS_GENESIS_SCHEMA) {
      p = { kind: "genesis", core: readDyn(data, readBig(data, 32, 32)) };
      parseGenesisCore(p.core);
    } else if (schema === EAS_DATA_SCHEMA || schema === EAS_AL_SCHEMA) {
      const x = readDyn(data, readBig(data, 64, 32));
      const y = readDyn(data, readBig(data, 96, 32));
      if (schema === EAS_DATA_SCHEMA) {
        if (x.length !== MANIFEST_LEN || y.length !== 65) return null;
        parseManifest(x);
        p = { kind: "data", manifest: x, signature: y };
      } else {
        if (y.length === 0 || y.length % 65 !== 0) return null;
        parseAlEntry(x);
        p = { kind: "al", entry: x, bundle: y };
      }
    } else return null;
    return equal(easDataOf(p).data, data) ? p : null; // canonical, and outer sequence/hash equal the inner ones
  } catch (err) {
    if (err instanceof BykError) return null;
    throw err;
  }
}

/* Conservative Solana size model (Section 12.4): legacy transaction, 1 signature, 5 account keys (fee payer,
 * witness key, System, Memo, ComputeBudget), a compute-unit-price instruction, a 0-lamport System transfer to
 * the witness key and one memo instruction. */
export const SOLANA_TX_LIMIT = 1232;
export const SOLANA_TX_OVERHEAD = 1 + 64 + 3 + 1 + 5 * 32 + 32 + 1 + (1 + 1 + 1 + 9) + (1 + 1 + 2 + 1 + 12) + (1 + 1 + 2);
export const MAX_MEMO_BYTES = SOLANA_TX_LIMIT - SOLANA_TX_OVERHEAD;
export const MAX_AL_MEMO_BYTES = "BYKL1 ".length + 2 * (80 + 4 + 20 * MAX_GOV_N) + 1 + 2 * 65 * MAX_GOV_N;
export const MAX_GENESIS_MEMO_BYTES = "BYKG1 ".length + 2 * (GENESIS_FIXED_LEN + 20 * MAX_GOV_N);

/** Highest Base block whose timestamp (seconds) x 1000 <= T, or null. */
export function baseAsOfBlock(blockTimestampSec: Map<number, number>, tMs: number): number | null {
  let best: number | null = null;
  for (const [block, ts] of blockTimestampSec) if (ts * 1000 <= tMs && (best === null || block > best)) best = block;
  return best;
}

/** Highest finalized Solana slot that reports a block time with time x 1000 <= T, or null. */
export function solanaAsOfSlot(slotTimeSec: Map<number, number | null>, tMs: number): number | null {
  let best: number | null = null;
  for (const [slot, ts] of slotTimeSec) if (ts !== null && ts * 1000 <= tMs && (best === null || slot > best)) best = slot;
  return best;
}

export type ReportedTime = { timeMs: number | null; status: "REPORTED" | "INFERRED" | "UNAVAILABLE" };

/** A slot without a block time inherits the time of the next later slot that has one (an upper bound). */
export function solanaReportedTime(slotTimeSec: Map<number, number | null>, slot: number): ReportedTime {
  const own = slotTimeSec.get(slot);
  if (own !== undefined && own !== null) return { timeMs: own * 1000, status: "REPORTED" };
  let next: number | null = null;
  for (const [sl, ts] of slotTimeSec) if (sl > slot && ts !== null && (next === null || sl < next)) next = sl;
  if (next !== null) return { timeMs: slotTimeSec.get(next)! * 1000, status: "INFERRED" };
  return { timeMs: null, status: "UNAVAILABLE" };
}
