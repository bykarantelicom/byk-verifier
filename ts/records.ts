/* BYK Data Layer v1 (rc6) · Sections 4.4, 6, 7 and 8: identifiers, status model, 104-byte leaves and the
 * RFC 6962 shaped Merkle tree over keccak256 with RFC 9162 inclusion verification. */
import { ascii, B0, BykError, type Bytes, compare, concat, equal, i64, readBig, readI64, readNum, u16, u32, u64, u8 } from "./bytes";
import { keccak256 } from "./crypto";

export const EPOCH_MS = BigInt(300000);
export const ZERO32 = new Uint8Array(32);
export const LEAF_LEN = 104;

export const STATUS = { OK: 0, DEGRADED: 1, INSUFFICIENT_COVERAGE: 2, NO_DATA: 3 } as const;
export type StatusName = keyof typeof STATUS;
export const STATUS_NAME: Record<number, StatusName> = { 0: "OK", 1: "DEGRADED", 2: "INSUFFICIENT_COVERAGE", 3: "NO_DATA" };

/** Section 4.4: keccak256 of a non-empty name whose every character is printable ASCII 0x21..0x7E
 *  (no space, no control character, nothing outside ASCII). */
export function id32(name: string): Bytes {
  if (typeof name !== "string" || name.length === 0) throw new BykError("invalid identifier name");
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    if (c < 0x21 || c > 0x7e) throw new BykError("invalid identifier name");
  }
  return keccak256(ascii(name));
}

export type Leaf = {
  status: number;
  decimals: number;
  feedId: Bytes;
  assetId: Bytes;
  observedAtMs: bigint;
  value: bigint;
  sourceCount: number;
  expectedSourceCount: number;
  coverageBps: number;
  outlierCount: number;
  maxSourceAgeMs: number;
  dispersion: bigint;
};

export function encodeLeaf(f: Leaf): Bytes {
  if (f.feedId.length !== 32 || f.assetId.length !== 32) throw new BykError("feed_id and asset_id must be 32 bytes");
  const b = concat(
    u8(1), u8(f.status), u8(f.decimals), u8(0), f.feedId, f.assetId, u64(f.observedAtMs), i64(f.value),
    u16(f.sourceCount), u16(f.expectedSourceCount), u16(f.coverageBps), u16(f.outlierCount), u32(f.maxSourceAgeMs), i64(f.dispersion),
  );
  validateLeaf(b);
  return b;
}

export function validateLeaf(b: Bytes): void {
  if (b.length !== LEAF_LEN || b[0] !== 1 || b[3] !== 0 || b[1]! > 3) throw new BykError("bad leaf header");
  if ((b[1] === 2 || b[1] === 3) && (readI64(b, 76) !== B0 || readI64(b, 96) !== B0)) throw new BykError("non-zero value/dispersion with status 2/3");
  if (readI64(b, 96) < B0 || readNum(b, 88, 2) > 10000) throw new BykError("bad quality field");
}

export function parseLeaf(b: Bytes): Leaf {
  validateLeaf(b);
  return {
    status: b[1]!, decimals: b[2]!, feedId: b.slice(4, 36), assetId: b.slice(36, 68), observedAtMs: readBig(b, 68, 8),
    value: readI64(b, 76), sourceCount: readNum(b, 84, 2), expectedSourceCount: readNum(b, 86, 2), coverageBps: readNum(b, 88, 2),
    outlierCount: readNum(b, 90, 2), maxSourceAgeMs: readNum(b, 92, 4), dispersion: readI64(b, 96),
  };
}

/** The sort and uniqueness key of a leaf: feed_id || asset_id (bytes 4..68). */
export function leafKey(leaf: Bytes): Bytes {
  return leaf.subarray(4, 68);
}

/** Section 8 rule 2: ascending by feed_id || asset_id; a duplicate key makes the epoch invalid. */
export function sortLeaves(leaves: Bytes[]): Bytes[] {
  const out = [...leaves].sort((a, b) => compare(leafKey(a), leafKey(b)));
  for (let i = 0; i + 1 < out.length; i++) if (compare(leafKey(out[i]!), leafKey(out[i + 1]!)) === 0) throw new BykError("duplicate leaf key");
  return out;
}

const LEAF_PREFIX = Uint8Array.of(0);
const NODE_PREFIX = Uint8Array.of(1);

export const leafHash = (leaf: Bytes): Bytes => keccak256(concat(LEAF_PREFIX, leaf));
export const nodeHash = (left: Bytes, right: Bytes): Bytes => keccak256(concat(NODE_PREFIX, left, right));

/** Largest power of two strictly smaller than n (n >= 2). */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Merkle tree hash of leaves given in their final order. The empty tree hashes to keccak256(""). */
export function merkleRoot(leaves: Bytes[]): Bytes {
  if (leaves.length === 0) return keccak256(new Uint8Array(0));
  if (leaves.length === 1) return leafHash(leaves[0]!);
  const k = split(leaves.length);
  return nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

export function auditPath(index: number, leaves: Bytes[]): Bytes[] {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) throw new BykError("leaf index outside tree");
  if (leaves.length === 1) return [];
  const k = split(leaves.length);
  if (index < k) return [...auditPath(index, leaves.slice(0, k)), merkleRoot(leaves.slice(k))];
  return [...auditPath(index - k, leaves.slice(k)), merkleRoot(leaves.slice(0, k))];
}

/** RFC 9162 Section 2.1.3.2: the root that a leaf hash and its audit path fold up to, or null when the path
 *  does not fit a tree of that size. treeSize MUST be the manifest's record_count (negative case N12: a proof
 *  can verify against the same root under a different claimed size). Plain arithmetic instead of bit
 *  operators: record_count is a uint32 and JavaScript shifts are signed 32-bit. */
export function rootFromInclusion(leafIndex: number, treeSize: number, hash: Bytes, path: Bytes[]): Bytes | null {
  if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize) || leafIndex < 0 || leafIndex >= treeSize) return null;
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = hash;
  const odd = (x: number) => x % 2 === 1;
  const half = (x: number) => Math.floor(x / 2);
  for (const p of path) {
    if (sn === 0) return null;
    if (odd(fn) || fn === sn) {
      r = nodeHash(p, r);
      if (!odd(fn)) {
        while (!(odd(fn) || fn === 0)) {
          fn = half(fn);
          sn = half(sn);
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = half(fn);
    sn = half(sn);
  }
  return sn === 0 ? r : null;
}

export function verifyInclusion(leafIndex: number, treeSize: number, hash: Bytes, path: Bytes[], root: Bytes): boolean {
  const r = rootFromInclusion(leafIndex, treeSize, hash, path);
  return r !== null && equal(r, root);
}
