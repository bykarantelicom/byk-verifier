/* BYK Data Layer v1 (rc6) · Sections 5, 9, 11.1, 12.3 and 13.2: genesis core and stream_id, witness keys,
 * the 200-byte manifest and its commitment, the stream sequence rule and S_max(T). */
import { ascii, B0, B1, BykError, type Bytes, compare, concat, equal, readBig, readNum, u16, u32, u64, u8 } from "./bytes";
import { keccak256 } from "./crypto";
import { EPOCH_MS, id32, ZERO32 } from "./records";

export const MAX_GOV_N = 4;
export const GENESIS_FIXED_LEN = 112;
export const MANIFEST_LEN = 200;
export const BASE_MAINNET_CHAIN_ID = BigInt(8453);
export const BASE_SEPOLIA_CHAIN_ID = BigInt(84532);
export const BASE_EAS_ADDRESS_HEX = "4200000000000000000000000000000000000021";
export const SOLANA_MAINNET_GENESIS_B58 = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
export const SOLANA_DEVNET_GENESIS_B58 = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

const MAGIC_GENESIS = ascii("BYKG");
const MAGIC_MANIFEST = ascii("BYKD");
const MAGIC_WITNESS = ascii("BYKW");
const EMPTY_ROOT = keccak256(new Uint8Array(0));

/** Section 11.1: 1 <= M, 1 <= N <= 4, N >= 2M - 1 (fewer than M compromised keys always leave M honest
 *  ones), addresses 20 bytes and strictly ascending. The same bounds apply to GOVERNANCE_UPDATE. */
export function checkGovernance(threshold: number, addrs: Bytes[]): void {
  const n = addrs.length;
  if (!(Number.isInteger(threshold) && threshold >= 1 && n >= 1 && n <= MAX_GOV_N && n >= 2 * threshold - 1)) throw new BykError("governance bounds");
  for (let i = 0; i < n; i++) {
    if (addrs[i]!.length !== 20 || (i + 1 < n && compare(addrs[i]!, addrs[i + 1]!) >= 0)) throw new BykError("governance addresses must be 20 bytes, strictly ascending");
  }
}

export type GenesisInput = {
  threshold: number;
  governance: Bytes[];
  genesisEpochStartMs: bigint;
  streamName: string;
  baseChainId: bigint;
  solanaGenesisHash: Bytes;
  baseEasAddress: Bytes;
};

export type Genesis = {
  threshold: number;
  governance: Bytes[];
  genesisEpochStartMs: bigint;
  streamNameId: Bytes;
  baseChainId: bigint;
  solanaGenesisHash: Bytes;
  baseEasAddress: Bytes;
  streamId: Bytes;
};

export function encodeGenesisCore(g: GenesisInput): Bytes {
  checkGovernance(g.threshold, g.governance);
  if (g.genesisEpochStartMs % EPOCH_MS !== B0) throw new BykError("genesis_epoch_start_ms must be aligned");
  if (g.solanaGenesisHash.length !== 32 || g.baseEasAddress.length !== 20) throw new BykError("bad network constant length");
  return concat(
    MAGIC_GENESIS, u8(1), u8(g.threshold), u8(g.governance.length), u8(0), u64(g.genesisEpochStartMs), id32(g.streamName),
    u64(g.baseChainId), g.solanaGenesisHash, g.baseEasAddress, u32(0), ...g.governance,
  );
}

export function parseGenesisCore(b: Bytes): Genesis {
  if (b.length < GENESIS_FIXED_LEN || !equal(b.subarray(0, 4), MAGIC_GENESIS) || b[4] !== 1 || b[7] !== 0 || readNum(b, 108, 4) !== 0) throw new BykError("bad genesis core");
  const m = b[5]!;
  const n = b[6]!;
  if (b.length !== GENESIS_FIXED_LEN + 20 * n) throw new BykError("bad genesis core length");
  const governance: Bytes[] = [];
  for (let i = 0; i < n; i++) governance.push(b.slice(112 + 20 * i, 132 + 20 * i));
  checkGovernance(m, governance);
  const genesisEpochStartMs = readBig(b, 8, 8);
  // The Section 11.1 table requires alignment. The Python reference asserts it only when it BUILDS a core;
  // a verifier has to refuse an unaligned one as well, otherwise no manifest of that stream can ever be valid.
  if (genesisEpochStartMs % EPOCH_MS !== B0) throw new BykError("genesis_epoch_start_ms must be aligned");
  return {
    threshold: m, governance, genesisEpochStartMs, streamNameId: b.slice(16, 48), baseChainId: readBig(b, 48, 8),
    solanaGenesisHash: b.slice(56, 88), baseEasAddress: b.slice(88, 108), streamId: keccak256(b),
  };
}

export const WITNESS_KIND = { DATA: 1, AL: 2, GENESIS: 3 } as const;
export type WitnessKind = (typeof WITNESS_KIND)[keyof typeof WITNESS_KIND];

/** Section 12.3: per-item discovery key. Solana uses the 32 bytes as a static account key, Base uses the
 *  last 20 bytes as the attestation recipient. n is the sequence (data), the log_seq (AL) or 0 (genesis). */
export function witnessKey(streamId: Bytes, kind: WitnessKind, n: bigint): Bytes {
  if (streamId.length !== 32 || (kind !== 1 && kind !== 2 && kind !== 3)) throw new BykError("bad witness key input");
  return keccak256(concat(MAGIC_WITNESS, streamId, u8(kind), u64(n)));
}

export type Manifest = {
  status: number;
  sequence: bigint;
  epochStartMs: bigint;
  epochEndMs: bigint;
  recordCount: number;
  streamId: Bytes;
  merkleRoot: Bytes;
  previousCommitment: Bytes;
  schemaHash: Bytes;
  methodologyHash: Bytes;
};

export function encodeManifest(m: Manifest): Bytes {
  for (const f of [m.streamId, m.merkleRoot, m.previousCommitment, m.schemaHash, m.methodologyHash]) if (f.length !== 32) throw new BykError("manifest hash fields must be 32 bytes");
  const b = concat(
    MAGIC_MANIFEST, u8(1), u8(m.status), u16(0), u64(m.sequence), u64(m.epochStartMs), u64(m.epochEndMs), u32(m.recordCount), u32(0),
    m.streamId, m.merkleRoot, m.previousCommitment, m.schemaHash, m.methodologyHash,
  );
  parseManifest(b);
  return b;
}

/** Structural checks of Section 13.2 steps 1 to 5 (the part that needs no genesis). */
export function parseManifest(b: Bytes): Manifest {
  if (b.length !== MANIFEST_LEN || !equal(b.subarray(0, 4), MAGIC_MANIFEST) || b[4] !== 1 || readNum(b, 6, 2) !== 0 || readNum(b, 36, 4) !== 0) throw new BykError("bad manifest header");
  const m: Manifest = {
    status: b[5]!, sequence: readBig(b, 8, 8), epochStartMs: readBig(b, 16, 8), epochEndMs: readBig(b, 24, 8), recordCount: readNum(b, 32, 4),
    streamId: b.slice(40, 72), merkleRoot: b.slice(72, 104), previousCommitment: b.slice(104, 136), schemaHash: b.slice(136, 168), methodologyHash: b.slice(168, 200),
  };
  const dur = m.epochEndMs - m.epochStartMs;
  if (m.status !== 0 && m.status !== 1 && m.status !== 3) throw new BykError("bad manifest status");
  if (m.epochStartMs % EPOCH_MS !== B0 || dur <= B0 || dur % EPOCH_MS !== B0) throw new BykError("bad window");
  if ((m.status === 0 || m.status === 1) && dur !== EPOCH_MS) throw new BykError("OK/DEGRADED window must be one epoch");
  if ((m.status === 3) !== (m.recordCount === 0)) throw new BykError("NO_DATA iff record_count == 0");
  if (m.recordCount === 0 && !equal(m.merkleRoot, EMPTY_ROOT)) throw new BykError("empty tree root mismatch");
  if (m.sequence === B0 && !equal(m.previousCommitment, ZERO32)) throw new BykError("genesis previous_commitment must be zero");
  return m;
}

/** Section 9.2: the commitment is keccak256 of the 200 manifest bytes. It is what the signer signs. */
export function commitmentOf(manifest: Bytes): Bytes {
  if (manifest.length !== MANIFEST_LEN) throw new BykError("bad manifest header");
  return keccak256(manifest);
}

/** Section 13.2 steps 5 to 7. bigint arithmetic: sequence x 300000 can exceed 2^64. */
export function validateManifestInStream(m: Manifest, genesis: Genesis): void {
  const g0 = genesis.genesisEpochStartMs;
  if (!equal(m.streamId, genesis.streamId)) throw new BykError("stream mismatch");
  if (m.epochStartMs < g0 + m.sequence * EPOCH_MS) throw new BykError("epoch_start_ms < genesis_epoch_start_ms + sequence * 300000");
  if (m.sequence === B0 && !(m.epochStartMs === g0 && m.epochEndMs === g0 + EPOCH_MS)) throw new BykError("genesis window mismatch");
}

/** Section 13.5: S_max(T) = floor((T - G) / 300000) - 1, or -1 when no epoch can have ended yet. */
export function maxSequence(genesis: Genesis, asOfMs: bigint): bigint {
  const d = asOfMs - genesis.genesisEpochStartMs;
  return d < EPOCH_MS ? -B1 : d / EPOCH_MS - B1;
}
