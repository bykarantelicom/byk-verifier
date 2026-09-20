/* BYK Data Layer v1 (rc6) · Section 11.3 to 11.8: authorization log entries, governance signature bundles
 * and the construction of the log at the as-of heights, including governance fork handling. */
import { ascii, BykError, type Bytes, compare, concat, equal, readBig, readNum, toHex, U64_MAX, u16, u32, u64, u8 } from "./bytes";
import { addressOfPrivateKey, keccak256, recoverAddress, signDigest } from "./crypto";
import { ZERO32 } from "./records";
import { checkGovernance, type Genesis } from "./stream";

export const AL_TYPE = { AUTHORIZE: 1, GOVERNANCE_UPDATE: 2, CHECKPOINT: 3, ACK: 4 } as const;
const MAGIC_AL = ascii("BYKL");
const AL_HEADER_LEN = 80;

function header(entryType: number, bodyLen: number, logSeq: bigint, streamId: Bytes, prevHash: Bytes): Bytes {
  if (streamId.length !== 32 || prevHash.length !== 32) throw new BykError("bad AL entry header");
  return concat(MAGIC_AL, u8(1), u8(entryType), u16(bodyLen), u64(logSeq), streamId, prevHash);
}

/** Authorizes `signer` for sequences [validFrom, validUntil); validUntil = 2^64 - 1 means unbounded.
 *  A later AUTHORIZE for the same signer replaces the range, which is how a signer is revoked. */
export function alAuthorize(logSeq: bigint, streamId: Bytes, prevHash: Bytes, signer: Bytes, validFrom: bigint, validUntil: bigint): Bytes {
  if (signer.length !== 20) throw new BykError("bad AUTHORIZE body");
  const body = concat(signer, u32(0), u64(validFrom), u64(validUntil));
  return concat(header(AL_TYPE.AUTHORIZE, body.length, logSeq, streamId, prevHash), body);
}

export function alGovernanceUpdate(logSeq: bigint, streamId: Bytes, prevHash: Bytes, threshold: number, addrs: Bytes[]): Bytes {
  checkGovernance(threshold, addrs);
  const body = concat(u8(threshold), u8(addrs.length), u16(0), ...addrs);
  return concat(header(AL_TYPE.GOVERNANCE_UPDATE, body.length, logSeq, streamId, prevHash), body);
}

export function alCheckpoint(logSeq: bigint, streamId: Bytes, prevHash: Bytes, sequence: bigint, commitment: Bytes): Bytes {
  if (commitment.length !== 32) throw new BykError("bad CHECKPOINT body");
  const body = concat(u64(sequence), commitment);
  return concat(header(AL_TYPE.CHECKPOINT, body.length, logSeq, streamId, prevHash), body);
}

export function alAck(logSeq: bigint, streamId: Bytes, prevHash: Bytes): Bytes {
  return header(AL_TYPE.ACK, 0, logSeq, streamId, prevHash);
}

type AlBase = { logSeq: bigint; streamId: Bytes; previousEntryHash: Bytes; entryHash: Bytes };
export type AlEntry =
  | (AlBase & { entryType: 1; signer: Bytes; validFrom: bigint; validUntil: bigint })
  | (AlBase & { entryType: 2; threshold: number; governance: Bytes[] })
  | (AlBase & { entryType: 3; sequence: bigint; commitment: Bytes })
  | (AlBase & { entryType: 4 });

export function parseAlEntry(b: Bytes): AlEntry {
  if (b.length < AL_HEADER_LEN || !equal(b.subarray(0, 4), MAGIC_AL) || b[4] !== 1 || b.length !== AL_HEADER_LEN + readNum(b, 6, 2)) throw new BykError("bad AL entry header");
  const base: AlBase = { logSeq: readBig(b, 8, 8), streamId: b.slice(16, 48), previousEntryHash: b.slice(48, 80), entryHash: keccak256(b) };
  const body = b.subarray(AL_HEADER_LEN);
  switch (b[5]) {
    case AL_TYPE.AUTHORIZE:
      if (body.length !== 40 || readNum(body, 20, 4) !== 0) throw new BykError("bad AUTHORIZE body");
      return { ...base, entryType: 1, signer: body.slice(0, 20), validFrom: readBig(body, 24, 8), validUntil: readBig(body, 32, 8) };
    case AL_TYPE.GOVERNANCE_UPDATE: {
      if (body.length < 4 || readNum(body, 2, 2) !== 0 || body.length !== 4 + 20 * body[1]!) throw new BykError("bad GOVERNANCE_UPDATE body");
      const governance: Bytes[] = [];
      for (let i = 0; i < body[1]!; i++) governance.push(body.slice(4 + 20 * i, 24 + 20 * i));
      checkGovernance(body[0]!, governance);
      return { ...base, entryType: 2, threshold: body[0]!, governance };
    }
    case AL_TYPE.CHECKPOINT:
      if (body.length !== 40) throw new BykError("bad CHECKPOINT body");
      return { ...base, entryType: 3, sequence: readBig(body, 0, 8), commitment: body.slice(8, 40) };
    case AL_TYPE.ACK:
      if (body.length !== 0) throw new BykError("bad ACK body");
      return { ...base, entryType: 4 };
    default:
      throw new BykError("unknown AL entry type");
  }
}

/** Section 11.4: the 65-byte signatures over the entry hash, concatenated in ascending signer address order. */
export function makeBundle(digest: Bytes, privateKeys: Bytes[]): Bytes {
  const sigs = privateKeys.map((k) => ({ address: addressOfPrivateKey(k), sig: signDigest(k, digest) }));
  sigs.sort((a, b) => compare(a.address, b.address));
  return concat(...sigs.map((s) => s.sig));
}

/** Joins signatures that were produced separately (each governance member signs on their own machine). */
export function joinBundle(digest: Bytes, signatures: Bytes[]): Bytes {
  const sigs = signatures.map((sig) => ({ address: recoverAddress(digest, sig), sig }));
  sigs.sort((a, b) => compare(a.address, b.address));
  return concat(...sigs.map((s) => s.sig));
}

export function verifyBundle(digest: Bytes, bundle: Bytes, governance: Bytes[], threshold: number): boolean {
  if (bundle.length === 0 || bundle.length % 65 !== 0) return false;
  let prev: Bytes = new Uint8Array(0);
  let count = 0;
  for (let i = 0; i < bundle.length; i += 65) {
    let a: Bytes;
    try {
      a = recoverAddress(digest, bundle.subarray(i, i + 65));
    } catch (err) {
      if (err instanceof BykError) return false;
      throw err;
    }
    if (!governance.some((g) => equal(g, a)) || compare(a, prev) <= 0) return false;
    prev = a;
    count++;
  }
  return count >= threshold;
}

export type AlStatus = "OK" | "GOVERNANCE_FORK" | "GOVERNANCE_FORK_TERMINAL";
export type AlState = {
  /** signer address (hex) -> [validFrom, validUntil) */
  auth: Map<string, { validFrom: bigint; validUntil: bigint }>;
  checkpoints: Map<bigint, Bytes>;
  governance: Bytes[];
  threshold: number;
};
export type AlResult = { state: AlState; head: { logSeq: bigint; entryHash: Bytes }; status: AlStatus };

/** Section 11.5. `found`: (entry bytes, bundle) pairs taken from admissible anchors within the as-of heights.
 *  Unparseable entries and entries of other streams are ignored. At a log_seq with more than one valid entry
 *  the log continues only through a single ACK at log_seq + 1 that names one branch and is signed by
 *  min(M + 1, N) members of the governance set in force BEFORE the fork. */
export function buildAuthorizationLog(genesis: Genesis, found: Array<{ entry: Bytes; bundle: Bytes }>): AlResult {
  const bySeq = new Map<bigint, Array<{ e: AlEntry; bundle: Bytes }>>();
  for (const f of found) {
    let e: AlEntry;
    try {
      e = parseAlEntry(f.entry);
    } catch (err) {
      if (err instanceof BykError) continue;
      throw err;
    }
    if (!equal(e.streamId, genesis.streamId)) continue;
    const list = bySeq.get(e.logSeq) ?? [];
    list.push({ e, bundle: f.bundle });
    bySeq.set(e.logSeq, list);
  }
  const state: AlState = { auth: new Map(), checkpoints: new Map(), governance: [...genesis.governance], threshold: genesis.threshold };
  const apply = (e: AlEntry) => {
    if (e.entryType === 1) state.auth.set(toHex(e.signer), { validFrom: e.validFrom, validUntil: e.validUntil });
    else if (e.entryType === 2) {
      state.governance = e.governance;
      state.threshold = e.threshold;
    } else if (e.entryType === 3) state.checkpoints.set(e.sequence, e.commitment);
  };

  let prev: Bytes = ZERO32;
  let seq = BigInt(0);
  for (;;) {
    const i = seq + BigInt(1);
    const valid = new Map<string, AlEntry>();
    for (const { e, bundle } of bySeq.get(i) ?? []) {
      if (equal(e.previousEntryHash, prev) && verifyBundle(e.entryHash, bundle, state.governance, state.threshold)) valid.set(toHex(e.entryHash), e);
    }
    if (valid.size === 0) return { state, head: { logSeq: seq, entryHash: prev }, status: "OK" };
    if (valid.size === 1) {
      const e = valid.values().next().value as AlEntry;
      apply(e);
      prev = e.entryHash;
      seq = i;
      continue;
    }
    const preGov = [...state.governance];
    const forkThreshold = Math.min(state.threshold + 1, preGov.length);
    const conts = new Map<string, AlEntry>();
    for (const { e, bundle } of bySeq.get(i + BigInt(1)) ?? []) {
      if (e.entryType === 4 && valid.has(toHex(e.previousEntryHash)) && verifyBundle(e.entryHash, bundle, preGov, forkThreshold)) conts.set(toHex(e.entryHash), e);
    }
    if (conts.size === 0) return { state, head: { logSeq: seq, entryHash: prev }, status: "GOVERNANCE_FORK" };
    if (conts.size > 1) return { state, head: { logSeq: seq, entryHash: prev }, status: "GOVERNANCE_FORK_TERMINAL" };
    const c = conts.values().next().value as AlEntry;
    apply(valid.get(toHex(c.previousEntryHash))!);
    apply(c);
    prev = c.entryHash;
    seq = i + BigInt(1);
  }
}

/** Section 11.6: is `signer` authorized for `sequence` in this log state. */
export function authorized(state: AlState, signer: Bytes, sequence: bigint): boolean {
  const r = state.auth.get(toHex(signer));
  if (!r) return false;
  return r.validFrom <= sequence && (r.validUntil === U64_MAX || sequence < r.validUntil);
}
