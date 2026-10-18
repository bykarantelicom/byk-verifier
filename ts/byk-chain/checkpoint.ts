/* BYK Data Layer · the verifier's reader checkpoint file (2026-10-18).
 *
 * A checkpoint is the reader's own earlier verdict: the last sequence a run of the same reader resolved CANONICAL, its
 * commitment, the authorization log head that run saw and the last Base block it scanned. The next run reads from that
 * sequence on and seeds the resolution with it (resolve.ts, READER_CHECKPOINT), so a daily run costs one day of
 * sequences instead of every sequence since genesis. It is NOT a protocol object: the log's type 3 checkpoint is
 * governance-signed; this one is only as trustworthy as the run that wrote it. Two rules keep it honest: a run that did
 * not pass writes nothing, and a checkpoint is refused when the authorization log changed since it was written (a
 * governance action can change what earlier sequences resolve to, so the next run must be a full one). */
import { type Bytes, fromHex, toHex } from "../index";

export type CheckpointFile = {
  stream_id: string;
  network: string;
  /** the last CANONICAL sequence of the run that wrote the file, as decimal text */
  sequence: string;
  /** its commitment, 64 hex characters (a 0x prefix is accepted) */
  commitment: string;
  /** the seed row carried HISTORY_UNRESOLVED_BEFORE in the run that wrote the file */
  history_unresolved_before?: boolean;
  /** the authorization log head that run saw; a different head refuses the checkpoint */
  al_head?: { log_seq: string; entry_hash: string } | null;
  solana_slot?: number | null;
  /** the last Base block that run scanned completely; the next run starts CHECKPOINT_BASE_REWIND blocks earlier */
  base_scanned_to?: string | null;
  as_of?: string;
  previous?: { sequence: string; commitment: string } | null;
};

/** The next run starts its Base scan this many blocks before the last scanned one: an hour at Base's 2 s blocks, so a
 *  reorganised or late-indexed attestation near the edge is not missed. */
export const CHECKPOINT_BASE_REWIND = BigInt(1800);

const HEX64 = /^(0x)?[0-9a-f]{64}$/i;
const DIGITS = /^\d+$/;

/** Parses and validates a checkpoint file for one stream on one network. Every refusal names the file. */
export function parseCheckpoint(text: string, streamHex: string, network: string, label = "--checkpoint"): CheckpointFile {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new Error(`${label} could not be read: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new Error(`${label} could not be read: not a JSON object`);
  const cp = raw as Partial<CheckpointFile>;
  if (cp.stream_id !== streamHex || cp.network !== network) throw new Error(`${label} belongs to stream ${String(cp.stream_id)} on ${String(cp.network)}, not to this run`);
  if (!DIGITS.test(String(cp.sequence)) || !HEX64.test(String(cp.commitment))) throw new Error(`${label}: sequence or commitment is malformed`);
  if (cp.base_scanned_to !== undefined && cp.base_scanned_to !== null && !DIGITS.test(String(cp.base_scanned_to))) throw new Error(`${label}: base_scanned_to is malformed`);
  if (cp.al_head !== undefined && cp.al_head !== null) {
    if (typeof cp.al_head !== "object" || !DIGITS.test(String(cp.al_head.log_seq)) || !HEX64.test(String(cp.al_head.entry_hash))) throw new Error(`${label}: al_head is malformed`);
  }
  return cp as CheckpointFile;
}

export function checkpointCommitment(cp: CheckpointFile): Bytes {
  return fromHex(cp.commitment.replace(/^0x/i, "").toLowerCase());
}

/** Where the next Base scan starts, or null when the checkpoint carries no scanned block (then the genesis time decides). */
export function checkpointBaseFrom(cp: CheckpointFile, rewind = CHECKPOINT_BASE_REWIND): bigint | null {
  if (cp.base_scanned_to === undefined || cp.base_scanned_to === null) return null;
  const from = BigInt(cp.base_scanned_to) - rewind;
  return from > BigInt(0) ? from : BigInt(0);
}

/** null when the log head the checkpoint recorded is the one read now (or when it recorded none), otherwise the refusal. */
export function alHeadChanged(cp: CheckpointFile, head: { logSeq: bigint; entryHash: Bytes }): string | null {
  if (cp.al_head === undefined || cp.al_head === null) return null;
  const same = cp.al_head.log_seq === head.logSeq.toString() && cp.al_head.entry_hash.replace(/^0x/i, "").toLowerCase() === toHex(head.entryHash);
  return same ? null : `the authorization log read now differs from the one the checkpoint recorded (head ${cp.al_head.log_seq} then, ${head.logSeq} now): either governance acted since, which can change what earlier sequences resolve to, or this resumed run's bounded Base scan could not see a log entry anchored only on Base; run a full verification without --checkpoint`;
}
