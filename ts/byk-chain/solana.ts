/* BYK Data Layer · Solana witness (rc6 Section 12.4, 12.6, 12.7): writing an anchor and reading anchors back.
 *
 * An anchor is one legacy transaction: a compute budget, a 0-lamport System transfer from the fee payer to the
 * WITNESS KEY (which makes that 32-byte key a static account key, so anyone finds the anchor again with
 * getSignaturesForAddress) and exactly one SPL Memo instruction carrying the payload as text. The fee payer is
 * a hot wallet with gas money and nothing else: admissibility never looks at who paid (Section 12.1). */
import { ComputeBudgetProgram, Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction } from "@solana/web3.js";

import { base58Decode, base58Encode, type Bytes, equal, memoOf, parseMemo, SOLANA_TX_LIMIT, SPL_MEMO_PROGRAM_ID, type WitnessPayload, witnessKeyOf } from "../index";

const MEMO_PROGRAM = new PublicKey(SPL_MEMO_PROGRAM_ID);
/* Measured on devnet, 17 Sep 2026: the Memo program burns about 350 compute units per memo byte. A data anchor
 * (536-byte memo) used 190,060 units, the largest AL anchor (4 governance signatures, 855 bytes) 271,078, the
 * largest genesis anchor 138,973. The default budget is 200,000 per instruction, so WITHOUT an explicit limit
 * the AL anchor fails and the data anchor passes with 5 percent to spare. rc6 Section 12.4 names only a
 * compute-unit price; an explicit limit is required in practice. The price applies to the LIMIT, so it is
 * kept close to the need instead of the 1.4 million maximum. */
const COMPUTE_UNIT_LIMIT = 400_000;

export const SOLANA_DEVNET_RPC = "https://api.devnet.solana.com";

export function keypairFromSecret(secret: string): Keypair {
  const raw = base58Decode(secret.trim());
  if (raw.length !== 64) throw new Error("Solana submitter key must be the base58 of a 64-byte secret key");
  return Keypair.fromSecretKey(raw);
}

export function buildAnchorTransaction(input: { payer: PublicKey; witnessKey: Bytes; memo: string; recentBlockhash: string; priorityMicroLamports?: number }): Transaction {
  const tx = new Transaction({ feePayer: input.payer, recentBlockhash: input.recentBlockhash });
  tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units: COMPUTE_UNIT_LIMIT }));
  tx.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: Math.max(0, Math.round(input.priorityMicroLamports ?? 0)) }));
  tx.add(SystemProgram.transfer({ fromPubkey: input.payer, toPubkey: new PublicKey(input.witnessKey), lamports: 0 }));
  tx.add(new TransactionInstruction({ programId: MEMO_PROGRAM, keys: [], data: Buffer.from(input.memo, "ascii") }));
  return tx;
}

/** Signs and sends one anchor. Returns the transaction signature; confirmation is the caller's job. */
export async function submitAnchor(conn: Connection, payer: Keypair, payload: WitnessPayload, streamId: Bytes, priorityMicroLamports = 0): Promise<{ signature: string; bytes: number; lastValidBlockHeight: number }> {
  const witnessKey = witnessKeyOf(payload, streamId);
  if (!witnessKey) throw new Error("payload does not belong to this stream");
  const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash("confirmed");
  const tx = buildAnchorTransaction({ payer: payer.publicKey, witnessKey, memo: memoOf(payload), recentBlockhash: blockhash, priorityMicroLamports });
  tx.sign(payer);
  const raw = tx.serialize();
  if (raw.length > SOLANA_TX_LIMIT) throw new Error(`anchor transaction is ${raw.length} bytes, limit ${SOLANA_TX_LIMIT}`);
  const signature = await conn.sendRawTransaction(raw, { skipPreflight: false, preflightCommitment: "confirmed", maxRetries: 5 });
  return { signature, bytes: raw.length, lastValidBlockHeight };
}

export type SolanaAnchor = { signature: string; slot: number; blockTimeSec: number | null; payload: WitnessPayload };
export type SolanaReadResult = {
  anchors: SolanaAnchor[];
  complete: boolean;
  examined: number;
  inadmissible: number;
  /** the newest transaction listed under the key, whatever its outcome: the record the rc6 13.7 cache proof compares
   *  against on the next run (cache-proof.ts); null when the key lists nothing */
  newestSignature: string | null;
};

/** Section 12.6 for one fetched transaction: succeeded, witness key among the STATIC account keys, exactly one
 *  SPL Memo instruction, the memo is exactly one of the three formats, and it belongs under this witness key. */
export function admissiblePayload(tx: { meta: { err: unknown } | null; transaction: { message: { staticAccountKeys: PublicKey[]; compiledInstructions: Array<{ programIdIndex: number; data: Uint8Array }> } } }, witnessKey: Bytes, streamId: Bytes): WitnessPayload | null {
  if (!tx.meta || tx.meta.err !== null) return null;
  const keys = tx.transaction.message.staticAccountKeys;
  if (!keys.some((k) => equal(k.toBytes(), witnessKey))) return null;
  const memos = tx.transaction.message.compiledInstructions.filter((ix) => keys[ix.programIdIndex]?.equals(MEMO_PROGRAM));
  if (memos.length !== 1) return null;
  const data = memos[0]!.data;
  for (const b of data) if (b > 0x7e || b < 0x20) return null;
  const payload = parseMemo(Buffer.from(data).toString("ascii"));
  if (!payload) return null;
  const expected = witnessKeyOf(payload, streamId);
  return expected && equal(expected, witnessKey) ? payload : null;
}

/** Section 12.7: every finalized anchor under one witness key, oldest first. `complete` is false when the
 *  enumeration could not be finished; a verifier must then answer INCOMPLETE, never CANONICAL. */
export async function readAnchors(conn: Connection, witnessKey: Bytes, streamId: Bytes, opts: { maxSignatures?: number; asOfSlot?: number } = {}): Promise<SolanaReadResult> {
  const address = new PublicKey(witnessKey);
  const max = opts.maxSignatures ?? 200;
  const out: SolanaAnchor[] = [];
  let before: string | undefined;
  let examined = 0;
  let inadmissible = 0;
  let complete = true;
  let newestSignature: string | null = null;
  for (;;) {
    const page = await conn.getSignaturesForAddress(address, { before, limit: 100 }, "finalized");
    for (const s of page) {
      examined++;
      if (opts.asOfSlot !== undefined && s.slot > opts.asOfSlot) continue; // beyond the as-of height: not judged, so not recorded either
      if (newestSignature === null) newestSignature = s.signature; // newest first: the first one inside the as-of height
      if (s.err !== null) continue; // cheap-first: failed transactions are skipped without a fetch
      const tx = await conn.getTransaction(s.signature, { commitment: "finalized", maxSupportedTransactionVersion: 0 });
      if (!tx) {
        complete = false; // listed but not retrievable: history is missing on this endpoint
        continue;
      }
      const payload = admissiblePayload(tx, witnessKey, streamId);
      if (payload) out.push({ signature: s.signature, slot: s.slot, blockTimeSec: tx.blockTime ?? s.blockTime ?? null, payload });
      else inadmissible++;
    }
    if (page.length < 100) break;
    if (examined >= max) {
      complete = false; // a spammed key: bounded work, honest answer
      break;
    }
    before = page[page.length - 1]!.signature;
  }
  out.sort((a, b) => a.slot - b.slot);
  return { anchors: out, complete, examined, inadmissible, newestSignature };
}

/** Section 12.2: an endpoint counts only when it is the network the genesis core names. */
export async function assertSolanaNetwork(conn: Connection, solanaGenesisHash: Bytes): Promise<void> {
  const got = await conn.getGenesisHash();
  if (got !== base58Encode(solanaGenesisHash)) throw new Error("RPC endpoint is not the Solana network named in the genesis core");
}

export const witnessAddress = (witnessKey: Bytes): string => base58Encode(witnessKey);
