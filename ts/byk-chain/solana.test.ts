/* readAnchors against a fake Solana node, through the real @solana/web3.js client (2026-11-16, audit 2.135 E14 (z2)).
 *
 * A witness key is an address anyone can send a transaction to, in any transaction version. The fake node behaves
 * as the mainnet nodes do: a transaction newer than the version the request names is not served, the answer is
 * JSON-RPC -32015 in a 200 body. Its answers are the "json" encoding of a legacy and of a version 1 transaction,
 * field for field what three mainnet nodes returned on 16 Nov 2026 (a version 1 message lists accountKeys, header,
 * instructions, recentBlockhash and transactionConfig), so the library's own reading of a version 1 answer is part
 * of what runs here. */
import assert from "node:assert/strict";
import { test } from "node:test";

import { Connection, PublicKey, SystemProgram, Transaction, TransactionInstruction } from "@solana/web3.js";

import { addressOfPrivateKey, base58Decode, base58Encode, type Bytes, encodeGenesisCore, encodeManifest, fromHex, keccak256, memoOf, signDigest, SOLANA_MAINNET_GENESIS_B58, SOLANA_MAX_TRANSACTION_VERSION, SPL_MEMO_PROGRAM_ID, WITNESS_KIND, witnessKey, type WitnessPayload } from "../index";
import { buildAnchorTransaction, readAnchors } from "./solana";

// keys derived here for the test only; they hold nothing
const key = (label: string) => keccak256(new TextEncoder().encode(`byk-solana-test:${label}`));
const T0 = BigInt(1_789_700_000_000 - (1_789_700_000_000 % 300_000));
const CORE = encodeGenesisCore({ threshold: 1, governance: [addressOfPrivateKey(key("governance"))], genesisEpochStartMs: T0, streamName: "BYK.TEST.SOLANA", baseChainId: BigInt(8453), solanaGenesisHash: base58Decode(SOLANA_MAINNET_GENESIS_B58), baseEasAddress: fromHex("4200000000000000000000000000000000000021") });
const STREAM = keccak256(CORE);
const PAYER = new PublicKey(key("payer"));
const BLOCKHASH = base58Encode(key("blockhash"));
const dataKey = (seq: number) => witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(seq));
function dataPayload(seq: number, rootLabel = "root"): WitnessPayload {
  const s = BigInt(seq);
  const manifest = encodeManifest({ status: 0, sequence: s, epochStartMs: T0 + s * BigInt(300_000), epochEndMs: T0 + (s + BigInt(1)) * BigInt(300_000), recordCount: 35, streamId: STREAM, merkleRoot: keccak256(new TextEncoder().encode(rootLabel)), previousCommitment: new Uint8Array(32), schemaHash: new Uint8Array(32).fill(1), methodologyHash: new Uint8Array(32).fill(2) });
  return { kind: "data", manifest, signature: signDigest(key("data-signer"), keccak256(manifest)) };
}

type MessageJson = { accountKeys: string[]; header: { numRequiredSignatures: number; numReadonlySignedAccounts: number; numReadonlyUnsignedAccounts: number }; instructions: Array<{ programIdIndex: number; accounts: number[]; data: string; stackHeight: number }>; recentBlockhash: string; transactionConfig?: { priorityFee: number | null; computeUnitLimit: number | null; loadedAccountsDataSizeLimit: number | null; heapSize: number | null } };
type Served = { slot: number; blockTime: number; version: "legacy" | number; transaction: { signatures: string[]; message: MessageJson }; meta: Record<string, unknown> };

/** A transaction's message as a node lists it in the "json" encoding. */
function messageJson(tx: Transaction): MessageJson {
  const m = tx.compileMessage();
  return { accountKeys: m.accountKeys.map((k) => k.toBase58()), header: m.header, instructions: m.instructions.map((ix) => ({ programIdIndex: ix.programIdIndex, accounts: ix.accounts, data: ix.data, stackHeight: 1 })), recentBlockhash: m.recentBlockhash };
}
function served(signature: string, slot: number, version: Served["version"], message: MessageJson, err: unknown = null): Served {
  const balances = message.accountKeys.map(() => 1_000_000);
  return { slot, blockTime: 1_794_862_094, version, transaction: { signatures: [signature], message }, meta: { err, fee: 5000, preBalances: balances, postBalances: balances, innerInstructions: [], logMessages: [], preTokenBalances: [], postTokenBalances: [], rewards: [], status: err === null ? { Ok: null } : { Err: err }, loadedAddresses: { writable: [], readonly: [] }, computeUnitsConsumed: 450 } };
}
/** Our own anchor: the legacy transaction the engine writes (buildAnchorTransaction). */
const legacyAnchor = (signature: string, slot: number, witness: Bytes, payload: WitnessPayload): Served =>
  served(signature, slot, "legacy", messageJson(buildAnchorTransaction({ payer: PAYER, witnessKey: witness, memo: memoOf(payload), recentBlockhash: BLOCKHASH })));
/** A transaction of a later version that sends nothing to the key, with or without a memo. Its compute budget is in the
 *  message's transactionConfig, as a version 1 message carries it. */
function versioned(signature: string, slot: number, version: number, witness: Bytes, payload: WitnessPayload | null): Served {
  const tx = new Transaction({ feePayer: PAYER, recentBlockhash: BLOCKHASH });
  tx.add(SystemProgram.transfer({ fromPubkey: PAYER, toPubkey: new PublicKey(witness), lamports: 0 }));
  if (payload) tx.add(new TransactionInstruction({ programId: new PublicKey(SPL_MEMO_PROGRAM_ID), keys: [], data: Buffer.from(memoOf(payload), "ascii") }));
  return served(signature, slot, version, { ...messageJson(tx), transactionConfig: { priorityFee: 0, computeUnitLimit: 400_000, loadedAccountsDataSizeLimit: 67_108_864, heapSize: null } });
}

/** The node: one history per address, newest first. `asked` is the version every getTransaction request named. */
function fakeNode(histories: Record<string, Served[]>) {
  const asked: Array<number | undefined> = [];
  const byId = new Map<string, Served>();
  for (const list of Object.values(histories)) for (const t of list) byId.set(t.transaction.signatures[0]!, t);
  const answer = (method: string, params: unknown[]): { result: unknown } | { error: { code: number; message: string } } => {
    if (method === "getSignaturesForAddress") {
      const [address, o] = params as [string, { limit?: number; before?: string }];
      const all = histories[address] ?? [];
      const from = o.before ? all.findIndex((t) => t.transaction.signatures[0] === o.before) + 1 : 0;
      return { result: all.slice(from, from + (o.limit ?? 1000)).map((t) => ({ signature: t.transaction.signatures[0], slot: t.slot, err: t.meta.err, memo: null, blockTime: t.blockTime, confirmationStatus: "finalized" })) };
    }
    if (method === "getTransaction") {
      const [signature, o] = params as [string, { maxSupportedTransactionVersion?: number }];
      asked.push(o.maxSupportedTransactionVersion);
      const t = byId.get(signature);
      if (!t) return { result: null };
      /* a request that names no version is served legacy transactions only */
      if (t.version !== "legacy" && t.version > (o.maxSupportedTransactionVersion ?? -1)) return { error: { code: -32015, message: `Transaction version (${t.version}) is not supported by the requesting client. Please try the request again with the following configuration parameter: "maxSupportedTransactionVersion": ${t.version}` } };
      return { result: t };
    }
    return { error: { code: -32601, message: `Method not found: ${method}` } };
  };
  const fetchFn = async (_url: unknown, init?: { body?: unknown }) => {
    const request = JSON.parse(String(init?.body)) as { id: unknown; method: string; params: unknown[] };
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: request.id, ...answer(request.method, request.params) }), { status: 200, headers: { "content-type": "application/json" } });
  };
  return { conn: new Connection("http://node.invalid", { commitment: "finalized", disableRetryOnRateLimit: true, fetch: fetchFn as never }), asked };
}

test("readAnchors: our own legacy anchor is found, and every fetch names the newest version the reader reads", async () => {
  const k = dataKey(5);
  const payload = dataPayload(5);
  const node = fakeNode({ [base58Encode(k)]: [legacyAnchor("anchor", 100, k, payload)] });
  const r = await readAnchors(node.conn, k, STREAM);
  assert.deepEqual({ anchors: r.anchors.length, complete: r.complete, examined: r.examined, inadmissible: r.inadmissible, newest: r.newestSignature }, { anchors: 1, complete: true, examined: 1, inadmissible: 0, newest: "anchor" });
  assert.deepEqual(r.anchors[0]!.payload, payload);
  assert.deepEqual({ signature: r.anchors[0]!.signature, slot: r.anchors[0]!.slot, blockTimeSec: r.anchors[0]!.blockTimeSec }, { signature: "anchor", slot: 100, blockTimeSec: 1_794_862_094 });
  assert.equal(SOLANA_MAX_TRANSACTION_VERSION, 1);
  assert.deepEqual(node.asked, [SOLANA_MAX_TRANSACTION_VERSION]);
});

test("readAnchors: a version 1 transaction a stranger sent to the key is read and found inadmissible, and the anchor under it is still found", async () => {
  const k = dataKey(5);
  const payload = dataPayload(5);
  const node = fakeNode({ [base58Encode(k)]: [versioned("dust-v1", 200, 1, k, null), legacyAnchor("anchor", 100, k, payload)] });
  const r = await readAnchors(node.conn, k, STREAM);
  assert.deepEqual({ anchors: r.anchors.map((a) => a.signature), complete: r.complete, examined: r.examined, inadmissible: r.inadmissible, newest: r.newestSignature }, { anchors: ["anchor"], complete: true, examined: 2, inadmissible: 1, newest: "dust-v1" });
  assert.deepEqual(node.asked, [1, 1]);
});

test("readAnchors: an anchor sent as a version 1 transaction is judged by the same rule, under its own key and under no other", async () => {
  const k = dataKey(5);
  const mine = dataPayload(5);
  const rival = dataPayload(5, "rival");
  const elsewhere = dataPayload(6);
  /* newest first: a payload of sequence 6 sent to the key of sequence 5, a second manifest for sequence 5, our own anchor */
  const node = fakeNode({ [base58Encode(k)]: [versioned("v1-of-another-key", 300, 1, k, elsewhere), versioned("v1-rival", 200, 1, k, rival), legacyAnchor("anchor", 100, k, mine)] });
  const r = await readAnchors(node.conn, k, STREAM);
  assert.deepEqual(r.anchors.map((a) => a.signature), ["anchor", "v1-rival"], "oldest first; the version 1 anchor is not skipped, so a rival manifest sent that way is seen");
  assert.deepEqual(r.anchors[1]!.payload, rival);
  assert.deepEqual({ complete: r.complete, examined: r.examined, inadmissible: r.inadmissible }, { complete: true, examined: 3, inadmissible: 1 });
});

test("readAnchors: a transaction of a version the reader does not name ends the read with the node's sentence, it is never skipped", async () => {
  const k = dataKey(5);
  const node = fakeNode({ [base58Encode(k)]: [versioned("future-v2", 300, 2, k, null), legacyAnchor("anchor", 100, k, dataPayload(5))] });
  await assert.rejects(readAnchors(node.conn, k, STREAM), /Transaction version \(2\) is not supported by the requesting client/);
  assert.deepEqual(node.asked, [1], "the read stopped at the transaction it could not fetch");
});

test("readAnchors: a failed transaction is never fetched, whatever its version", async () => {
  const k = dataKey(5);
  const failed = versioned("failed-v2", 300, 2, k, null);
  failed.meta.err = { InstructionError: [0, "Custom"] };
  const node = fakeNode({ [base58Encode(k)]: [failed, legacyAnchor("anchor", 100, k, dataPayload(5))] });
  const r = await readAnchors(node.conn, k, STREAM);
  assert.deepEqual({ anchors: r.anchors.map((a) => a.signature), complete: r.complete, examined: r.examined, newest: r.newestSignature }, { anchors: ["anchor"], complete: true, examined: 2, newest: "failed-v2" });
  assert.deepEqual(node.asked, [1]);
});
