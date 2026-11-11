/* scanStreamAttestations and scanWitnessWindows against a fake Base JSON-RPC (2026-10-18): a throttled endpoint ends in an
 * honest incomplete scan with its reason instead of an exception, a transient throttle is waited out, a clean pass covers
 * every block, an error that is not throttling still surfaces; windows mode places each expected copy from its Solana time
 * through the chain's own block times, asks for one recipient, reads from the expected time on and no further than the
 * copy, adapts to a ten-block cap, extends a window with no copy, leaves an open window alone and stops on the budget.
 * The fake answers eth_chainId, eth_getBlockByNumber, eth_getLogs and the getAttestation eth_call. Its blocks are two
 * seconds apart unless a test gives the chain its own clock (2026-11-11: Base went to five blocks a second on 5 Nov 2026
 * and the fixed two seconds this pass assumed reported every later copy missing). */
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { test } from "node:test";

import { encodeFunctionResult, parseAbi } from "viem";

import { BASE_EAS_ADDRESS_HEX, BASE_MAINNET_CHAIN_ID, easDataOf, easSchemaUid, EAS_DATA_SCHEMA, encodeManifest, EPOCH_MS, fromHex, toHex, WITNESS_KIND, witnessKey } from "../index";
import { type BaseNetwork, scanStreamAttestations, scanWitnessWindows, type WindowSpec } from "./base";
import { CLOCK_TOLERANCE_MS } from "./block-clock";

const STREAM = fromHex("46b69e107bc75175e86a336662311c6e198bbf0dab271c06bc5248888238f66d");
const LATEST = 0x20;
const TS = 0x68f3a000;
const blockTemplate = { hash: "0x" + "ab".repeat(32), parentHash: "0x" + "cd".repeat(32), nonce: "0x0000000000000000", difficulty: "0x0", gasLimit: "0x1c9c380", gasUsed: "0x0", miner: "0x" + "00".repeat(20), extraData: "0x", size: "0x200", sha3Uncles: "0x" + "00".repeat(32), stateRoot: "0x" + "00".repeat(32), receiptsRoot: "0x" + "00".repeat(32), transactionsRoot: "0x" + "00".repeat(32), logsBloom: "0x" + "00".repeat(256), transactions: [], uncles: [], mixHash: "0x" + "00".repeat(32), baseFeePerGas: "0x1" };

type LogParams = { fromBlock: string; toBlock: string; topics: Array<string | string[] | null> };
type Reply = { result: unknown } | { error: { code: number; message: string } };
type Rpc = { server: Server; url: string; calls: string[]; logCalls: LogParams[]; close: () => Promise<void> };
/** `timeOf`: the chain's own clock, seconds for a block number (default: two seconds a block back from the latest one);
 *  `attestations`: what getAttestation answers, by uid; `blockReply`: a test's own answer to a numbered block read. */
type Chain = { latest?: number; timestamp?: number; timeOf?: (number: number) => number; attestations?: Map<string, string>; blockReply?: (nthNumbered: number) => Reply | null };
function fakeRpc(getLogs: (n: number, p: LogParams) => Reply, chain: Chain = {}): Promise<Rpc> {
  const latest = chain.latest ?? LATEST;
  const ts = chain.timestamp ?? TS;
  const timeOf = chain.timeOf ?? ((number: number) => ts - 2 * (latest - number));
  let numberedReads = 0;
  const calls: string[] = [];
  const logCalls: LogParams[] = [];
  let logsCalls = 0;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const msg = JSON.parse(body) as { id: number; method: string; params: unknown[] };
      calls.push(msg.method);
      const reply = (r: Record<string, unknown>) => {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, ...r }));
      };
      if (msg.method === "eth_chainId") return reply({ result: "0x" + BASE_MAINNET_CHAIN_ID.toString(16) });
      if (msg.method === "eth_getBlockByNumber") {
        const tag = msg.params[0] as string;
        const number = tag === "latest" || tag === "finalized" ? latest : Number(BigInt(tag));
        if (tag !== "latest" && tag !== "finalized") {
          const own = chain.blockReply?.(++numberedReads) ?? null;
          if (own !== null) return reply(own);
        }
        return reply({ result: { ...blockTemplate, number: "0x" + number.toString(16), timestamp: "0x" + timeOf(number).toString(16) } });
      }
      if (msg.method === "eth_call") {
        // getAttestation(bytes32 uid): the selector, then the uid
        const uid = "0x" + (msg.params[0] as { data: string }).data.slice(10, 74);
        const result = chain.attestations?.get(uid);
        return reply(result ? { result } : { error: { code: -32000, message: "execution reverted" } });
      }
      if (msg.method === "eth_getLogs") {
        const p = msg.params[0] as LogParams;
        logCalls.push(p);
        return reply(getLogs(++logsCalls, p));
      }
      return reply({ error: { code: -32601, message: `method ${msg.method} not found` } });
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as { port: number };
      resolve({ server, url: `http://127.0.0.1:${addr.port}`, calls, logCalls, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}
const net = (url: string): BaseNetwork => ({ chainId: BASE_MAINNET_CHAIN_ID, rpcUrl: url, easAddress: fromHex(BASE_EAS_ADDRESS_HEX) });
const span = (p: LogParams) => Number(BigInt(p.toBlock) - BigInt(p.fromBlock));
const ALCHEMY_FREE = "Under the Free tier plan, you can make eth_getLogs requests with up to a 10 block range. Based on your parameters, this block range should work: [0x325230a, 0x3252313]. Upgrade to PAYG for expanded block range.";

test("a clean pass covers every block up to latest and is complete", async () => {
  const rpc = await fakeRpc(() => ({ result: [] }));
  try {
    const r = await scanStreamAttestations(net(rpc.url), STREAM, BigInt(0), { rateLimitWaitMs: 1 });
    assert.equal(r.complete, true);
    assert.equal(r.stopReason, null);
    assert.equal(r.scannedFrom, BigInt(0));
    assert.equal(r.scannedTo, BigInt(LATEST));
    assert.equal(r.byWitnessKey.size, 0);
    assert.ok(r.calls >= 1);
    assert.equal(rpc.logCalls[0]!.topics[1], null, "range mode asks for every recipient");
  } finally {
    await rpc.close();
  }
});

test("an endpoint that keeps answering 'request limit reached' ends in an incomplete scan with the reason, not an exception", async () => {
  const rpc = await fakeRpc(() => ({ error: { code: -32000, message: "request limit reached" } }));
  try {
    const r = await scanStreamAttestations(net(rpc.url), STREAM, BigInt(0), { rateLimitWaitMs: 1, maxRateLimitWaits: 3 });
    assert.equal(r.complete, false);
    assert.equal(r.stopReason, "rate_limited");
    assert.equal(r.scannedTo, BigInt(-1), "nothing was covered");
    assert.equal(r.calls, 4, "the first call plus the three waits");
  } finally {
    await rpc.close();
  }
});

test("a transient endpoint error is tried again a bounded number of times, and the count resets after a success", async () => {
  // 33 blocks in chunks of nine (the chunk grows to 17 after two full ones): calls 1 ok, 2 fails, 3 retry ok, 4 fails, 5 retry ok
  const rpc = await fakeRpc((n) => ([2, 4].includes(n) ? { error: { code: -32000, message: "internal error" } } : { result: [] }));
  try {
    const r = await scanStreamAttestations(net(rpc.url), STREAM, BigInt(0), { rateLimitWaitMs: 1, chunk: BigInt(8) });
    assert.equal(r.complete, true);
    assert.equal(r.scannedTo, BigInt(LATEST));
    assert.equal(r.calls, 5, "three chunks and two retries");
  } finally {
    await rpc.close();
  }
});

test("a transient throttle is waited out and the count resets after a success", async () => {
  // throttled on the 1st, 2nd, 4th and 5th getLogs: four throttles in total, never three in a row with maxRateLimitWaits 2
  const rpc = await fakeRpc((n) => ([1, 2, 4, 5].includes(n) ? { error: { code: -32000, message: "Too Many Requests" } } : { result: [] }));
  try {
    const r = await scanStreamAttestations(net(rpc.url), STREAM, BigInt(0), { rateLimitWaitMs: 1, maxRateLimitWaits: 2, chunk: BigInt(8) });
    assert.equal(r.complete, true);
    assert.equal(r.stopReason, null);
    assert.equal(r.scannedTo, BigInt(LATEST));
  } finally {
    await rpc.close();
  }
});

test("a throttle sent as a JSON-RPC error with code 429 in a 200 body is waited out like any other", async () => {
  const rpc = await fakeRpc((n) => (n <= 2 ? { error: { code: 429, message: "Your app has exceeded its compute units per second capacity. If you have retries enabled, you can safely ignore this message." } } : { result: [] }));
  try {
    const r = await scanStreamAttestations(net(rpc.url), STREAM, BigInt(0), { rateLimitWaitMs: 1, maxRateLimitWaits: 3 });
    assert.equal(r.complete, true);
    assert.equal(r.scannedTo, BigInt(LATEST));
  } finally {
    await rpc.close();
  }
});

test("an error that is not throttling still surfaces", async () => {
  const rpc = await fakeRpc(() => ({ error: { code: -32000, message: "execution reverted" } }));
  try {
    await assert.rejects(() => scanStreamAttestations(net(rpc.url), STREAM, BigInt(0), { rateLimitWaitMs: 1 }), /execution reverted/);
  } finally {
    await rpc.close();
  }
});

test("a range scan reports the latest block and its time, so a checkpoint knows which windows had closed", async () => {
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    const r = await scanStreamAttestations(net(rpc.url), STREAM, BigInt(99_000), { rateLimitWaitMs: 1 });
    assert.equal(r.latestBlock, BigInt(100_000));
    assert.equal(r.latestTimeMs, BigInt(CHAIN.timestamp) * BigInt(1000));
    assert.equal(r.scannedTo, BigInt(100_000));
  } finally {
    await rpc.close();
  }
});

/* Windows mode. The chain: latest block 100,000 at TS2, two seconds a block. A data manifest whose window ended 50,000 s
 * before TS2 is expected at block 75,000 (the block of that very second); fifteen minutes after it is block 75,450, two
 * minutes before it block 74,940, six hours beyond the window block 86,250. The clock answers a block just before a
 * range's first second and one just after its last, each within its tolerance, so the tests assert times, not numbers. */
const CHAIN = { latest: 100_000, timestamp: 1_760_000_000 };
const KEY5 = witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(5));
const AT5 = BigInt(CHAIN.timestamp - 50_000) * BigInt(1000);
const spec5: WindowSpec = { key: KEY5, kind: "data", n: BigInt(5), atMs: AT5 };
const TOL = Number(CLOCK_TOLERANCE_MS) / 1000;
const linear = (number: number) => CHAIN.timestamp - 2 * (CHAIN.latest - number);
const num = (hexOrDec: string | null) => Number(BigInt(hexOrDec ?? "-1"));
/** The block starts a range for `sec`: before that second, by no more than the tolerance. */
const startsAt = (block: number, sec: number, timeOf: (n: number) => number = linear) => timeOf(block) < sec && sec - timeOf(block) <= TOL;
/** The block ends a range for `sec`: after that second, by no more than the tolerance. */
const endsAt = (block: number, sec: number, timeOf: (n: number) => number = linear) => timeOf(block) > sec && timeOf(block) - sec <= TOL;
const sec = (ms: bigint) => Number(ms / BigInt(1000));

/* A real copy for the fake: an admissible data attestation under the witness key of `sequence`, in `block`. The log is
 * answered when a call's range holds the block and asks for the key's recipient; the attestation is read back by uid. */
const easAbi = parseAbi(["function getAttestation(bytes32 uid) view returns ((bytes32 uid, bytes32 schema, uint64 time, uint64 expirationTime, uint64 revocationTime, bytes32 refUID, address recipient, address attester, bool revocable, bytes data))"]);
const ATTESTED_TOPIC = "0x8bf46bf4cfd674fa735a3d63ec1c9ad4153f033c290341f3a588b75685141b35";
const ZERO32 = ("0x" + "00".repeat(32)) as `0x${string}`;
function copyOf(sequence: number, block: number, timeSec: number, attestations: Map<string, string>) {
  const key = witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(sequence));
  const start = BigInt(1_759_000_000_000) - (BigInt(1_759_000_000_000) % EPOCH_MS) + BigInt(sequence) * EPOCH_MS;
  const manifest = encodeManifest({ status: 0, sequence: BigInt(sequence), epochStartMs: start, epochEndMs: start + EPOCH_MS, recordCount: 1, streamId: STREAM, merkleRoot: new Uint8Array(32).fill(7), previousCommitment: new Uint8Array(32).fill(8), schemaHash: new Uint8Array(32).fill(9), methodologyHash: new Uint8Array(32).fill(10) });
  const { data } = easDataOf({ kind: "data", manifest, signature: new Uint8Array(65).fill(1) });
  const uid = ("0x" + sequence.toString(16).padStart(64, "0")) as `0x${string}`;
  const recipient = ("0x" + toHex(key.subarray(12))) as `0x${string}`;
  const schema = ("0x" + toHex(easSchemaUid(EAS_DATA_SCHEMA))) as `0x${string}`;
  attestations.set(uid, encodeFunctionResult({ abi: easAbi, functionName: "getAttestation", result: { uid, schema, time: BigInt(timeSec), expirationTime: BigInt(0), revocationTime: BigInt(0), refUID: ZERO32, recipient, attester: "0x00000000000000000000000000000000000000aa", revocable: false, data: ("0x" + toHex(data)) as `0x${string}` } }));
  const log = { address: "0x" + BASE_EAS_ADDRESS_HEX.replace(/^0x/, ""), topics: [ATTESTED_TOPIC, "0x" + "00".repeat(12) + recipient.slice(2), "0x" + "00".repeat(12) + "00000000000000000000000000000000000000aa", schema], data: uid, blockNumber: "0x" + block.toString(16), blockHash: "0x" + "ab".repeat(32), transactionHash: "0x" + "ef".repeat(32), transactionIndex: "0x0", logIndex: "0x0", removed: false };
  /** The logs a call gets: this copy when the range holds its block and the filter is its recipient. */
  const logsFor = (p: LogParams): unknown[] => (Number(BigInt(p.fromBlock)) <= block && block <= Number(BigInt(p.toBlock)) && String(p.topics[1]).slice(-40) === recipient.slice(2) ? [log] : []);
  return { key, logsFor };
}

test("windows mode asks for one recipient, reads from the expected time first, then the lead, then the hours beyond a window with no copy", async () => {
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5], { rateLimitWaitMs: 1 });
    assert.equal(r.windows.length, 1);
    const w = r.windows[0]!;
    assert.deepEqual({ kind: w.kind, n: w.n, found: w.found, extended: w.extended, status: w.status }, { kind: "data", n: "5", found: 0, extended: true, status: "missing" });
    const recipient = "0x" + toHex(KEY5.subarray(12));
    for (const p of rpc.logCalls) assert.equal(String(p.topics[1]).slice(-40), recipient.slice(2), "topic 1 is the witness key's recipient");
    const [forward, lead, ...beyond] = rpc.logCalls;
    assert.ok(startsAt(num(forward!.fromBlock), sec(AT5)), "the first call starts at the expected time");
    assert.ok(endsAt(num(forward!.toBlock), sec(AT5) + 900), "and runs to fifteen minutes after it");
    assert.ok(startsAt(num(lead!.fromBlock), sec(AT5) - 120), "the lead starts two minutes before the expected time");
    assert.equal(num(lead!.toBlock), num(forward!.fromBlock) - 1, "and ends right before the part already read");
    assert.equal(num(beyond[0]!.fromBlock), num(forward!.toBlock) + 1, "the extension starts right after the window");
    assert.ok(endsAt(num(beyond[beyond.length - 1]!.toBlock), sec(AT5) + 900 + 21_600), "and ends six hours beyond it");
    assert.deepEqual(beyond.slice(0, 3).map(span), [1999, 1999, 3999], "the chunk grows only after two full chunks");
    assert.equal(w.calls, 6, "one call for the window from the expected time, one for the lead, four for the 10,800-block extension");
    assert.equal(r.calls, 6);
    assert.deepEqual({ from: w.from, to: w.to }, { from: String(num(lead!.fromBlock)), to: String(num(beyond[beyond.length - 1]!.toBlock)) }, "the window reports the blocks it read");
    assert.deepEqual({ found: r.found, missing: r.missing, open: r.open, notWalked: r.notWalked, complete: r.complete, stop: r.stopReason }, { found: 0, missing: 1, open: 0, notWalked: 0, complete: true, stop: null });
    assert.deepEqual(r.copies, [{ kind: "data", n: "5", status: "missing", windows: 1, found: 0 }]);
    assert.ok(r.blockReads > 0 && r.blockReads <= 12, `four times placed on a chain with one pace: ${r.blockReads} block reads`);
  } finally {
    await rpc.close();
  }
});

test("a copy is read back, counted as found, and nothing after its chunk is read", async () => {
  // the copy lands sixty seconds after the expected time, as on the live stream: block 75,030
  const attestations = new Map<string, string>();
  const copy = copyOf(5, 75_030, linear(75_030), attestations);
  const rpc = await fakeRpc((_n, p) => (span(p) > 9 ? { error: { code: -32600, message: ALCHEMY_FREE } } : { result: copy.logsFor(p) }), { ...CHAIN, attestations });
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [{ ...spec5, key: copy.key }], { rateLimitWaitMs: 1 });
    const w = r.windows[0]!;
    assert.deepEqual({ status: w.status, found: w.found, extended: w.extended }, { status: "found", found: 1, extended: false });
    assert.deepEqual({ found: r.found, missing: r.missing, complete: r.complete }, { found: 1, missing: 0, complete: true });
    const anchors = r.byWitnessKey.get(toHex(copy.key)) ?? [];
    assert.equal(anchors.length, 1);
    assert.equal(anchors[0]!.blockNumber, BigInt(75_030));
    assert.equal(r.chunkUsed, BigInt(9), "ten blocks a call from the refusal on");
    const last = rpc.logCalls[rpc.logCalls.length - 1]!;
    assert.ok(num(last.fromBlock) <= 75_030 && 75_030 <= num(last.toBlock), "the last call is the one that holds the copy");
    assert.equal(w.to, String(num(last.toBlock)), "the window reports the chunk of the copy as its end");
    assert.ok(r.calls <= 6, `one refused call and at most five ten-block calls from the expected time to block 75,030, not the 46 of the whole window: ${r.calls}`);
    assert.ok(startsAt(num(w.from), sec(AT5)), "the lead was never read");
  } finally {
    await rpc.close();
  }
});

/* The 5 Nov 2026 incident. A chain of a million blocks: two seconds a block up to block 600,000, five blocks a second
 * (whole-second timestamps, five blocks sharing each) from there on. Counting back from the head at two seconds a block
 * puts a copy that sits 40,060 s after the change at block 980,030; it is in block 800,300. */
const CHANGE = { latest: 1_000_000, at: 600_000, timestamp: 1_762_400_000 };
const changeTime = CHANGE.timestamp - (CHANGE.latest - CHANGE.at) / 5;
const paced = (number: number) => (number >= CHANGE.at ? changeTime + Math.floor((number - CHANGE.at) / 5) : changeTime - 2 * (CHANGE.at - number));

test("a range scan that starts at a time begins half an hour of chain time before it, whatever the chain's pace", async () => {
  // five blocks a second from block 600,000 on (CHANGE below): 3,600 s before the head is block 982,000, half an hour before that 973,000
  const rpc = await fakeRpc(() => ({ result: [] }), { latest: CHANGE.latest, timestamp: CHANGE.timestamp, timeOf: paced });
  try {
    const sinceMs = BigInt(CHANGE.timestamp - 3_600) * BigInt(1000);
    const r = await scanStreamAttestations(net(rpc.url), STREAM, { timeMs: sinceMs }, { rateLimitWaitMs: 1 });
    assert.equal(r.complete, true);
    assert.ok(startsAt(Number(r.scannedFrom), CHANGE.timestamp - 3_600 - 1_800, paced), `the pass starts half an hour before the time on the chain's own clock: block ${r.scannedFrom}`);
    assert.equal(r.scannedTo, BigInt(CHANGE.latest));
    assert.equal(rpc.logCalls[0]!.fromBlock, "0x" + r.scannedFrom.toString(16));
  } finally {
    await rpc.close();
  }
});

test("a range scan that continues from a checkpoint's block rewinds by chain time, not by a count of blocks", async () => {
  const rpc = await fakeRpc(() => ({ result: [] }), { latest: CHANGE.latest, timestamp: CHANGE.timestamp, timeOf: paced });
  try {
    // an hour before block 900,000 is 18,000 blocks at five a second; before block 500,000, on the old pace, it is 1,800
    const fast = await scanStreamAttestations(net(rpc.url), STREAM, { rewindFrom: BigInt(900_000), rewindMs: BigInt(3_600_000) }, { rateLimitWaitMs: 1, maxCalls: 1 });
    assert.ok(startsAt(Number(fast.scannedFrom), paced(900_000) - 3_600, paced), `block ${fast.scannedFrom}`);
    assert.ok(900_000 - Number(fast.scannedFrom) >= 18_000);
    const slow = await scanStreamAttestations(net(rpc.url), STREAM, { rewindFrom: BigInt(500_000), rewindMs: BigInt(3_600_000) }, { rateLimitWaitMs: 1, maxCalls: 1 });
    assert.ok(startsAt(Number(slow.scannedFrom), paced(500_000) - 3_600, paced), `block ${slow.scannedFrom}`);
    assert.ok(500_000 - Number(slow.scannedFrom) <= 1_803);
    // a checkpoint block beyond the head (another endpoint's view) rewinds from the head
    const beyond = await scanStreamAttestations(net(rpc.url), STREAM, { rewindFrom: BigInt(CHANGE.latest + 50), rewindMs: BigInt(3_600_000) }, { rateLimitWaitMs: 1, maxCalls: 1 });
    assert.ok(startsAt(Number(beyond.scannedFrom), CHANGE.timestamp - 3_600, paced));
  } finally {
    await rpc.close();
  }
});

test("a range scan whose start cannot be looked up because the endpoint throttles for good is an honest nothing", async () => {
  const rpc = await fakeRpc(() => ({ result: [] }), { ...CHAIN, blockReply: () => ({ error: { code: -32000, message: "Too Many Requests" } }) });
  try {
    const r = await scanStreamAttestations(net(rpc.url), STREAM, { timeMs: AT5 }, { rateLimitWaitMs: 1, maxRateLimitWaits: 2 });
    assert.deepEqual({ complete: r.complete, stop: r.stopReason, calls: r.calls, to: r.scannedTo }, { complete: false, stop: "rate_limited", calls: 0, to: BigInt(-1) });
  } finally {
    await rpc.close();
  }
});

test("copies on both sides of a change of block time are found where the chain has them", async () => {
  const attestations = new Map<string, string>();
  const before = copyOf(11, 550_030, paced(550_030), attestations); // expected at block 550,000, sixty seconds later at two seconds a block
  const across = copyOf(12, 600_150, paced(600_150), attestations); // expected thirty seconds before the change, thirty seconds after it on the new pace
  const after = copyOf(13, 800_300, paced(800_300), attestations); // expected at block 800,000, sixty seconds later at five blocks a second
  const specs: WindowSpec[] = [
    { key: before.key, kind: "data", n: BigInt(11), atMs: BigInt(paced(550_000)) * BigInt(1000) },
    { key: across.key, kind: "data", n: BigInt(12), atMs: BigInt(changeTime - 30) * BigInt(1000) },
    { key: after.key, kind: "data", n: BigInt(13), atMs: BigInt(paced(800_000)) * BigInt(1000) },
  ];
  const rpc = await fakeRpc((_n, p) => ({ result: [...before.logsFor(p), ...across.logsFor(p), ...after.logsFor(p)] }), { latest: CHANGE.latest, timestamp: CHANGE.timestamp, timeOf: paced, attestations });
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, specs, { rateLimitWaitMs: 1 });
    assert.deepEqual(r.copies.map((c) => c.status), ["found", "found", "found"]);
    assert.deepEqual({ found: r.found, missing: r.missing, complete: r.complete }, { found: 3, missing: 0, complete: true });
    for (const [i, s] of specs.entries()) assert.ok(startsAt(num(r.windows[i]!.from), sec(s.atMs), paced), `window ${i} starts at its expected time on the chain's own clock`);
    assert.equal(r.byWitnessKey.get(toHex(after.key))![0]!.blockNumber, BigInt(800_300));
    assert.ok(r.blockReads <= 90, `six times placed across a change of pace: ${r.blockReads} block reads`);
    assert.ok(r.calls <= 6, `a call or two a copy on an endpoint without a cap: ${r.calls}`);
  } finally {
    await rpc.close();
  }
});

test("a copy that is not there is missing after the whole window and the hours beyond, on the chain's own clock", async () => {
  const at = BigInt(paced(800_000)) * BigInt(1000);
  const rpc = await fakeRpc(() => ({ result: [] }), { latest: CHANGE.latest, timestamp: CHANGE.timestamp, timeOf: paced });
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [{ key: KEY5, kind: "data", n: BigInt(5), atMs: at }], { rateLimitWaitMs: 1 });
    const w = r.windows[0]!;
    assert.deepEqual({ status: w.status, extended: w.extended }, { status: "missing", extended: true });
    assert.ok(startsAt(num(w.from), sec(at) - 120, paced), "from two minutes before the expected time");
    assert.ok(endsAt(num(w.to), sec(at) + 900 + 21_600, paced), "to six hours beyond the window");
    assert.ok(num(w.to) - num(w.from) > 112_000, "seventeen minutes and six hours at five blocks a second is more than 112,000 blocks");
  } finally {
    await rpc.close();
  }
});

test("a copy in the lead of a window placed from a Solana block time alone is found after the part from the expected time held nothing", async () => {
  // a log entry whose Solana anchor landed ten minutes after its Base copy: the copy sits 300 blocks before the expected time
  const attestations = new Map<string, string>();
  const copy = copyOf(5, 74_700, linear(74_700), attestations);
  const rpc = await fakeRpc((_n, p) => ({ result: copy.logsFor(p) }), { ...CHAIN, attestations });
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [{ ...spec5, key: copy.key, beforeMs: BigInt(1_800_000) }], { rateLimitWaitMs: 1 });
    const w = r.windows[0]!;
    assert.deepEqual({ status: w.status, found: w.found, extended: w.extended, calls: w.calls }, { status: "found", found: 1, extended: false, calls: 2 });
    assert.ok(startsAt(num(rpc.logCalls[0]!.fromBlock), sec(AT5)), "the expected time first");
    assert.ok(startsAt(num(rpc.logCalls[1]!.fromBlock), sec(AT5) - 1_800), "then the thirty minutes before it");
    assert.equal(w.from, String(num(rpc.logCalls[1]!.fromBlock)));
  } finally {
    await rpc.close();
  }
});

test("windows mode adapts to a ten-block cap and walks the whole window at that size when the copy is not there", async () => {
  const rpc = await fakeRpc((_n, p) => (span(p) > 9 ? { error: { code: -32600, message: ALCHEMY_FREE } } : { result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5], { rateLimitWaitMs: 1, extensionMs: BigInt(0) });
    const w = r.windows[0]!;
    assert.equal(w.status, "missing");
    assert.equal(w.extended, false);
    assert.equal(r.chunkUsed, BigInt(9), "ten blocks a call from the refusal on");
    const blocks = num(w.to) - num(w.from) + 1;
    assert.ok(blocks >= 512 && blocks <= 518, `two minutes before to fifteen minutes after, a block or three more on each side: ${blocks}`);
    assert.ok(r.calls >= 53 && r.calls <= 54, `one refused call, then ten blocks a call over the two parts: ${r.calls}`);
    assert.equal(r.missing, 1);
  } finally {
    await rpc.close();
  }
});

test("the window grows only on calls that exercised the whole span, so a short window never widens the next chunk", async () => {
  // three short windows succeed; the extension of the third must still start at the default 1,999 blocks, not at 9,999
  const specs: WindowSpec[] = [1, 2, 3].map((i) => ({ key: witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(i)), kind: "data", n: BigInt(i), atMs: AT5 - BigInt(i) * BigInt(3_600_000) }));
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    await scanWitnessWindows(net(rpc.url), STREAM, specs, { rateLimitWaitMs: 1 });
    const firstExtension = rpc.logCalls.find((p) => span(p) > 600);
    assert.ok(firstExtension, "an extension was walked");
    assert.equal(span(firstExtension!), 1999, "the first extension chunk is the default span: three short windows earned no growth");
    const widest = rpc.logCalls.reduce((m, p) => (span(p) > m ? span(p) : m), 0);
    assert.ok(widest <= 9999, "never beyond the ceiling");
    // every chunk wider than the default was earned by two full chunks of the previous size before it
    let earned = 1999;
    let full = 0;
    for (const p of rpc.logCalls) {
      assert.ok(span(p) <= earned, `a ${span(p)}-block chunk before it was earned (${earned})`);
      if (span(p) === earned && ++full >= 2) earned = Math.min(earned * 2 + 1, 9999);
    }
  } finally {
    await rpc.close();
  }
});

test("windows mode stops on the call budget and reports the windows after it as not walked", async () => {
  const spec6: WindowSpec = { key: witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(6)), kind: "data", n: BigInt(6), atMs: AT5 + BigInt(3_600_000) };
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    // two calls: the first window from its expected time, then its lead
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5, spec6], { rateLimitWaitMs: 1, extensionMs: BigInt(0), maxCalls: 2 });
    assert.equal(r.windows[0]!.status, "missing");
    assert.equal(r.windows[1]!.status, "not_walked");
    assert.equal(r.windows[1]!.calls, 0);
    assert.deepEqual({ from: r.windows[1]!.from, to: r.windows[1]!.to }, { from: null, to: null }, "a window the pass never reached has no range, after a budget stop as after an error");
    assert.deepEqual({ complete: r.complete, stop: r.stopReason, missing: r.missing, found: r.found, notWalked: r.notWalked }, { complete: false, stop: "max_calls", missing: 1, found: 0, notWalked: 1 });
    assert.deepEqual(r.copies.map((c) => c.status), ["missing", "not_walked"]);
  } finally {
    await rpc.close();
  }
});

test("a budget that ends before the lead was read leaves the copy not walked, never missing", async () => {
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5], { rateLimitWaitMs: 1, extensionMs: BigInt(0), maxCalls: 1 });
    const w = r.windows[0]!;
    assert.deepEqual({ status: w.status, calls: w.calls }, { status: "not_walked", calls: 1 });
    assert.ok(startsAt(num(w.from), sec(AT5)), "the lead is not part of what was read");
    assert.deepEqual({ complete: r.complete, stop: r.stopReason, missing: r.missing }, { complete: false, stop: "max_calls", missing: 0 });
  } finally {
    await rpc.close();
  }
});

test("every window with no copy gets its own extension; the call budget, not a counter, bounds the work", async () => {
  // five manifests an hour apart, all inside the fake chain (block 75,000 and 1,800 blocks earlier each)
  const specs: WindowSpec[] = [1, 2, 3, 4, 5].map((i) => ({ key: witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(i)), kind: "data", n: BigInt(i), atMs: AT5 - BigInt(i) * BigInt(3_600_000) }));
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, specs, { rateLimitWaitMs: 1 });
    assert.equal(r.windows.filter((w) => w.extended).length, 5, "the fifth late window is extended like the first");
    assert.equal(r.missing, 5);
    assert.equal(r.complete, true);
  } finally {
    await rpc.close();
  }
});

test("an error that is neither a refusal nor throttling keeps the windows walked so far and reports the rest as not walked", async () => {
  const spec6: WindowSpec = { key: witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(6)), kind: "data", n: BigInt(6), atMs: AT5 + BigInt(3_600_000) };
  const spec7: WindowSpec = { key: witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(7)), kind: "data", n: BigInt(7), atMs: AT5 + BigInt(7_200_000) };
  // from the third getLogs on the endpoint keeps failing: the first window (two calls) stands, the three retries do not help the second
  const rpc = await fakeRpc((n) => (n >= 3 ? { error: { code: -32000, message: "execution reverted" } } : { result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5, spec6, spec7], { rateLimitWaitMs: 1, extensionMs: BigInt(0) });
    assert.equal(r.windows.length, 3);
    assert.equal(r.windows[0]!.status, "missing");
    assert.equal(r.windows[1]!.status, "not_walked");
    assert.equal(r.windows[1]!.calls, 4, "one call and three retries");
    assert.equal(r.windows[2]!.status, "not_walked");
    assert.equal(r.windows[2]!.calls, 0);
    assert.deepEqual({ from: r.windows[2]!.from, to: r.windows[2]!.to }, { from: null, to: null }, "a window the pass never reached has no range");
    assert.deepEqual({ complete: r.complete, stop: r.stopReason, missing: r.missing, notWalked: r.notWalked }, { complete: false, stop: "error", missing: 1, notWalked: 2 });
    assert.match(r.error ?? "", /execution reverted/);
  } finally {
    await rpc.close();
  }
});

test("an extension the cap did not allow leaves the copy not walked, never missing", async () => {
  const spec6: WindowSpec = { key: witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(6)), kind: "data", n: BigInt(6), atMs: AT5 + BigInt(3_600_000) };
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5, spec6], { rateLimitWaitMs: 1, maxExtensions: 1 });
    assert.deepEqual(r.windows.map((w) => [w.status, w.extended]), [["missing", true], ["not_walked", false]]);
    assert.deepEqual({ missing: r.missing, notWalked: r.notWalked, complete: r.complete }, { missing: 1, notWalked: 1, complete: false });
  } finally {
    await rpc.close();
  }
});

test("a window that is still open is walked to the latest block, never extended and never called missing", async () => {
  const fresh: WindowSpec = { key: KEY5, kind: "data", n: BigInt(5), atMs: BigInt(CHAIN.timestamp - 60) * BigInt(1000) };
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [fresh], { rateLimitWaitMs: 1 });
    const w = r.windows[0]!;
    assert.deepEqual({ to: w.to, status: w.status, extended: w.extended, calls: w.calls }, { to: "100000", status: "open", extended: false, calls: 2 });
    assert.ok(startsAt(num(w.from), CHAIN.timestamp - 60 - 120), "the lead was read as well: two minutes before the expected time");
    assert.equal(rpc.logCalls[0]!.toBlock, "0x" + (100_000).toString(16), "from the expected time to the head");
    assert.deepEqual({ missing: r.missing, open: r.open, found: r.found }, { missing: 0, open: 1, found: 0 });
    assert.equal(r.copies[0]!.status, "open");
  } finally {
    await rpc.close();
  }
});

test("an extension that reaches the chain head leaves the copy open, never missing", async () => {
  // the window closed five minutes ago, but the six hours it is looked for beyond it have not passed
  const recent: WindowSpec = { key: KEY5, kind: "data", n: BigInt(5), atMs: BigInt(CHAIN.timestamp - 20 * 60) * BigInt(1000) };
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [recent], { rateLimitWaitMs: 1 });
    const w = r.windows[0]!;
    assert.deepEqual({ extended: w.extended, status: w.status, to: w.to }, { extended: true, status: "open", to: "100000" });
    assert.deepEqual({ missing: r.missing, open: r.open }, { missing: 0, open: 1 });
  } finally {
    await rpc.close();
  }
});

test("a copy with two windows is one expected copy: only its last window is extended, and the copy is missing only when both are", async () => {
  const atEnd: WindowSpec = { ...spec5 };
  const atSolana: WindowSpec = { ...spec5, atMs: AT5 + BigInt(4 * 3_600_000), beforeMs: BigInt(1_800_000) };
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [atEnd, atSolana], { rateLimitWaitMs: 1 });
    assert.equal(r.windows.length, 2);
    assert.equal(r.windows[0]!.extended, false, "the first window of the copy is not extended");
    assert.equal(r.windows[1]!.extended, true, "the last one is");
    assert.deepEqual(r.copies, [{ kind: "data", n: "5", status: "missing", windows: 2, found: 0 }]);
    assert.equal(r.missing, 1);
  } finally {
    await rpc.close();
  }
});

test("the later window of a copy an earlier window found is not read at all", async () => {
  const attestations = new Map<string, string>();
  const copy = copyOf(5, 75_030, linear(75_030), attestations);
  const atEnd: WindowSpec = { ...spec5, key: copy.key };
  const atSolana: WindowSpec = { ...atEnd, atMs: AT5 + BigInt(4 * 3_600_000), beforeMs: BigInt(1_800_000) };
  const rpc = await fakeRpc((_n, p) => ({ result: copy.logsFor(p) }), { ...CHAIN, attestations });
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [atEnd, atSolana], { rateLimitWaitMs: 1 });
    assert.deepEqual(r.windows.map((w) => [w.status, w.calls, w.from]), [["found", 1, r.windows[0]!.from], ["found", 0, null]]);
    assert.deepEqual(r.copies, [{ kind: "data", n: "5", status: "found", windows: 2, found: 1 }]);
    assert.equal(r.calls, 1);
  } finally {
    await rpc.close();
  }
});

test("an extension cut short by the budget reports the block it actually reached", async () => {
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5], { rateLimitWaitMs: 1, maxCalls: 3 });
    const w = r.windows[0]!;
    assert.deepEqual({ extended: w.extended, status: w.status, calls: w.calls }, { extended: true, status: "not_walked", calls: 3 }, "the window, its lead and one 1,999-block chunk of the extension");
    assert.equal(num(w.to), num(rpc.logCalls[0]!.toBlock) + 2000, "the window's end and the one chunk beyond it");
    assert.equal(r.stopReason, "max_calls");
  } finally {
    await rpc.close();
  }
});

test("an endpoint error in the middle of a window keeps what was read and reports where it stopped", async () => {
  // the part from the expected time is walked in ten-block chunks (a refusal first); from the third chunk on the endpoint keeps failing
  const rpc = await fakeRpc((n, p) => (span(p) > 9 ? { error: { code: -32600, message: ALCHEMY_FREE } } : n >= 4 ? { error: { code: -32000, message: "internal error" } } : { result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5], { rateLimitWaitMs: 1 });
    const w = r.windows[0]!;
    assert.deepEqual({ status: w.status, calls: w.calls }, { status: "not_walked", calls: 7 }, "two ten-block chunks were read, the third failed four times (three retries)");
    assert.ok(startsAt(num(w.from), sec(AT5)));
    assert.equal(num(w.to), num(w.from) + 19, "the last covered block is the end of the second chunk");
    assert.match(r.error ?? "", /internal error/);
    assert.equal(r.stopReason, "error");
  } finally {
    await rpc.close();
  }
});

test("a window whose end sits at the chain head within the hours beyond is open even when nothing beyond it can be read yet", async () => {
  // the window closes exactly at the head: open is false by time, the extension has no block to walk, the copy is still open
  const atHead: WindowSpec = { key: KEY5, kind: "data", n: BigInt(5), atMs: BigInt(CHAIN.timestamp - 15 * 60) * BigInt(1000) };
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [atHead], { rateLimitWaitMs: 1 });
    assert.deepEqual({ status: r.windows[0]!.status, extended: r.windows[0]!.extended, open: r.open, missing: r.missing }, { status: "open", extended: false, open: 1, missing: 0 });
  } finally {
    await rpc.close();
  }
});

test("an endpoint that fails the first block read reports every copy as not walked with the reason, never an exception", async () => {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const msg = JSON.parse(body) as { id: number; method: string };
      res.setHeader("content-type", "application/json");
      if (msg.method === "eth_chainId") return res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: "0x" + BASE_MAINNET_CHAIN_ID.toString(16) }));
      res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: "internal error" } }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const r = await scanWitnessWindows(net(url), STREAM, [spec5], { rateLimitWaitMs: 1 });
    assert.deepEqual({ complete: r.complete, stop: r.stopReason, notWalked: r.notWalked, latest: r.latestBlock }, { complete: false, stop: "error", notWalked: 1, latest: BigInt(-1) });
    assert.match(r.error ?? "", /internal error/);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("an endpoint that throttles the first block read for good reports every copy as not walked instead of ending the run", async () => {
  // a fake that answers 429 to everything
  const calls: string[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const msg = JSON.parse(body) as { id: number; method: string };
      calls.push(msg.method);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: "Too Many Requests" } }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const r = await scanWitnessWindows(net(url), STREAM, [spec5], { rateLimitWaitMs: 1, maxRateLimitWaits: 2 });
    assert.deepEqual({ complete: r.complete, stop: r.stopReason, notWalked: r.notWalked, calls: r.calls }, { complete: false, stop: "rate_limited", notWalked: 1, calls: 0 });
    assert.equal(r.windows[0]!.status, "not_walked");
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("a block read that fails while a later window is being placed keeps the windows before it and reports the rest as not walked", async () => {
  const spec6: WindowSpec = { key: witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(6)), kind: "data", n: BigInt(6), atMs: AT5 + BigInt(3_600_000) };
  // the numbered block reads the first window needs succeed; every later one fails, past the retries
  let firstWindowReads = 0;
  const probe = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    firstWindowReads = (await scanWitnessWindows(net(probe.url), STREAM, [spec5], { rateLimitWaitMs: 1, extensionMs: BigInt(0) })).blockReads;
  } finally {
    await probe.close();
  }
  const rpc = await fakeRpc(() => ({ result: [] }), { ...CHAIN, blockReply: (nth) => (nth > firstWindowReads ? { error: { code: -32000, message: "internal error" } } : null) });
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5, spec6], { rateLimitWaitMs: 1, extensionMs: BigInt(0) });
    assert.deepEqual(r.windows.map((w) => w.status), ["missing", "not_walked"]);
    assert.deepEqual({ complete: r.complete, stop: r.stopReason, missing: r.missing, notWalked: r.notWalked }, { complete: false, stop: "error", missing: 1, notWalked: 1 });
    assert.match(r.error ?? "", /internal error/);
  } finally {
    await rpc.close();
  }
});
