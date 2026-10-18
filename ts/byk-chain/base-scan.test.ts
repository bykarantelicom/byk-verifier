/* scanStreamAttestations and scanWitnessWindows against a fake Base JSON-RPC (2026-10-18): a throttled endpoint ends in an
 * honest incomplete scan with its reason instead of an exception, a transient throttle is waited out, a clean pass covers
 * every block, an error that is not throttling still surfaces; windows mode places each expected copy from its Solana time,
 * asks for one recipient, adapts to a ten-block cap, extends a window with no copy, leaves an open window alone, stops on
 * the budget and corrects a clock drift. The fake answers eth_chainId, eth_getBlockByNumber and eth_getLogs only, with
 * blocks exactly two seconds apart like Base. */
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { test } from "node:test";

import { BASE_EAS_ADDRESS_HEX, BASE_MAINNET_CHAIN_ID, fromHex, toHex, WITNESS_KIND, witnessKey } from "../index";
import { type BaseNetwork, scanStreamAttestations, scanWitnessWindows, type WindowSpec } from "./base";

const STREAM = fromHex("46b69e107bc75175e86a336662311c6e198bbf0dab271c06bc5248888238f66d");
const LATEST = 0x20;
const TS = 0x68f3a000;
const blockTemplate = { hash: "0x" + "ab".repeat(32), parentHash: "0x" + "cd".repeat(32), nonce: "0x0000000000000000", difficulty: "0x0", gasLimit: "0x1c9c380", gasUsed: "0x0", miner: "0x" + "00".repeat(20), extraData: "0x", size: "0x200", sha3Uncles: "0x" + "00".repeat(32), stateRoot: "0x" + "00".repeat(32), receiptsRoot: "0x" + "00".repeat(32), transactionsRoot: "0x" + "00".repeat(32), logsBloom: "0x" + "00".repeat(256), transactions: [], uncles: [], mixHash: "0x" + "00".repeat(32), baseFeePerGas: "0x1" };

type LogParams = { fromBlock: string; toBlock: string; topics: Array<string | string[] | null> };
type Reply = { result: unknown } | { error: { code: number; message: string } };
type Rpc = { server: Server; url: string; calls: string[]; logCalls: LogParams[]; close: () => Promise<void> };
type Chain = { latest?: number; timestamp?: number; skewSec?: number };
function fakeRpc(getLogs: (n: number, p: LogParams) => Reply, chain: Chain = {}): Promise<Rpc> {
  const latest = chain.latest ?? LATEST;
  const ts = chain.timestamp ?? TS;
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
        // a numbered block is exactly two seconds per block behind the latest one, plus the skew a test asks for
        const timestamp = number === latest && tag !== "latest" ? ts : tag === "latest" ? ts : ts - 2 * (latest - number) + (chain.skewSec ?? 0);
        return reply({ result: { ...blockTemplate, number: "0x" + number.toString(16), timestamp: "0x" + timestamp.toString(16) } });
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
 * before TS2 is expected at block 75,000; its window runs from two minutes before (block 74,940) to fifteen minutes after
 * (block 75,450), and a copy that is not there is looked for six more hours ahead (to block 86,250). */
const CHAIN = { latest: 100_000, timestamp: 1_760_000_000 };
const KEY5 = witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(5));
const AT5 = BigInt(CHAIN.timestamp - 50_000) * BigInt(1000);
const spec5: WindowSpec = { key: KEY5, kind: "data", n: BigInt(5), atMs: AT5 };

test("windows mode asks for one recipient inside the expected range and extends a window with no copy", async () => {
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5], { rateLimitWaitMs: 1 });
    assert.equal(r.windows.length, 1);
    const w = r.windows[0]!;
    assert.deepEqual({ kind: w.kind, n: w.n, from: w.from, to: w.to, found: w.found, extended: w.extended, status: w.status }, { kind: "data", n: "5", from: "74940", to: "86250", found: 0, extended: true, status: "missing" });
    assert.equal(w.calls, 5, "one call for the 511-block window (too short to grow the chunk), four for the 10,800-block extension: 1,999 twice, then 3,999, then the rest");
    assert.equal(r.calls, 5);
    assert.deepEqual({ found: r.found, missing: r.missing, open: r.open, notWalked: r.notWalked, complete: r.complete, stop: r.stopReason, drift: r.driftBlocks }, { found: 0, missing: 1, open: 0, notWalked: 0, complete: true, stop: null, drift: BigInt(0) });
    assert.deepEqual(r.copies, [{ kind: "data", n: "5", status: "missing", windows: 1, found: 0 }]);
    const recipient = "0x" + toHex(KEY5.subarray(12));
    for (const p of rpc.logCalls) assert.equal(String(p.topics[1]).slice(-40), recipient.slice(2), "topic 1 is the witness key's recipient");
    assert.equal(rpc.logCalls[0]!.fromBlock, "0x" + (74_940).toString(16));
    assert.equal(rpc.logCalls[0]!.toBlock, "0x" + (75_450).toString(16));
    assert.equal(rpc.logCalls[1]!.fromBlock, "0x" + (75_451).toString(16), "the extension starts right after the window");
    assert.equal(rpc.logCalls[4]!.toBlock, "0x" + (86_250).toString(16));
    assert.deepEqual(rpc.logCalls.slice(1).map(span), [1999, 1999, 3999, 2799], "the chunk grows only after two full chunks");
  } finally {
    await rpc.close();
  }
});

test("windows mode adapts to a ten-block cap and walks the whole window at that size", async () => {
  const rpc = await fakeRpc((_n, p) => (span(p) > 9 ? { error: { code: -32600, message: ALCHEMY_FREE } } : { result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5], { rateLimitWaitMs: 1, extensionMs: BigInt(0) });
    const w = r.windows[0]!;
    assert.equal(w.status, "missing");
    assert.equal(w.extended, false);
    assert.equal(r.chunkUsed, BigInt(9), "ten blocks a call from the refusal on");
    assert.equal(r.calls, 53, "one refused call, then 52 calls of ten blocks for 511 blocks");
    assert.equal(rpc.logCalls[rpc.logCalls.length - 1]!.toBlock, "0x" + (75_450).toString(16), "the window is walked to its end");
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
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5, spec6], { rateLimitWaitMs: 1, extensionMs: BigInt(0), maxCalls: 1 });
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

test("a window placed from a Solana block time alone starts thirty minutes earlier, and a spec near the head never calibrates the drift", async () => {
  const fixed: WindowSpec = { ...spec5, kind: "al", n: BigInt(1), beforeMs: BigInt(1_800_000) };
  const nearHead: WindowSpec = { key: KEY5, kind: "data", n: BigInt(9), atMs: BigInt(CHAIN.timestamp - 60) * BigInt(1000) };
  const rpc = await fakeRpc(() => ({ result: [] }), { ...CHAIN, skewSec: 100 });
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [nearHead, fixed], { rateLimitWaitMs: 1, extensionMs: BigInt(0) });
    assert.equal(r.driftBlocks, BigInt(50), "calibrated on the second spec, the one well behind the head");
    assert.equal(r.windows[1]!.from, "74050", "block 75,000 minus 900 blocks of lead minus the drift");
    assert.equal(r.windows[1]!.to, "75400");
  } finally {
    await rpc.close();
  }
});

test("an error that is neither a refusal nor throttling keeps the windows walked so far and reports the rest as not walked", async () => {
  const spec6: WindowSpec = { key: witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(6)), kind: "data", n: BigInt(6), atMs: AT5 + BigInt(3_600_000) };
  const spec7: WindowSpec = { key: witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(7)), kind: "data", n: BigInt(7), atMs: AT5 + BigInt(7_200_000) };
  // from the second getLogs on the endpoint keeps failing: the three retries do not help, the first window stands
  const rpc = await fakeRpc((n) => (n >= 2 ? { error: { code: -32000, message: "execution reverted" } } : { result: [] }), CHAIN);
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
    assert.deepEqual({ from: w.from, to: w.to, status: w.status, extended: w.extended, calls: w.calls }, { from: "99910", to: "100000", status: "open", extended: false, calls: 1 });
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

test("an extension cut short by the budget reports the block it actually reached", async () => {
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5], { rateLimitWaitMs: 1, maxCalls: 2 });
    const w = r.windows[0]!;
    assert.deepEqual({ extended: w.extended, status: w.status, to: w.to, calls: w.calls }, { extended: true, status: "not_walked", to: "77450", calls: 2 }, "the window and one 1,999-block chunk of the extension");
    assert.equal(r.stopReason, "max_calls");
  } finally {
    await rpc.close();
  }
});

test("an endpoint error in the middle of a window keeps what was read and reports where it stopped", async () => {
  // the window 74,940 to 75,450 is walked in ten-block chunks (a refusal first); from the third chunk on the endpoint keeps failing
  const rpc = await fakeRpc((n, p) => (span(p) > 9 ? { error: { code: -32600, message: ALCHEMY_FREE } } : n >= 4 ? { error: { code: -32000, message: "internal error" } } : { result: [] }), CHAIN);
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5], { rateLimitWaitMs: 1 });
    const w = r.windows[0]!;
    assert.deepEqual({ status: w.status, to: w.to, calls: w.calls }, { status: "not_walked", to: "74959", calls: 7 }, "two ten-block chunks were read, the third failed four times (three retries): the last covered block is 74,959");
    assert.equal(w.from, "74940");
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

test("a probe that disagrees with the arithmetic by more than an hour is rejected and reported", async () => {
  const rpc = await fakeRpc(() => ({ result: [] }), { ...CHAIN, skewSec: 7_200 });
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5], { rateLimitWaitMs: 1, extensionMs: BigInt(0) });
    assert.equal(r.driftBlocks, BigInt(0));
    assert.equal(r.driftRejected, BigInt(3_600));
    assert.equal(r.windows[0]!.from, "74940", "placed by the arithmetic alone");
  } finally {
    await rpc.close();
  }
});

test("an endpoint that fails the first block read reports every copy as not walked with the reason, never an exception", async () => {
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  await rpc.close();
  const { createServer } = await import("node:http");
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
  const rpc = await fakeRpc(() => ({ result: [] }), CHAIN);
  await rpc.close();
  // a fake that answers 429 to everything
  const throttled = await (async () => {
    const calls: string[] = [];
    const { createServer } = await import("node:http");
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
    const addr = server.address() as { port: number };
    return { url: `http://127.0.0.1:${addr.port}`, calls, close: () => new Promise<void>((r) => server.close(() => r())) };
  })();
  try {
    const r = await scanWitnessWindows(net(throttled.url), STREAM, [spec5], { rateLimitWaitMs: 1, maxRateLimitWaits: 2 });
    assert.deepEqual({ complete: r.complete, stop: r.stopReason, notWalked: r.notWalked, calls: r.calls }, { complete: false, stop: "rate_limited", notWalked: 1, calls: 0 });
    assert.equal(r.windows[0]!.status, "not_walked");
  } finally {
    await throttled.close();
  }
});

test("a chain whose blocks are later than the arithmetic says moves every window back by the drift", async () => {
  const rpc = await fakeRpc(() => ({ result: [] }), { ...CHAIN, skewSec: 100 });
  try {
    const r = await scanWitnessWindows(net(rpc.url), STREAM, [spec5], { rateLimitWaitMs: 1, extensionMs: BigInt(0) });
    assert.equal(r.driftBlocks, BigInt(50), "100 s of skew is 50 blocks");
    assert.equal(r.windows[0]!.from, "74890");
    assert.equal(r.windows[0]!.to, "75400");
  } finally {
    await rpc.close();
  }
});
