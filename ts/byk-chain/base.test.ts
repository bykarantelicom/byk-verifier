import assert from "node:assert/strict";
import test from "node:test";

import { chunkFromRangeRefusal, DEFAULT_LOG_CHUNK, MAX_LOG_CHUNK, MIN_LOG_CHUNK, nextChunkAfterSuccess, rateLimited } from "./base";

/* Endpoints disagree about how many blocks one eth_getLogs may span and about how they say so. Base Sepolia
 * answers 10,000, Base mainnet refuses above 2,000. The scan has to read the number out of the refusal when
 * there is one and back off blindly when there is not, because the independent verifier is the whole claim. */
test("a range refusal is turned into a narrower window", () => {
  const big = BigInt(9_999);
  assert.equal(chunkFromRangeRefusal("eth_getLogs is limited to a 2,000 range", big), BigInt(1_999), "base mainnet");
  assert.equal(chunkFromRangeRefusal("eth_getLogs is limited to a 10000 range", big), BigInt(4_999), "a stated limit we already respect means the refusal was about something else: halve");
  assert.equal(chunkFromRangeRefusal("block range is too large", big), BigInt(4_999), "no number stated: halve");
  assert.equal(chunkFromRangeRefusal("query returned more than 10000 results", big), BigInt(4_999), "a result-count limit is not a block count: halve");
  assert.equal(chunkFromRangeRefusal("You can make eth_getLogs requests with up to 1000 blocks", big), BigInt(999));
  assert.equal(chunkFromRangeRefusal("range exceeds max", big), BigInt(4_999));
});

/* Wordings met on live endpoints on 18 Oct 2026 while looking for a Base endpoint an outside reader can afford. */
test("the refusals of the keyed and the public endpoints are read for their number", () => {
  const big = BigInt(9_999);
  assert.equal(chunkFromRangeRefusal("Under the Free tier plan, you can make eth_getLogs requests with up to a 10 block range. Based on your parameters, this block range should work: [0x325230a, 0x3252313]. Upgrade to PAYG for expanded block range.", big), BigInt(9), "alchemy free tier: ten blocks, a span of nine");
  assert.equal(chunkFromRangeRefusal("eth_getLogs is limited to 0 - 50 blocks range", big), BigInt(49), "1rpc: the upper bound, not the zero");
  assert.equal(chunkFromRangeRefusal("Block range too large: maximum allowed is 50 blocks on your current plan. Upgrade your subscription at https://nodies.app", big), BigInt(49), "nodies");
  assert.equal(chunkFromRangeRefusal("Requested range is over limit of 100", big), BigInt(99), "tatum");
  assert.equal(chunkFromRangeRefusal("HTTP request failed.\n\nStatus: 400\nURL: https://base.drpc.org\nRequest body: {}", big), null, "a bare 400 says nothing about the range: it surfaces instead of pinning the window");
  assert.equal(chunkFromRangeRefusal("You can make eth_getLogs requests with up to a 2K block range", big), BigInt(1_999), "an abbreviated limit");
  assert.equal(chunkFromRangeRefusal("eth_getLogs is limited to a 10k blocks range", big), BigInt(4_999), "10k is the ceiling already: halve");
  assert.equal(chunkFromRangeRefusal("Requested range is over limit of 100", BigInt(9)), BigInt(9), "at the floor the next refusal surfaces (the caller sees no narrower window)");
  assert.equal(chunkFromRangeRefusal("Block range limit exceeded. Max range: 10000", big), BigInt(4_999), "a limit we already respect: halve");
  assert.equal(chunkFromRangeRefusal("Block range limit exceeded. Max range: 5000", big), BigInt(4_999), "stated, and under the window");
  assert.equal(chunkFromRangeRefusal("query exceeds max block range 2000", big), BigInt(1_999));
  assert.equal(chunkFromRangeRefusal("invalid block range, max 1000 blocks", big), BigInt(999));
  assert.equal(chunkFromRangeRefusal("eth_getLogs: maximum block range is 3000", big), BigInt(2_999));
  assert.equal(chunkFromRangeRefusal("invalid block range", big), null, "without a number this wording also means a toBlock beyond a lagging backend's head: it surfaces");
  assert.equal(chunkFromRangeRefusal("block range limit exceeded", big), BigInt(4_999), "unambiguous even without a number: halve");
});

test("anything that is not a range refusal is left alone, and the window has a floor", () => {
  assert.equal(chunkFromRangeRefusal("connection reset by peer", BigInt(9_999)), null);
  assert.equal(chunkFromRangeRefusal("429 Too Many Requests", BigInt(9_999)), null);
  assert.equal(chunkFromRangeRefusal("", BigInt(9_999)), null);
  assert.equal(chunkFromRangeRefusal("block range is too large", BigInt(200)), BigInt(100), "halved while above the floor");
  assert.equal(chunkFromRangeRefusal("block range is too large", BigInt(12)), MIN_LOG_CHUNK, "never narrower than the floor");
  assert.equal(chunkFromRangeRefusal("eth_getLogs is limited to a 5 range", BigInt(9)), MIN_LOG_CHUNK, "a stated limit under the floor stays at the floor");
  assert.equal(MIN_LOG_CHUNK, BigInt(9), "ten blocks, the smallest cap met on a live endpoint");
});

test("the log window grows after consecutive successes and respects the ceiling the RPC stated", () => {
  assert.equal(nextChunkAfterSuccess(DEFAULT_LOG_CHUNK, 1, MAX_LOG_CHUNK), DEFAULT_LOG_CHUNK, "one success: no growth yet");
  assert.equal(nextChunkAfterSuccess(DEFAULT_LOG_CHUNK, 2, MAX_LOG_CHUNK), BigInt(3_999), "two successes: doubled plus one");
  assert.equal(nextChunkAfterSuccess(BigInt(3_999), 3, MAX_LOG_CHUNK), BigInt(7_999));
  assert.equal(nextChunkAfterSuccess(BigInt(7_999), 4, MAX_LOG_CHUNK), MAX_LOG_CHUNK, "capped at the ceiling");
  assert.equal(nextChunkAfterSuccess(MAX_LOG_CHUNK, 9, MAX_LOG_CHUNK), MAX_LOG_CHUNK, "stays at the ceiling");
  assert.equal(nextChunkAfterSuccess(BigInt(1_999), 5, BigInt(1_999)), BigInt(1_999), "a refused 2,000 range pins the window at 1,999 for good");
});

/* Throttling comes in several shapes: a text, an HTTP status, a JSON-RPC error code in a 200 body (Alchemy's free tier,
 * 18 Oct 2026: "exceeded its compute units per second capacity" with code 429), sometimes a cause below the error. */
test("a throttle is recognised by its wording, its status or its code, wherever the code sits", () => {
  assert.equal(rateLimited(new Error("request limit reached")), true);
  assert.equal(rateLimited(new Error("HTTP request failed.\n\nStatus: 429")), true);
  assert.equal(rateLimited(Object.assign(new Error("RPC Request failed.\n\nDetails: Your app has exceeded its compute units per second capacity. If you have retries enabled, you can safely ignore this message."), { code: 429 })), true);
  assert.equal(rateLimited(Object.assign(new Error("RPC Request failed."), { code: 429 })), true, "the code alone");
  assert.equal(rateLimited(Object.assign(new Error("RPC Request failed."), { code: -32005 })), true, "limit exceeded");
  assert.equal(rateLimited(Object.assign(new Error("wrapped"), { cause: Object.assign(new Error("inner"), { status: 429 }) })), true, "the status on the cause");
  assert.equal(rateLimited(new Error("execution reverted")), false);
  assert.equal(rateLimited(new Error("HTTP request failed.\nURL: https://x.y/v2/429abc\nRequest body: {\"fromBlock\":\"0x3252429\"}\n\nDetails: fetch failed")), false, "a 429 inside the URL or the request body is not a throttle");
  assert.equal(rateLimited(new Error("HTTP request failed.\n\nStatus: 500")), false);
  assert.equal(chunkFromRangeRefusal("HTTP request failed.\nURL: https://x.y/\nRequest body: {\"params\":[{\"topics\":[\"0xrange exceeds max\"]}]}\n\nDetails: fetch failed", BigInt(9_999)), null, "words inside the quoted request are not read");
  assert.equal(rateLimited(Object.assign(new Error("RPC Request failed."), { code: -32000 })), false);
  assert.equal(rateLimited(null), false);
});
