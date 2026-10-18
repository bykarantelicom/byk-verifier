import assert from "node:assert/strict";
import test from "node:test";

import { endpointHost, oneLine, redactUrls } from "./redact";

/* The verifier's output is committed to a public repository by the daily run; a keyed endpoint must never appear in it. */
test("a key in the path, the query or the userinfo never survives", () => {
  assert.equal(redactUrls("URL: https://base-mainnet.g.alchemy.com/v2/AbCd-EfGh_1234"), "URL: https://base-mainnet.g.alchemy.com/[redacted]");
  assert.equal(redactUrls("request to https://mainnet.helius-rpc.com/?api-key=0000-1111 failed"), "request to https://mainnet.helius-rpc.com/[redacted] failed");
  assert.equal(redactUrls("http://user:secret@rpc.example.org:8545/x?y=1 and https://a.b/c#frag"), "http://rpc.example.org:8545/[redacted] and https://a.b/[redacted]");
  assert.equal(redactUrls('{"url":"https://base.example/v3/KEY"}'), '{"url":"https://base.example/[redacted]"}');
  assert.equal(redactUrls("URL: wss://base-mainnet.g.alchemy.com/v2/KEY"), "URL: wss://base-mainnet.g.alchemy.com/[redacted]", "the websocket transport carries the same key");
});

test("redacting twice changes nothing more", () => {
  const once = redactUrls("URL: https://base-mainnet.g.alchemy.com/v2/KEY and wss://a.b/c?k=1 and https://plain.host");
  assert.equal(redactUrls(once), once);
  assert.equal(once, "URL: https://base-mainnet.g.alchemy.com/[redacted] and wss://a.b/[redacted] and https://plain.host");
  assert.equal(oneLine(redactUrls("x https://h.i/j k")), "x https://h.i/[redacted] k");
});

test("text without a URL and a bare host are left alone", () => {
  assert.equal(redactUrls("request limit reached"), "request limit reached");
  assert.equal(redactUrls("read from https://api.mainnet-beta.solana.com"), "read from https://api.mainnet-beta.solana.com", "nothing was cut, nothing is marked");
  assert.equal(redactUrls("https://mainnet.base.org/ failed"), "https://mainnet.base.org failed", "a bare slash hides nothing");
  assert.equal(redactUrls(""), "");
});

test("the read-from line names the host only", () => {
  assert.equal(endpointHost("https://base-mainnet.g.alchemy.com/v2/AbCd"), "base-mainnet.g.alchemy.com");
  assert.equal(endpointHost("https://mainnet.helius-rpc.com/?api-key=0000"), "mainnet.helius-rpc.com");
  assert.equal(endpointHost("not a url https://x.y/z?k=1"), "not a url https://x.y/[redacted]");
});

test("a log line is one line, cut to its length, with its URLs cut to their host", () => {
  assert.equal(oneLine("RPC Request failed.\n\nURL: https://base-mainnet.g.alchemy.com/v2/KEY\nRequest body: {}\n\nDetails: boom"), "RPC Request failed. URL: https://base-mainnet.g.alchemy.com/[redacted] Request body: {} Details: boom");
  assert.equal(oneLine("a".repeat(300), 10), "aaaaaaaaaa");
  assert.equal(oneLine("  spaced   out  "), "spaced out");
});
