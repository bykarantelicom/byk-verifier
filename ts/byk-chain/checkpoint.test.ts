import assert from "node:assert/strict";
import { test } from "node:test";

import { fromHex, toHex } from "../index";
import { alHeadChanged, CHECKPOINT_BASE_REWIND, checkpointBaseFrom, checkpointCommitment, checkpointWindowsThrough, parseCheckpoint } from "./checkpoint";

const STREAM = "46b69e107bc75175e86a336662311c6e198bbf0dab271c06bc5248888238f66d";
const C = "7bd7b325533b50e7952e101b88434f638df912436bd6cf674523636406f52436";
const ok = { stream_id: STREAM, network: "mainnet", sequence: "631", commitment: C, base_scanned_to: "52700000", al_head: { log_seq: "1", entry_hash: C } };

test("reader checkpoint: a valid file parses, the commitment is bytes, the Base scan rewinds an hour", () => {
  const cp = parseCheckpoint(JSON.stringify(ok), STREAM, "mainnet");
  assert.equal(cp.sequence, "631");
  assert.equal(toHex(checkpointCommitment(cp)), C);
  assert.equal(checkpointBaseFrom(cp), BigInt(52700000) - CHECKPOINT_BASE_REWIND);
  assert.equal(checkpointBaseFrom(parseCheckpoint(JSON.stringify({ ...ok, base_scanned_to: null }), STREAM, "mainnet")), null);
  assert.equal(checkpointBaseFrom(parseCheckpoint(JSON.stringify({ ...ok, base_scanned_to: "100" }), STREAM, "mainnet")), BigInt(0));
  assert.equal(toHex(checkpointCommitment(parseCheckpoint(JSON.stringify({ ...ok, commitment: "0x" + C.toUpperCase() }), STREAM, "mainnet"))), C);
});

test("reader checkpoint: the windows-mode fields are optional, kept when well formed and refused when not", () => {
  const cp = parseCheckpoint(JSON.stringify({ ...ok, base_windows_through: "8587", base_fixed_windows: true }), STREAM, "mainnet");
  assert.equal(cp.base_windows_through, "8587");
  assert.equal(cp.base_fixed_windows, true);
  assert.equal(checkpointWindowsThrough(cp), BigInt(8587));
  assert.equal(checkpointWindowsThrough(parseCheckpoint(JSON.stringify(ok), STREAM, "mainnet")), BigInt(-1), "no field: every due sequence gets a window");
  assert.equal(parseCheckpoint(JSON.stringify({ ...ok, base_windows_through: null }), STREAM, "mainnet").base_windows_through, null);
  assert.equal(checkpointWindowsThrough(parseCheckpoint(JSON.stringify({ ...ok, base_windows_through: null }), STREAM, "mainnet")), BigInt(-1));
  assert.equal(parseCheckpoint(JSON.stringify(ok), STREAM, "mainnet").base_fixed_windows, undefined, "a file from before windows mode still parses");
  assert.throws(() => parseCheckpoint(JSON.stringify({ ...ok, base_windows_through: "x" }), STREAM, "mainnet"), /base_windows_through is malformed/);
  assert.throws(() => parseCheckpoint(JSON.stringify({ ...ok, base_fixed_windows: "yes" }), STREAM, "mainnet"), /base_fixed_windows is malformed/);
});

test("reader checkpoint: every malformed file is refused with the file named, never a bare TypeError", () => {
  const label = "--checkpoint cp.json";
  for (const [text, re] of [
    ["null", /could not be read: not a JSON object/],
    ["[]", /not a JSON object/],
    ["42", /not a JSON object/],
    ["{not json", /could not be read/],
    [JSON.stringify({ ...ok, stream_id: "00".repeat(32) }), /belongs to stream/],
    [JSON.stringify({ ...ok, network: "devnet" }), /on devnet, not to this run/],
    [JSON.stringify({ ...ok, sequence: "-1" }), /sequence or commitment is malformed/],
    [JSON.stringify({ ...ok, sequence: "6.5" }), /sequence or commitment is malformed/],
    [JSON.stringify({ ...ok, commitment: C.slice(0, 60) }), /sequence or commitment is malformed/],
    [JSON.stringify({ ...ok, base_scanned_to: "later" }), /base_scanned_to is malformed/],
    [JSON.stringify({ ...ok, al_head: { log_seq: "x", entry_hash: C } }), /al_head is malformed/],
    [JSON.stringify({ ...ok, al_head: "head" }), /al_head is malformed/],
  ] as const) {
    assert.throws(() => parseCheckpoint(text, STREAM, "mainnet", label), (e: unknown) => e instanceof Error && re.test(e.message) && e.message.includes("cp.json"), text.slice(0, 40));
  }
});

test("reader checkpoint: an authorization log head other than the recorded one refuses the checkpoint", () => {
  const cp = parseCheckpoint(JSON.stringify(ok), STREAM, "mainnet");
  assert.equal(alHeadChanged(cp, { logSeq: BigInt(1), entryHash: fromHex(C) }), null);
  assert.match(alHeadChanged(cp, { logSeq: BigInt(2), entryHash: fromHex(C) }) ?? "", /differs from the one the checkpoint recorded/);
  assert.match(alHeadChanged(cp, { logSeq: BigInt(1), entryHash: fromHex("11".repeat(32)) }) ?? "", /run a full verification/);
  assert.equal(alHeadChanged(parseCheckpoint(JSON.stringify({ ...ok, al_head: null }), STREAM, "mainnet"), { logSeq: BigInt(9), entryHash: fromHex(C) }), null);
});
