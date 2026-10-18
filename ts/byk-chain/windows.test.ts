import assert from "node:assert/strict";
import { test } from "node:test";

import { fromHex, WITNESS_KIND, witnessKey } from "../index";
import { type CopyResult, FIXED_WINDOW_BEFORE_MS } from "./base";
import { checkpointSequence, dataCopyWindows, fixedCopyWindow, windowsMarks } from "./windows";

const STREAM = fromHex("46b69e107bc75175e86a336662311c6e198bbf0dab271c06bc5248888238f66d");
const DAY = BigInt(86_400_000);
const E = BigInt(300_000);
const MIDNIGHT = BigInt(20_714) * DAY;
const key = (n: number) => witnessKey(STREAM, WITNESS_KIND.DATA, BigInt(n));
const s = (ms: bigint) => Number(ms / BigInt(1000));

/* Where the Base copy of a manifest is looked for: at the window end, reaching to a Solana anchor that landed soon after;
 * a second window at a Solana anchor that landed much later; none when the engine would not have planned a copy. */
test("a daily manifest gets one window at its window end, stretched to a Solana anchor that landed within reach", () => {
  const w = dataCopyWindows(key(7), BigInt(7), { epochStartMs: MIDNIGHT - E, epochEndMs: MIDNIGHT }, [s(MIDNIGHT) + 53]);
  assert.equal(w.length, 1);
  assert.deepEqual({ atMs: w[0]!.atMs, untilMs: w[0]!.untilMs, beforeMs: w[0]!.beforeMs }, { atMs: MIDNIGHT, untilMs: MIDNIGHT + BigInt(53_000), beforeMs: undefined });
  const early = dataCopyWindows(key(7), BigInt(7), { epochStartMs: MIDNIGHT - E, epochEndMs: MIDNIGHT }, [s(MIDNIGHT) - 40]);
  assert.deepEqual({ atMs: early[0]!.atMs, untilMs: early[0]!.untilMs }, { atMs: MIDNIGHT - BigInt(40_000), untilMs: MIDNIGHT }, "a block time before the window end (clock skew) moves the start, never the end");
  assert.equal(dataCopyWindows(key(8), BigInt(8), { epochStartMs: MIDNIGHT, epochEndMs: MIDNIGHT + E }, [s(MIDNIGHT + E)]).length, 0, "the first window of the day: no copy expected");
});

test("a Solana anchor that landed hours after the window end stretches the one window to it, so nothing in between is skipped", () => {
  const late = MIDNIGHT + BigInt(4) * BigInt(3_600_000);
  const w = dataCopyWindows(key(0), BigInt(0), { epochStartMs: MIDNIGHT, epochEndMs: MIDNIGHT + E }, [s(late), s(late) + 20]);
  assert.equal(w.length, 1);
  assert.deepEqual({ atMs: w[0]!.atMs, untilMs: w[0]!.untilMs, beforeMs: w[0]!.beforeMs }, { atMs: MIDNIGHT + E, untilMs: late + BigInt(20_000), beforeMs: undefined });
});

test("without a Solana block time the window end alone places the copy; outside the planning horizon none is expected", () => {
  const w = dataCopyWindows(key(7), BigInt(7), { epochStartMs: MIDNIGHT - E, epochEndMs: MIDNIGHT }, []);
  assert.equal(w.length, 1);
  assert.deepEqual({ atMs: w[0]!.atMs, untilMs: w[0]!.untilMs }, { atMs: MIDNIGHT, untilMs: MIDNIGHT });
  const stale = s(MIDNIGHT + BigInt(4) * DAY);
  assert.equal(dataCopyWindows(key(7), BigInt(7), { epochStartMs: MIDNIGHT - E, epochEndMs: MIDNIGHT }, [stale]).length, 0, "anchored four days after a midnight window: the engine planned no Base copy");
  assert.equal(dataCopyWindows(key(0), BigInt(0), { epochStartMs: MIDNIGHT, epochEndMs: MIDNIGHT + E }, [stale]).length, 1, "the genesis manifest is always expected");
});

test("a genesis or log copy is placed around its Solana block time with the long lead, or not at all without one", () => {
  const g = witnessKey(STREAM, WITNESS_KIND.GENESIS, BigInt(0));
  const w = fixedCopyWindow(g, "genesis", BigInt(0), [1_000, 1_030]);
  assert.deepEqual({ atMs: w?.atMs, untilMs: w?.untilMs, beforeMs: w?.beforeMs, kind: w?.kind }, { atMs: BigInt(1_000_000), untilMs: BigInt(1_030_000), beforeMs: FIXED_WINDOW_BEFORE_MS, kind: "genesis" });
  assert.equal(fixedCopyWindow(g, "genesis", BigInt(0), []), null);
});

/* Where the checkpoint stops: before the first data copy that is open or not walked, never behind the seed, never held by
 * a copy that is missing. */
const copy = (n: number, status: CopyResult["status"], kind: CopyResult["kind"] = "data"): CopyResult => ({ kind, n: String(n), status, windows: 1, found: status === "found" ? 1 : 0 });
test("the checkpoint stops before the first copy that was not walked to the end, and never behind the seed", () => {
  assert.deepEqual(checkpointSequence(BigInt(100), null, [copy(10, "found"), copy(40, "missing"), copy(70, "found")]), { sequence: BigInt(100), heldBy: null }, "missing copies do not hold");
  assert.deepEqual(checkpointSequence(BigInt(100), null, [copy(10, "found"), copy(40, "not_walked"), copy(70, "not_walked")]), { sequence: BigInt(39), heldBy: BigInt(40) });
  assert.deepEqual(checkpointSequence(BigInt(100), null, [copy(10, "found"), copy(99, "open")]), { sequence: BigInt(98), heldBy: BigInt(99) }, "an open window at the head holds one sequence");
  assert.deepEqual(checkpointSequence(BigInt(100), BigInt(60), [copy(61, "open")]), { sequence: BigInt(60), heldBy: BigInt(61) }, "held at the seed: carried forward");
  assert.deepEqual(checkpointSequence(BigInt(100), BigInt(60), [copy(60, "not_walked")]), { sequence: BigInt(60), heldBy: BigInt(60) }, "never behind the seed");
  assert.deepEqual(checkpointSequence(BigInt(100), null, [copy(0, "not_walked", "genesis"), copy(1, "open", "al")]), { sequence: BigInt(100), heldBy: null }, "genesis and log copies never hold the sequence");
  assert.deepEqual(checkpointSequence(BigInt(100), null, null), { sequence: BigInt(100), heldBy: null });
});

/* The marks a checkpoint carries forward. */
test("the windows marks follow the copies walked, never move back, and a range scan from genesis sets them", () => {
  const base = { cpSequence: BigInt(100), throughBefore: BigInt(-1), fixedBefore: false, unplacedFixed: 0, rangeCovered: null };
  assert.deepEqual(windowsMarks({ ...base, copies: [copy(0, "found", "genesis"), copy(1, "found", "al"), copy(40, "found"), copy(70, "missing")] }), { through: BigInt(70), fixed: true });
  assert.deepEqual(windowsMarks({ ...base, copies: [copy(0, "found", "genesis"), copy(40, "found"), copy(70, "not_walked")], cpSequence: BigInt(69) }), { through: BigInt(40), fixed: true });
  assert.deepEqual(windowsMarks({ ...base, copies: [copy(0, "not_walked", "genesis"), copy(40, "found")] }), { through: BigInt(40), fixed: false }, "a genesis copy not walked: the fixed mark stays off");
  assert.deepEqual(windowsMarks({ ...base, copies: [copy(40, "found")], unplacedFixed: 1 }), { through: BigInt(40), fixed: false }, "a genesis copy that could not be placed: the fixed mark stays off");
  assert.deepEqual(windowsMarks({ ...base, copies: [copy(40, "found")], fixedBefore: true }), { through: BigInt(40), fixed: true }, "skipped because an earlier run walked them: the mark holds");
  assert.deepEqual(windowsMarks({ ...base, copies: [copy(40, "found")], throughBefore: BigInt(90), fixedBefore: true }), { through: BigInt(90), fixed: true }, "a mark never moves back");
  assert.deepEqual(windowsMarks({ ...base, copies: null, rangeCovered: { through: BigInt(100), fixed: true } }), { through: BigInt(100), fixed: true }, "a range scan from genesis to the head covered every window that had closed");
  assert.deepEqual(windowsMarks({ ...base, copies: null, rangeCovered: { through: BigInt(97), fixed: true } }), { through: BigInt(97), fixed: true }, "a copy whose window had not closed when the range scan read the head is not passed");
  assert.deepEqual(windowsMarks({ ...base, copies: null, rangeCovered: { through: BigInt(97), fixed: false } }), { through: BigInt(97), fixed: false }, "a log entry whose window had not closed either: the fixed mark stays off");
  assert.deepEqual(windowsMarks({ ...base, copies: null, rangeCovered: { through: BigInt(150), fixed: true }, cpSequence: BigInt(100) }), { through: BigInt(100), fixed: true }, "never beyond the checkpoint sequence");
  assert.deepEqual(windowsMarks({ ...base, copies: null, rangeCovered: null, throughBefore: BigInt(50), fixedBefore: true }), { through: BigInt(50), fixed: true }, "a range scan that started late or stopped early leaves the marks as they were");
  assert.deepEqual(windowsMarks({ ...base, copies: null, rangeCovered: null }), { through: BigInt(-1), fixed: false });
  assert.deepEqual(windowsMarks({ ...base, copies: null, fixedBefore: true, throughBefore: BigInt(5) }), { through: BigInt(5), fixed: true }, "no Base read at all: carried");
});
