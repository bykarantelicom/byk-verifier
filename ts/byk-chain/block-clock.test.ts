/* The block clock against chains it has to survive (2026-11-11): one pace, a change of pace (Base, 5 Nov 2026: a block
 * every two seconds, then five a second with whole-second timestamps), a pause in block production, a time before the
 * chain and one beyond its head, an endpoint that cannot be read and one whose block times are out of order. Every
 * answer is checked against the property the windows pass relies on, not against a block number: the start of a range
 * is before the wanted time and the end after it, each by no more than the tolerance or with its neighbour on the other
 * side of the time. */
import assert from "node:assert/strict";
import { test } from "node:test";

import { type BlockPoint, CLOCK_TOLERANCE_MS, makeBlockClock } from "./block-clock";

const TOL = Number(CLOCK_TOLERANCE_MS);
type TimeOf = (number: number) => number; // milliseconds

function chain(latest: number, timeOf: TimeOf) {
  const asked: number[] = [];
  const point = (number: number): BlockPoint => ({ number: BigInt(number), timeMs: BigInt(timeOf(number)) });
  const clock = makeBlockClock(point(latest), async (number) => {
    asked.push(Number(number));
    return point(Number(number));
  });
  return { clock, asked, timeOf, latest };
}

/** rangeStart's contract for `ms` on a chain: before the time; within the tolerance, or the next block at or after it. */
function assertStart(c: { timeOf: TimeOf; latest: number }, block: bigint | null, ms: number, note = ""): void {
  assert.notEqual(block, null);
  const b = Number(block);
  if (b === c.latest && c.timeOf(b) < ms) return; // the head, for a time beyond it
  if (b === 0 && c.timeOf(0) >= ms) return; // the chain starts at or after the time
  assert.ok(c.timeOf(b) < ms, `${note} block ${b} at ${c.timeOf(b)} is not before ${ms}`);
  assert.ok(ms - c.timeOf(b) <= TOL || c.timeOf(b + 1) >= ms, `${note} block ${b} is ${ms - c.timeOf(b)} ms before the time and its neighbour is before it as well`);
}
/** rangeEnd's contract: after the time; within the tolerance, or the block before it at or before the time. */
function assertEnd(c: { timeOf: TimeOf; latest: number }, block: bigint | null, ms: number, note = ""): void {
  assert.notEqual(block, null);
  const b = Number(block);
  if (b === c.latest && c.timeOf(b) <= ms) return; // nothing is after the time yet
  assert.ok(c.timeOf(b) > ms, `${note} block ${b} at ${c.timeOf(b)} is not after ${ms}`);
  assert.ok(c.timeOf(b) - ms <= TOL || c.timeOf(b - 1) <= ms, `${note} block ${b} is ${c.timeOf(b) - ms} ms after the time and its neighbour is after it as well`);
}

const HEAD_MS = 1_762_400_000_000;

test("on a chain with one pace a time costs a few reads and the next one beside it one or two", async () => {
  const c = chain(50_000_000, (n) => HEAD_MS - 2_000 * (50_000_000 - n));
  const day = 86_400_000;
  const first = HEAD_MS - 30 * day;
  assertStart(c, await c.clock.rangeStart(BigInt(first)), first);
  const afterFirst = c.asked.length;
  assert.ok(afterFirst <= 8, `the first time, with only the head known: ${afterFirst} reads`);
  assertEnd(c, await c.clock.rangeEnd(BigInt(first + 900_000)), first + 900_000);
  for (let d = 29; d >= 1; d--) {
    const t = HEAD_MS - d * day;
    assertStart(c, await c.clock.rangeStart(BigInt(t)), t, `day -${d}`);
    assertEnd(c, await c.clock.rangeEnd(BigInt(t + 900_000)), t + 900_000, `day -${d}`);
  }
  assert.ok(c.asked.length - afterFirst <= 2 * 59 + 2, `fifty-nine more times, a read or two each: ${c.asked.length - afterFirst}`);
  assert.equal(c.clock.reads(), c.asked.length);
});

/* Base on 5 Nov 2026: two seconds a block up to block 53,566,959, five blocks a second from there on, timestamps in whole
 * seconds, so five neighbours share one. */
const CHANGE_AT = 53_566_959;
const BASE_HEAD = 55_897_841;
const CHANGE_MS = HEAD_MS - Math.floor((BASE_HEAD - CHANGE_AT) / 5) * 1000;
const base: TimeOf = (n) => (n >= CHANGE_AT ? CHANGE_MS + Math.floor((n - CHANGE_AT) / 5) * 1000 : CHANGE_MS - 2_000 * (CHANGE_AT - n));

test("across a change of block time every answer keeps its contract and no search runs away", async () => {
  const c = chain(BASE_HEAD, base);
  const times = [
    HEAD_MS - 3_600_000, // an hour ago, the new pace
    CHANGE_MS + 86_400_000, // a day after the change
    CHANGE_MS + 1_000, // the second after it
    CHANGE_MS, // the very second
    CHANGE_MS - 1_000,
    CHANGE_MS - 30 * 86_400_000, // a month before, the old pace
    CHANGE_MS - 47 * 86_400_000, // the stream's genesis
    CHANGE_MS + 3 * 86_400_000 + 61_000,
  ];
  let before = 0;
  for (const t of times) {
    assertStart(c, await c.clock.rangeStart(BigInt(t)), t, `start ${t - CHANGE_MS}`);
    assertEnd(c, await c.clock.rangeEnd(BigInt(t)), t, `end ${t - CHANGE_MS}`);
    assert.ok(c.asked.length - before <= 70, `two searches for one time took ${c.asked.length - before} reads`);
    before = c.asked.length;
  }
});

test("the daily copies of a stream that lived through the change are placed in a handful of reads each", async () => {
  // fifty-five midnights: forty-eight on the old pace, seven on the new one, placed in sequence order as the windows pass does
  const c = chain(BASE_HEAD, base);
  const firstMidnight = CHANGE_MS - 48 * 86_400_000;
  for (let d = 0; d < 55; d++) {
    const at = firstMidnight + d * 86_400_000;
    assertStart(c, await c.clock.rangeStart(BigInt(at)), at, `day ${d}`);
    assertEnd(c, await c.clock.rangeEnd(BigInt(at + 900_000)), at + 900_000, `day ${d}`);
  }
  assert.ok(c.asked.length <= 55 * 4 + 60, `fifty-five windows placed in ${c.asked.length} block reads`);
});

test("blocks that share a second are all inside the range of that second", async () => {
  const c = chain(BASE_HEAD, base);
  const t = CHANGE_MS + 7_200_000; // five blocks carry exactly this second
  const start = Number(await c.clock.rangeStart(BigInt(t)));
  const end = Number(await c.clock.rangeEnd(BigInt(t)));
  const firstOfSecond = CHANGE_AT + 5 * 7_200;
  assert.ok(start < firstOfSecond, "the range starts before the first block of the second");
  assert.ok(end > firstOfSecond + 4, "and ends after its last one");
});

test("a time before the chain answers block 0, a time beyond the head answers the head", async () => {
  const c = chain(1_000, (n) => HEAD_MS - 2_000 * (1_000 - n));
  assert.equal(await c.clock.rangeStart(BigInt(HEAD_MS - 10_000_000)), BigInt(0));
  assert.equal(await c.clock.rangeEnd(BigInt(HEAD_MS - 10_000_000)), BigInt(0));
  assert.equal(await c.clock.rangeStart(BigInt(HEAD_MS + 5_000)), BigInt(1_000));
  assert.equal(await c.clock.rangeEnd(BigInt(HEAD_MS + 5_000)), BigInt(1_000));
  assert.equal(await c.clock.rangeEnd(BigInt(HEAD_MS)), BigInt(1_000), "no block is after the head's own second");
});

test("a pause in block production wider than the tolerance answers the blocks on either side of it", async () => {
  // blocks 0 to 5,000 two seconds apart, then ten minutes with no block, then two seconds apart again
  const paused: TimeOf = (n) => (n > 5_000 ? HEAD_MS - 2_000 * (10_000 - n) : HEAD_MS - 2_000 * (10_000 - n) - 600_000);
  const c = chain(10_000, paused);
  const inThePause = paused(5_000) + 300_000;
  assert.equal(await c.clock.rangeStart(BigInt(inThePause)), BigInt(5_000), "the last block before the pause");
  assert.equal(await c.clock.rangeEnd(BigInt(inThePause)), BigInt(5_001), "the first block after it");
});

test("a block that cannot be read ends the search with null, and the blocks read before it are kept", async () => {
  let allowed = 2;
  const timeOf: TimeOf = (n) => HEAD_MS - 2_000 * (1_000_000 - n);
  const clock = makeBlockClock({ number: BigInt(1_000_000), timeMs: BigInt(HEAD_MS) }, async (number) => (allowed-- > 0 ? { number, timeMs: BigInt(timeOf(Number(number))) } : null));
  assert.equal(await clock.rangeStart(BigInt(HEAD_MS - 86_400_000)), null);
  assert.equal(clock.reads(), 2);
});

test("an endpoint whose block times are out of order is an error, never a loop", async () => {
  const clock = makeBlockClock({ number: BigInt(1_000_000), timeMs: BigInt(HEAD_MS) }, async (number) => ({ number, timeMs: BigInt(HEAD_MS + 1_000_000 - Number(number)) }));
  await assert.rejects(() => clock.rangeStart(BigInt(HEAD_MS - 86_400_000)), /out of order/);
});
