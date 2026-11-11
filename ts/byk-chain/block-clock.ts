/* BYK Data Layer · which block a chain had at a given time, read from the chain itself (2026-11-11).
 *
 * Windows mode turns a time (the end of a manifest's window, a Solana block time) into a Base block number. Until
 * 5 Nov 2026 Base produced a block every two seconds and the verifier counted back from the latest block at that pace.
 * That day's upgrade moved the chain to five blocks a second: the arithmetic put every window more than a million blocks
 * away from its copy, and from 6 Nov the public daily run reported each Base copy MISSING while all of them were on the
 * chain. A block time is not a constant of a chain, so nothing here assumes one.
 *
 * The clock keeps every block it has read, brackets the wanted time between the two nearest of them, guesses along the
 * straight line between those two and reads the guess. A change of pace inside the bracket makes the straight line wrong,
 * so a guess that did not at least halve the bracket is followed by a plain bisection: the bracket halves at least every
 * second read whatever the chain did. Windows are placed in sequence order, so after the first few every new time sits
 * next to blocks already read and costs one or two reads.
 *
 * Base's block timestamps are whole seconds and several blocks share one, so the two answers are strict: the start of a
 * range is a block BEFORE the time and the end a block AFTER it, each within CLOCK_TOLERANCE_MS. A few more blocks are
 * walked, never a block of the wanted second left out. */
export type BlockPoint = { number: bigint; timeMs: bigint };

/** How far from the wanted time an answer may sit, on its own side of it. */
export const CLOCK_TOLERANCE_MS = BigInt(6_000);
/** One search never needs this many reads on a chain whose block times are in order (two per halving of the bracket,
 *  under sixty for Base); beyond it the endpoint is answering inconsistently and the search says so. */
export const CLOCK_MAX_READS_PER_SEARCH = 160;

export type BlockClock = {
  /** A block whose time is before `timeMs`, by no more than the tolerance or with the very next block at or after it:
   *  every block at or after `timeMs` comes after the answer. Block 0 when the chain starts at or after `timeMs`, the
   *  head when `timeMs` is beyond it. null when the reader could not read a block (it answered null). */
  rangeStart(timeMs: bigint): Promise<bigint | null>;
  /** A block whose time is after `timeMs`, by no more than the tolerance or with the block right before it at or before
   *  `timeMs`: every block at or before `timeMs` comes before the answer. The head when no block is after `timeMs` yet. */
  rangeEnd(timeMs: bigint): Promise<bigint | null>;
  /** Blocks read so far (the head it was given is not counted). */
  reads(): number;
};

const B0 = BigInt(0);
const B1 = BigInt(1);
const B2 = BigInt(2);

/** `readBlock` answers one block by number, null when it could not be read for good (the caller knows why), and may
 *  throw; both end the search, the first as a null answer, the second as the exception. */
export function makeBlockClock(head: BlockPoint, readBlock: (number: bigint) => Promise<BlockPoint | null>): BlockClock {
  const points: BlockPoint[] = [head]; // ascending by block number, so ascending by time as well
  let reads = 0;

  /** The index of the first point that `before` does not hold for (the points are sorted and `before` holds for a prefix). */
  const firstNot = (before: (p: BlockPoint) => boolean): number => {
    let lo = 0;
    let hi = points.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (before(points[mid]!)) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  };
  const insert = (p: BlockPoint): void => {
    const i = firstNot((x) => x.number < p.number);
    if (points[i]?.number !== p.number) points.splice(i, 0, p);
  };

  async function locate(timeMs: bigint, side: "start" | "end"): Promise<bigint | null> {
    // early: on the past side of the wanted block. The start is the last early block, the end the first late one.
    const early = (p: BlockPoint) => (side === "start" ? p.timeMs < timeMs : p.timeMs <= timeMs);
    if (early(head)) return head.number;
    // block times never run backwards, so the early points are a prefix of the sorted list; the head is not early
    const firstLate = firstNot(early);
    let lo: BlockPoint | null = firstLate > 0 ? points[firstLate - 1]! : null;
    let hi: BlockPoint = points[firstLate]!;
    let spent = 0;
    const read = async (number: bigint): Promise<BlockPoint | null> => {
      if (++spent > CLOCK_MAX_READS_PER_SEARCH) throw new Error(`the endpoint's block times do not narrow down to ${new Date(Number(timeMs)).toISOString()} after ${CLOCK_MAX_READS_PER_SEARCH} block reads`);
      const p = await readBlock(number);
      if (p === null) return null;
      reads++;
      insert(p);
      return p;
    };
    /* No block read so far is early enough: step back from the lowest one. The step is twice what the pace of the lowest
     * stretch read so far asks for, and at least twice the step before it, so block 0 is reached in a bounded number of
     * reads however the pace changed further back. */
    let step = B0;
    while (lo === null) {
      const lowest = points[0]!;
      if (lowest.number === B0) return B0;
      const next = points[1];
      // with a single block read, or two that share a timestamp, there is no pace to measure yet: a thousand blocks gives one
      let back = next && next.timeMs > lowest.timeMs ? ((lowest.timeMs - timeMs) * (next.number - lowest.number)) / (next.timeMs - lowest.timeMs) : BigInt(1000);
      back = back * B2 + B1;
      if (back < step * B2) back = step * B2;
      step = back;
      const p = await read(lowest.number > back ? lowest.number - back : B0);
      if (p === null) return null;
      if (p.timeMs > lowest.timeMs) throw new Error(`the endpoint's block times are out of order: block ${p.number} is later than block ${lowest.number}`);
      if (early(p)) lo = p;
      else hi = p;
    }
    let bisect = false;
    for (;;) {
      if (side === "start" && timeMs - lo.timeMs <= CLOCK_TOLERANCE_MS) return lo.number;
      if (side === "end" && hi.timeMs - timeMs <= CLOCK_TOLERANCE_MS) return hi.number;
      const gap: bigint = hi.number - lo.number;
      // neighbours on either side of the time: a pause in block production wider than the tolerance
      if (gap <= B1) return side === "start" ? lo.number : hi.number;
      let guess: bigint;
      if (bisect || hi.timeMs <= lo.timeMs) guess = lo.number + gap / B2;
      else {
        // aim at the middle of the accepted band, so a guess a block or two off still lands inside it
        const aim = side === "start" ? timeMs - CLOCK_TOLERANCE_MS / B2 : timeMs + CLOCK_TOLERANCE_MS / B2;
        guess = lo.number + ((aim - lo.timeMs) * gap) / (hi.timeMs - lo.timeMs);
      }
      if (guess <= lo.number) guess = lo.number + B1;
      if (guess >= hi.number) guess = hi.number - B1;
      const p = await read(guess);
      if (p === null) return null;
      if (p.timeMs < lo.timeMs || p.timeMs > hi.timeMs) throw new Error(`the endpoint's block times are out of order around block ${p.number}`);
      if (early(p)) lo = p;
      else hi = p;
      bisect = !bisect && (hi.number - lo.number) * B2 > gap;
    }
  }

  return { rangeStart: (timeMs) => locate(timeMs, "start"), rangeEnd: (timeMs) => locate(timeMs, "end"), reads: () => reads };
}
