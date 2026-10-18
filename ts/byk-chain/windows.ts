/* BYK Data Layer · where a Base copy is expected, and how a reader checkpoint moves in windows mode (2026-10-18).
 *
 * Pure functions, so the placement and the hold rules are unit-tested (windows.test.ts); byk-verify.ts only feeds them
 * what it read on Solana and what its checkpoint says. */
import { baseCopyPlanned, type Bytes } from "../index";
import { type CopyResult, FIXED_WINDOW_BEFORE_MS, type WindowSpec } from "./base";

const sec = (t: number) => BigInt(Math.trunc(t)) * BigInt(1000);
const walked = (c: CopyResult) => c.status === "found" || c.status === "missing";

/** The window in which a data manifest's Base copy is expected, or none when the engine would not have planned one.
 *  The copy is sent right after the window end, in the tick that also sends the Solana copy, so the window starts at the
 *  window end and reaches to the last Solana anchor: one contiguous range, however late that anchor landed (the live
 *  stream's genesis manifest was anchored hours after its window, at the mainnet switch), because a copy that landed in
 *  between must not be missed; the cost is bounded by the budget and paid only for such a manifest. The engine planned
 *  before its Solana copy landed (a dropped transaction is sent again up to five times), so the earliest Solana block time
 *  less that lead stands in for the planning time on the horizon side; between the two possible errors, a copy that is
 *  looked for and reported MISSING is visible, a copy that is never looked for is not. Without a block time the window end
 *  stands in. */
export function dataCopyWindows(key: Bytes, sequence: bigint, window: { epochStartMs: bigint; epochEndMs: bigint }, blockTimesSec: number[]): WindowSpec[] {
  const solMin = blockTimesSec.length ? sec(Math.min(...blockTimesSec)) : null;
  const solMax = blockTimesSec.length ? sec(Math.max(...blockTimesSec)) : null;
  const plannedAt = solMin !== null ? solMin - FIXED_WINDOW_BEFORE_MS : window.epochEndMs;
  if (!baseCopyPlanned(sequence, window.epochStartMs, window.epochEndMs, plannedAt)) return [];
  const atMs = solMin !== null && solMin < window.epochEndMs ? solMin : window.epochEndMs;
  const untilMs = solMax !== null && solMax > window.epochEndMs ? solMax : window.epochEndMs;
  return [{ key, kind: "data", n: sequence, atMs, untilMs }];
}

/** The window of the genesis core's or a log entry's Base copy: around the Solana block time, with the long lead, since
 *  there is no window end to place it from. null when no Solana anchor carries a block time (reported, never guessed). */
export function fixedCopyWindow(key: Bytes, kind: "genesis" | "al", n: bigint, blockTimesSec: number[]): WindowSpec | null {
  if (blockTimesSec.length === 0) return null;
  return { key, kind, n, atMs: sec(Math.min(...blockTimesSec)), untilMs: sec(Math.max(...blockTimesSec)), beforeMs: FIXED_WINDOW_BEFORE_MS };
}

/** Where the checkpoint stops. A data copy whose window was not walked to the end (the budget or the endpoint stopped the
 *  pass, or the window is still open) must be placed again by a later run, and a later run only reads Solana from the
 *  checkpoint sequence on: so the checkpoint stops right before the first such sequence. It never goes behind the seed
 *  (nothing before it was read in this run): then it is written at the seed again, carried forward. A copy with no window
 *  to its name (MISSING) is passed: windows mode looked where the copy belongs and hours beyond. */
export function checkpointSequence(head: bigint, seedSequence: bigint | null, copies: CopyResult[] | null): { sequence: bigint; heldBy: bigint | null } {
  const pending = (copies ?? []).filter((c) => c.kind === "data" && (c.status === "open" || c.status === "not_walked")).map((c) => BigInt(c.n));
  if (pending.length === 0) return { sequence: head, heldBy: null };
  const heldBy = pending.reduce((m, n) => (n < m ? n : m)); // every pending copy sits at or below the head: it has Solana evidence
  let sequence = heldBy - BigInt(1);
  if (seedSequence !== null && sequence < seedSequence) sequence = seedSequence;
  return { sequence, heldBy };
}

/** The windows marks a checkpoint carries: the highest data sequence whose copy was looked for to the end (never beyond
 *  the checkpoint sequence, which stops before the first copy that was not), and whether the genesis and log copies were.
 *  A windows pass whose checkpoint already carried the fixed mark skipped those windows, and the mark holds. A range scan
 *  that started at the genesis time and reached its head covered every window that had closed by the time it read the
 *  head: the caller computes from the scan's latest block time the highest such data sequence (`through`) and whether the
 *  genesis and log windows had closed too (`fixed`); a range scan that started later or stopped early passes null and
 *  leaves the marks as they were, and the sequences it passed are only read again by a full run. Marks never move back. */
export function windowsMarks(a: { copies: CopyResult[] | null; cpSequence: bigint; throughBefore: bigint; fixedBefore: boolean; unplacedFixed: number; rangeCovered: { through: bigint; fixed: boolean } | null }): { through: bigint; fixed: boolean } {
  let through = BigInt(-1);
  let fixed = a.fixedBefore;
  if (a.rangeCovered !== null) {
    through = a.rangeCovered.through > a.cpSequence ? a.cpSequence : a.rangeCovered.through;
    fixed = a.fixedBefore || a.rangeCovered.fixed;
  } else if (a.copies) {
    const highest = a.copies.filter((c) => c.kind === "data" && walked(c)).reduce((m, c) => (BigInt(c.n) > m ? BigInt(c.n) : m), BigInt(-1));
    through = highest > a.cpSequence ? a.cpSequence : highest;
    fixed = a.fixedBefore ? true : a.unplacedFixed === 0 && a.copies.filter((c) => c.kind !== "data").every(walked);
  }
  return { through: through > a.throughBefore ? through : a.throughBefore, fixed };
}
