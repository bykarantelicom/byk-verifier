/* BYK Data Layer · beta profile rules shared by the engine and the verifier (reports/data-layer-beta-profile-20260917.md).
 *
 * The engine decides at planning time which manifests get a Base copy; the independent verifier applies the same pure rules
 * to the manifests it reads from Solana to know where a Base copy is expected (byk-chain/base.ts, windows mode). One module,
 * one place, so the two cannot drift apart: the engine's SQL takes its horizon from here and its tests pin the rule. */

export const DAY_MS = BigInt(86_400_000);

/** The engine plans a Base copy only while the manifest's window ended less than this long ago: a manifest that is sealed
 *  or re-planned days late (a long outage, a backfill) gets its Solana copy and no Base one. */
export const BASE_PLAN_HORIZON_MS = BigInt(3) * DAY_MS;

/** Does a manifest with this window get a Base anchor under the beta profile? The genesis manifest, the window that ends at
 *  00:00 UTC, and a gap manifest whose window crosses midnight (manifests are chained by previous_commitment, so that one
 *  anchor covers every epoch of the day before it). */
export function baseAnchorDue(sequence: bigint, startMs: bigint, endMs: bigint): boolean {
  return sequence === BigInt(0) || endMs % DAY_MS === BigInt(0) || endMs / DAY_MS > startMs / DAY_MS;
}

/** The rule the engine actually applies when it plans at `plannedAtMs` (byk-engine/anchors.ts planAnchors): due by the
 *  window, and the window's end within the horizon. The verifier passes the time of the Solana anchor it read, which is
 *  when the engine planned both copies. */
export function baseCopyPlanned(sequence: bigint, startMs: bigint, endMs: bigint, plannedAtMs: bigint): boolean {
  return sequence === BigInt(0) || (endMs > plannedAtMs - BASE_PLAN_HORIZON_MS && baseAnchorDue(sequence, startMs, endMs));
}
