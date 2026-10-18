import assert from "node:assert/strict";
import test from "node:test";

import { BASE_PLAN_HORIZON_MS, baseAnchorDue, baseCopyPlanned, DAY_MS } from "./beta-profile";

/* The verifier expects a Base copy exactly where the engine plans one; both read this module. */
test("a Base copy is planned for the genesis manifest and for one manifest a day, only within the planning horizon", () => {
  const e = BigInt(300_000);
  const midnight = BigInt(20_714) * DAY_MS;
  assert.equal(baseAnchorDue(BigInt(7), midnight - e, midnight), true, "the window that ends at 00:00 UTC");
  assert.equal(baseAnchorDue(BigInt(8), midnight, midnight + e), false, "the first window of the day");
  assert.equal(baseCopyPlanned(BigInt(7), midnight - e, midnight, midnight + BigInt(60_000)), true, "planned a minute after the window closed");
  assert.equal(baseCopyPlanned(BigInt(7), midnight - e, midnight, midnight + BASE_PLAN_HORIZON_MS - BigInt(1)), true, "still inside the horizon");
  assert.equal(baseCopyPlanned(BigInt(7), midnight - e, midnight, midnight + BASE_PLAN_HORIZON_MS), false, "a window that ended three days before the planning: no Base copy");
  assert.equal(baseCopyPlanned(BigInt(0), midnight, midnight + e, midnight + BigInt(10) * DAY_MS), true, "the genesis manifest always");
  assert.equal(baseCopyPlanned(BigInt(8), midnight, midnight + e, midnight + e), false, "not due by the window");
  assert.equal(BASE_PLAN_HORIZON_MS, BigInt(3) * DAY_MS);
});
