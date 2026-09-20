import assert from "node:assert/strict";
import test from "node:test";

import { BykError } from "./bytes";
import { canonicalDecimal, scaleDecimal, scaleNumber } from "./decimal";

test("canonical decimal text of a double: shortest round-trip digits, never an exponent", () => {
  const cases: Array<[number, string]> = [
    [0, "0"], [-0, "0"], [1, "1"], [-1.5, "-1.5"], [0.1, "0.1"], [0.01, "0.01"], [1e21, "1000000000000000000000"], [1.5e-7, "0.00000015"], [-2.5e-10, "-0.00000000025"],
    [123456789.125, "123456789.125"], [8286662072.4552, "8286662072.4552"], [0.004717, "0.004717"], [5e-324, "0." + "0".repeat(323) + "5"], [1.7976931348623157e308, "17976931348623157" + "0".repeat(292)],
    [0.1 + 0.2, "0.30000000000000004"], [76627.6, "76627.6"], [100, "100"], [1e-7, "0.0000001"],
  ];
  for (const [x, want] of cases) {
    assert.equal(canonicalDecimal(x), want);
    assert.equal(Number(canonicalDecimal(x)), x === 0 ? 0 : x, `round trip ${x}`);
  }
  for (const bad of [NaN, Infinity, -Infinity]) assert.throws(() => canonicalDecimal(bad), BykError);
});

test("exact scaling truncates toward zero and never goes through a float", () => {
  const big = (s: string) => BigInt(s);
  assert.equal(scaleDecimal("1.23456", 2), big("123"));
  assert.equal(scaleDecimal("-1.239", 2), big("-123"));
  assert.equal(scaleDecimal("-0.001", 2), big("0"));
  assert.equal(scaleDecimal("7", 3), big("7000"));
  assert.equal(scaleDecimal("0.5", 0), big("0"));
  assert.equal(scaleDecimal("12345678901234567.89", 2), big("1234567890123456789"));
  assert.equal(scaleDecimal("0.00000000011", 10), big("1"));
  assert.equal(scaleNumber(0.01, 10), big("100000000"));
  assert.equal(scaleNumber(-9.79, 2), big("-979"));
  assert.equal(scaleNumber(8286662072.4552, 2), big("828666207245"));
  assert.equal(scaleNumber(0.1 + 0.2, 10), big("3000000000"));
  for (const bad of ["", "1e5", "+1", " 1", "1,0", ".5", "5.", "abc", "1\n"]) assert.throws(() => scaleDecimal(bad, 2), BykError, JSON.stringify(bad));
  assert.throws(() => scaleDecimal("1", -1), BykError);
  assert.throws(() => scaleDecimal("1", 1.5), BykError);
});
