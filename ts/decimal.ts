/* BYK Data Layer · exact decimal handling for values that reach us as binary64 (Class B feeds and the
 * Integration Profile section 3.2 capture rule). A double never enters leaf arithmetic directly: it is first
 * written as its shortest round-trip decimal text, and that TEXT is scaled with integer arithmetic. The one
 * rounding step is truncation toward zero, the protocol's only rounding rule (Section 4). */
import { B0, BykError } from "./bytes";

/** Shortest decimal text that parses back to exactly the same double, without exponent notation. */
export function canonicalDecimal(x: number): string {
  if (typeof x !== "number" || !Number.isFinite(x)) throw new BykError("non-finite number");
  if (x === 0) return "0";
  let r = x.toString(); // shortest round-trip digits (ECMA-262 Number::toString)
  const neg = r.startsWith("-");
  if (neg) r = r.slice(1);
  let mant = r;
  let exp = 0;
  if (r.includes("e")) {
    const parts = r.split("e");
    mant = parts[0]!;
    exp = parseInt(parts[1]!, 10);
  }
  const [whole = "", frac = ""] = mant.split(".");
  const all = whole + frac;
  const stripped = all.replace(/^0+/, "");
  const digits = stripped || "0";
  const point = whole.length + exp - (all.length - stripped.length);
  let s: string;
  if (point <= 0) s = "0." + "0".repeat(-point) + digits;
  else if (point >= digits.length) s = digits + "0".repeat(point - digits.length);
  else s = digits.slice(0, point) + "." + digits.slice(point);
  if (s.includes(".")) s = s.replace(/0+$/, "").replace(/\.$/, "");
  return (neg ? "-" : "") + s;
}

const DECIMAL_TEXT = /^-?[0-9]+(\.[0-9]+)?$/;

/** value x 10^decimals as an integer, truncated toward zero. `text` is plain decimal text of any length. */
export function scaleDecimal(text: string, decimals: number): bigint {
  if (typeof text !== "string" || !DECIMAL_TEXT.test(text)) throw new BykError("decimal text grammar");
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) throw new BykError("decimals out of range");
  const neg = text.startsWith("-");
  const [whole = "0", frac = ""] = (neg ? text.slice(1) : text).split(".");
  const kept = frac.length >= decimals ? frac.slice(0, decimals) : frac + "0".repeat(decimals - frac.length);
  const v = BigInt(whole + kept);
  return neg && v !== B0 ? -v : v;
}

/** A stored double as a leaf integer: canonical text first, then exact scaling. */
export function scaleNumber(x: number, decimals: number): bigint {
  return scaleDecimal(canonicalDecimal(x), decimals);
}
