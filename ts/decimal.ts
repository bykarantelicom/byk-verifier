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

/** Annex A lexeme grammar: a venue number text carries at most this many fractional digits. */
export const LEXEME_MAX_FRACTION_DIGITS = 18;

/** A venue's raw decimal text cut to the grammar bound, toward zero, as TEXT (a lexeme operation, never through a
 *  float): "0.00009599999999999999" (20 digits) becomes "0.000095999999999999". Lighter and Delta publish 19 and 20
 *  fractional digits, and until 2026-10-02 the Class A candidate rejected both venues ("too many fractional digits"),
 *  which pushed the source ratio under the 70 percent quorum on most epochs. A text that is not a plain decimal is
 *  returned unchanged and fails downstream as before. */
export function boundLexemeFraction(text: string, max = LEXEME_MAX_FRACTION_DIGITS): string {
  if (typeof text !== "string" || !DECIMAL_TEXT.test(text)) return text;
  const dot = text.indexOf(".");
  if (dot < 0 || text.length - dot - 1 <= max) return text;
  const cut = text.slice(0, dot + 1 + max).replace(/0+$/, "").replace(/\.$/, "");
  return cut === "-0" || cut === "-" || cut === "" ? "0" : cut;
}
