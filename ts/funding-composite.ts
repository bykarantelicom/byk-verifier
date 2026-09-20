/* BYK Data Layer v1 (rc6) · Annex A: BYK_FUNDING_COMPOSITE_V1, the reference computation of the Class A
 * composite funding leaf. Exact arithmetic only: every numeric input is the RAW TEXT of the venue's number
 * (a "lexeme"), parsed into an exact rational; a binary64 value is never an input (N24). Rationals here are
 * (numerator, power-of-ten denominator) bigint pairs; products multiply both parts and the single rounding
 * step is truncation toward zero, which is what bigint division does.
 *
 * The venue, detail and result objects keep the specification's snake_case names on purpose: they are the
 * wire format of the retained input snapshot (A.12) and of the conformance vectors. */
import { absBig, B0, B1, BykError, type Bytes, compare, compareBig, I64_MAX, truncDiv, U32_MAX } from "./bytes";
import { id32, type StatusName } from "./records";

const LEX_UNSIGNED = /^[0-9]+(\.[0-9]+)?$/;
const LEX_SIGNED = /^-?[0-9]+(\.[0-9]+)?$/;
const LEX_INTEGER = /^[0-9]{1,19}$/;
const TEN = BigInt(10);
const B10000 = BigInt(10000);

export const HOURLY_MAX = (B1 << BigInt(62)) - B1;
export const HOUR_MS = BigInt(3600000);
export const RATE_SCALE: Record<string, bigint> = { FRACTION: TEN ** TEN, PERCENT: TEN ** BigInt(8), BPS: TEN ** BigInt(6) };
export const TIME_SCALE: Record<string, bigint> = { ms: B1, s: BigInt(1000) };
export const INTERVAL_SCALE: Record<string, bigint> = { ms: B1, s: BigInt(1000), h: HOUR_MS };
export const INTERVAL_MIN_MS = BigInt(60000);
export const INTERVAL_MAX_MS = BigInt(86400000);

export type Rational = { num: bigint; den: bigint };

/** A.2 decimal lexeme: at most 24 characters, digits with an optional fraction of at most 18 digits, a
 *  leading minus only where the field is signed. No exponent, no plus sign, no spaces, no separators. */
export function parseLexeme(lex: unknown, signed: boolean): Rational {
  if (typeof lex !== "string" || lex.length > 24) throw new BykError("lexeme length");
  if (!(signed ? LEX_SIGNED : LEX_UNSIGNED).test(lex)) throw new BykError("lexeme grammar");
  const neg = lex.startsWith("-");
  const [whole, frac = ""] = (neg ? lex.slice(1) : lex).split(".") as [string, string?];
  if (frac.length > 18) throw new BykError("too many fractional digits");
  const num = BigInt(whole + frac);
  return { num: neg ? -num : num, den: TEN ** BigInt(frac.length) };
}

/** A.2 integer lexeme: 1 to 19 digits, scaled by the catalog unit to milliseconds, at most 2^63 - 1. */
export function parseIntegerLexeme(lex: unknown, unit: unknown, scale: Record<string, bigint>): bigint {
  if (typeof lex !== "string" || !LEX_INTEGER.test(lex) || typeof unit !== "string" || !Object.prototype.hasOwnProperty.call(scale, unit)) throw new BykError("integer lexeme or unit");
  const v = BigInt(lex) * scale[unit]!;
  if (v > I64_MAX) throw new BykError("integer exceeds 2^63 - 1 after unit scaling");
  return v;
}

export const mulRational = (a: Rational, b: Rational): Rational => ({ num: a.num * b.num, den: a.den * b.den });
export const scaleRational = (a: Rational, k: bigint): Rational => ({ num: a.num * k, den: a.den });
export const truncRational = (q: Rational): bigint => q.num / q.den;

function medianInt(vals: bigint[]): bigint {
  const v = [...vals].sort(compareBig);
  const mid = v.length >> 1;
  return v.length % 2 === 1 ? v[mid]! : truncDiv(v[mid - 1]! + v[mid]!, BigInt(2));
}

export const PARAM_KEYS = ["decimals", "min_contributors", "max_weight_bps", "coverage_ok_bps", "min_source_ratio_bps", "stale_factor", "oi_max_age_ms", "price_max_skew_ms", "outlier_k", "outlier_floor"] as const;
export type ParamKey = (typeof PARAM_KEYS)[number];
export type FundingParams = Record<ParamKey, bigint>;

/** A.10 bounds (inclusive). They make signed 256-bit arithmetic sufficient for every intermediate (A.2). */
export const PARAM_BOUNDS: Record<ParamKey, [bigint, bigint]> = {
  decimals: [TEN, TEN],
  min_contributors: [B1, BigInt(65535)],
  max_weight_bps: [B1, B10000],
  coverage_ok_bps: [B0, B10000],
  min_source_ratio_bps: [B0, B10000],
  stale_factor: [B1, BigInt(1000)],
  oi_max_age_ms: [B0, BigInt(604800000)],
  price_max_skew_ms: [B0, BigInt(604800000)],
  outlier_k: [B0, BigInt(1000)],
  outlier_floor: [B0, HOURLY_MAX],
};

function paramValue(v: unknown): bigint | null {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isSafeInteger(v)) return BigInt(v);
  return null; // booleans, strings, fractions, unsafe numbers
}

/** A.10: exactly the ten parameters, each an integer inside its bounds, and cap x min_contributors >= 10000
 *  (otherwise the weight cap cannot be met by min_contributors venues). */
export function validateParams(p: Record<string, unknown>, catalogSize: number): FundingParams {
  const keys = Object.keys(p);
  if (keys.length !== PARAM_KEYS.length || !PARAM_KEYS.every((k) => Object.prototype.hasOwnProperty.call(p, k))) throw new BykError("parameter set must contain exactly the A.10 parameters");
  const out = {} as FundingParams;
  for (const k of PARAM_KEYS) {
    const v = paramValue(p[k]);
    const [lo, hi] = PARAM_BOUNDS[k];
    if (v === null || v < lo || v > hi) throw new BykError(`parameter out of bounds: ${k}`);
    out[k] = v;
  }
  if (out.max_weight_bps * out.min_contributors < B10000 || !(Number.isInteger(catalogSize) && catalogSize >= 1 && catalogSize <= 65535)) throw new BykError("invalid methodology parameters");
  return out;
}

/** Two parameter sets are the same methodology when they have the same keys and the same integer values. */
export function paramsEqual(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
  const ka = Object.keys(a);
  if (ka.length !== Object.keys(b).length) return false;
  return ka.every((k) => {
    if (!Object.prototype.hasOwnProperty.call(b, k)) return false;
    const x = paramValue(a[k]);
    const y = paramValue(b[k]);
    return x !== null && y !== null ? x === y : Object.is(a[k], b[k]);
  });
}

export type FundingVenueInput = {
  venue: string;
  rate: string;
  rate_unit: string;
  interval: string;
  interval_unit: string;
  settlement_ts: string;
  settlement_ts_unit: string;
  oi_unit: string;
  oi_value: string;
  contract_size: string | null;
  mark_price: string | null;
  oi_ts: string;
  oi_ts_unit: string;
  price_ts: string | null;
  price_ts_unit: string | null;
};

export type FundingVenueDetail = {
  venue: string;
  vid: Bytes;
  valid_rate: boolean;
  valid_oi: boolean;
  eligible: boolean;
  interval_ms?: bigint;
  units?: bigint;
  hourly?: bigint;
  settle_age?: bigint;
  stale?: boolean;
  rate_error?: string;
  oi_usd?: bigint;
  oi_ages?: bigint[];
  oi_error?: string;
  outlier?: boolean;
};

export type FundingLeaf = {
  value: bigint;
  dispersion: bigint;
  source_count: number;
  expected_source_count: number;
  coverage_bps: number;
  outlier_count: number;
  max_source_age_ms: number;
  status: StatusName;
  median?: bigint;
  mad?: bigint;
  tau?: bigint;
  weights?: Map<string, bigint>;
  capped_count?: number;
  cap_weight?: bigint | null;
  max_weight_share_bps?: number;
};

const REQUIRED_VENUE_KEYS = ["venue", "rate", "rate_unit", "interval", "interval_unit", "settlement_ts", "settlement_ts_unit", "oi_unit", "oi_value", "oi_ts", "oi_ts_unit"] as const;

function sumBig(xs: bigint[]): bigint {
  return xs.reduce((a, b) => a + b, B0);
}

/** A.3 to A.8 for one feed at T = epoch_end_ms. Returns the leaf fields and the per-venue working, so a
 *  reader can see why a venue was left out. Every returned leaf is encodable as a Section 7.1 record.
 *  Throws BykError when the parameters or the shape of a venue object are invalid; an invalid VALUE inside
 *  a venue only makes that venue ineligible. */
export function fundingComposite(venues: FundingVenueInput[], params: Record<string, unknown>, tMs: bigint): { leaf: FundingLeaf; details: FundingVenueDetail[] } {
  const p = validateParams(params, venues.length);
  const det: FundingVenueDetail[] = [];
  for (const v of venues) {
    for (const k of REQUIRED_VENUE_KEYS) if ((v as Record<string, unknown>)[k] === undefined) throw new BykError(`venue field missing: ${k}`);
    const d: FundingVenueDetail = { venue: v.venue, vid: id32(v.venue), valid_rate: false, valid_oi: false, eligible: false };
    try {
      const intervalMs = parseIntegerLexeme(v.interval, v.interval_unit, INTERVAL_SCALE);
      if (intervalMs < INTERVAL_MIN_MS || intervalMs > INTERVAL_MAX_MS) throw new BykError("interval outside [60000, 86400000] ms");
      const settle = parseIntegerLexeme(v.settlement_ts, v.settlement_ts_unit, TIME_SCALE);
      if (!Object.prototype.hasOwnProperty.call(RATE_SCALE, v.rate_unit)) throw new BykError("rate_unit");
      const units = truncRational(scaleRational(parseLexeme(v.rate, true), RATE_SCALE[v.rate_unit]!));
      if (absBig(units) > I64_MAX) throw new BykError("rate units exceed int64");
      const hourly = truncDiv(units * HOUR_MS, intervalMs);
      if (absBig(hourly) > HOURLY_MAX) throw new BykError("hourly outside +-(2^62 - 1)");
      if (!(settle < tMs)) throw new BykError("settlement_ts >= T");
      Object.assign(d, { interval_ms: intervalMs, units, hourly, settle_age: tMs - settle, valid_rate: true, stale: tMs - settle > p.stale_factor * intervalMs });
    } catch (err) {
      if (!(err instanceof BykError)) throw err;
      d.rate_error = err.message;
    }
    try {
      const oiTs = parseIntegerLexeme(v.oi_ts, v.oi_ts_unit, TIME_SCALE);
      let q = parseLexeme(v.oi_value, false);
      const ages = [tMs - oiTs];
      if (v.oi_unit === "QUOTE") {
        // already in USD terms
      } else if (v.oi_unit === "BASE" || v.oi_unit === "CONTRACTS") {
        if (v.mark_price === null || v.mark_price === undefined || v.price_ts === null || v.price_ts === undefined) throw new BykError("mark price required");
        const priceTs = parseIntegerLexeme(v.price_ts, v.price_ts_unit, TIME_SCALE);
        if (!(priceTs < tMs && absBig(oiTs - priceTs) <= p.price_max_skew_ms)) throw new BykError("price timing");
        q = mulRational(q, parseLexeme(v.mark_price, false));
        if (v.oi_unit === "CONTRACTS") q = mulRational(q, parseLexeme(v.contract_size, false));
        ages.push(tMs - priceTs);
      } else {
        throw new BykError("oi_unit");
      }
      const oiUsd = truncRational(q);
      if (!(oiUsd >= B1 && oiUsd <= I64_MAX) || !(oiTs < tMs && tMs - oiTs <= p.oi_max_age_ms)) throw new BykError("oi bounds or timing");
      Object.assign(d, { oi_usd: oiUsd, valid_oi: true, oi_ages: ages });
    } catch (err) {
      if (!(err instanceof BykError)) throw err;
      d.oi_error = err.message;
    }
    d.eligible = d.valid_rate && !d.stale && d.valid_oi;
    det.push(d);
  }

  const nExp = venues.length;
  const leaf: FundingLeaf = { value: B0, dispersion: B0, source_count: 0, expected_source_count: nExp, coverage_bps: 0, outlier_count: 0, max_source_age_ms: 0, status: "NO_DATA" };
  const elig = det.filter((d) => d.eligible);
  if (elig.length === 0) return { leaf, details: det }; // A.8 step 2

  // A.7: OI-weighted median of the hourly rates, then a MAD filter around it
  const srt = [...elig].sort((a, b) => compareBig(a.hourly!, b.hourly!) || compare(a.vid, b.vid));
  const tot = sumBig(srt.map((d) => d.oi_usd!));
  let cum = B0;
  let m = srt[0]!.hourly!;
  for (const d of srt) {
    cum += d.oi_usd!;
    if (BigInt(2) * cum >= tot) {
      m = d.hourly!;
      break;
    }
  }
  const mad = medianInt(elig.map((d) => absBig(d.hourly! - m)));
  const kMad = p.outlier_k * mad;
  const tau = kMad > p.outlier_floor ? kMad : p.outlier_floor;
  const contrib = elig.filter((d) => absBig(d.hourly! - m) <= tau); // never empty: it contains the median venue
  const contribSet = new Set(contrib);
  for (const d of elig) d.outlier = !contribSet.has(d);
  const cov = truncDiv(B10000 * sumBig(contrib.map((d) => d.oi_usd!)), sumBig(det.filter((d) => d.valid_oi).map((d) => d.oi_usd!)));
  let age = B0;
  for (const d of contrib) for (const a of [d.settle_age!, ...d.oi_ages!]) if (a > age) age = a;
  Object.assign(leaf, {
    source_count: contrib.length, outlier_count: elig.length - contrib.length, coverage_bps: Number(cov),
    max_source_age_ms: age > BigInt(U32_MAX) ? U32_MAX : Number(age), median: m, mad, tau,
  });
  if (BigInt(contrib.length) < p.min_contributors) { // A.8 step 4
    leaf.status = "INSUFFICIENT_COVERAGE";
    return { leaf, details: det };
  }

  // A.8 step 5: weight cap. n >= min_contributors and cap x min_contributors >= 10000, so cap x n >= 10000
  // and the loop ends with a positive denominator before it runs out of venues.
  const cap = p.max_weight_bps;
  const n = contrib.length;
  const order = [...contrib].sort((a, b) => compareBig(b.oi_usd!, a.oi_usd!) || compare(a.vid, b.vid));
  let k = 0;
  let x = B0;
  for (;;) {
    const denom = B10000 - cap * BigInt(k);
    if (!(denom > B0 && k < n)) throw new Error("weight cap loop left its proven range (A.8)");
    x = truncDiv(cap * sumBig(order.slice(k).map((d) => d.oi_usd!)), denom);
    if (order[k]!.oi_usd! <= x) break;
    k++;
  }
  const w = new Map<string, bigint>();
  order.forEach((d, i) => w.set(d.venue, i < k ? x : d.oi_usd!));
  const sw = sumBig([...w.values()]);
  let wMax = B0;
  for (const wi of w.values()) {
    if (wi * B10000 > cap * sw) throw new Error("weight above cap (A.8)");
    if (wi > wMax) wMax = wi;
  }
  const r = truncDiv(sumBig(contrib.map((d) => w.get(d.venue)! * d.hourly!)), sw);
  const disp = medianInt(contrib.map((d) => absBig(d.hourly! - r)));
  if (!(absBig(r) <= HOURLY_MAX && disp >= B0 && disp <= I64_MAX)) throw new Error("composite outside its proven bound (A.6)");
  const ok = cov >= p.coverage_ok_bps && B10000 * BigInt(n) >= p.min_source_ratio_bps * BigInt(nExp);
  Object.assign(leaf, {
    value: r, dispersion: disp, status: ok ? "OK" : "DEGRADED", weights: w, capped_count: k, cap_weight: k ? x : null,
    max_weight_share_bps: Number(truncDiv(B10000 * wMax, sw)),
  });
  return { leaf, details: det };
}
