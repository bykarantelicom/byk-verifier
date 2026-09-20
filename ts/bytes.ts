/* BYK Data Layer v1 (rc6) · byte helpers.
 *
 * Everything in src/lib/byk is a pure library: no database, no network, no Node-only API, relative imports
 * only. It runs unchanged in the worker, in a route handler and in a browser verifier. Integers wider than 32
 * bits are bigint end to end (sequence numbers reach 2^64 - 1 in the conformance vectors). The main tsconfig
 * targets ES2017, so bigint literals are not available: constants are built with BigInt(). */

/** The reference implementation raises ValueError for every rejected input; this is its counterpart.
 *  Callers that must keep going on bad input (candidate collection, log construction) catch exactly this. */
export class BykError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BykError";
  }
}

export type Bytes = Uint8Array;

export const B0 = BigInt(0);
export const B1 = BigInt(1);
export const B2 = BigInt(2);
export const U64_MAX = (B1 << BigInt(64)) - B1;
export const I64_MAX = (B1 << BigInt(63)) - B1;
export const I64_MIN = -(B1 << BigInt(63));
export const U32_MAX = 4294967295;

export function concat(...parts: Bytes[]): Bytes {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const HEX = "0123456789abcdef";

export function toHex(b: Bytes): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += HEX[b[i]! >> 4]! + HEX[b[i]! & 15]!;
  return s;
}

/** Lower or upper case, optional 0x prefix, even length. */
export function fromHex(hex: string): Bytes {
  const s = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) throw new BykError("bad hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function ascii(s: string): Bytes {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0x7f) throw new BykError("non-ASCII text");
    out[i] = c;
  }
  return out;
}

export function equal(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/** Lexicographic byte order, shorter prefix first (the order of Python bytes and of the spec's sort rules). */
export function compare(a: Bytes, b: Bytes): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i]! < b[i]! ? -1 : 1;
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

export function compareBig(a: bigint, b: bigint): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function absBig(a: bigint): bigint {
  return a < B0 ? -a : a;
}

function uintBytes(x: bigint, n: number): Bytes {
  if (x < B0 || x >= B1 << BigInt(8 * n)) throw new BykError(`value does not fit uint${8 * n}`);
  const out = new Uint8Array(n);
  let v = x;
  for (let i = n - 1; i >= 0; i--) {
    out[i] = Number(v & BigInt(255));
    v >>= BigInt(8);
  }
  return out;
}

function smallUint(x: number, n: number): Bytes {
  if (!Number.isInteger(x)) throw new BykError(`value does not fit uint${8 * n}`);
  return uintBytes(BigInt(x), n);
}

export const u8 = (x: number): Bytes => smallUint(x, 1);
export const u16 = (x: number): Bytes => smallUint(x, 2);
export const u32 = (x: number): Bytes => smallUint(x, 4);
export const u64 = (x: bigint): Bytes => uintBytes(x, 8);
export const word = (x: bigint): Bytes => uintBytes(x, 32);

/** Two's complement, big-endian. */
export function i64(x: bigint): Bytes {
  if (x < I64_MIN || x > I64_MAX) throw new BykError("value does not fit int64");
  return uintBytes(x < B0 ? x + (B1 << BigInt(64)) : x, 8);
}

/** Unsigned big-endian read of n bytes. */
export function readBig(b: Bytes, offset: number, n: number): bigint {
  if (offset < 0 || offset + n > b.length) throw new BykError("read outside buffer");
  let v = B0;
  for (let i = 0; i < n; i++) v = (v << BigInt(8)) | BigInt(b[offset + i]!);
  return v;
}

/** Unsigned big-endian read of at most 4 bytes, as a number. */
export function readNum(b: Bytes, offset: number, n: 1 | 2 | 4): number {
  return Number(readBig(b, offset, n));
}

export function readI64(b: Bytes, offset: number): bigint {
  const v = readBig(b, offset, 8);
  return v > I64_MAX ? v - (B1 << BigInt(64)) : v;
}

/** Section 4: division truncates toward zero. bigint division already does; the name keeps call sites
 *  readable next to the specification text. */
export function truncDiv(a: bigint, b: bigint): bigint {
  if (b === B0) throw new BykError("division by zero");
  return a / b;
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(b: Bytes): string {
  let n = b.length ? readBig(b, 0, b.length) : B0;
  let out = "";
  const base = BigInt(58);
  while (n > B0) {
    out = B58[Number(n % base)]! + out;
    n /= base;
  }
  let zeros = 0;
  while (zeros < b.length && b[zeros] === 0) zeros++;
  return "1".repeat(zeros) + out;
}

export function base58Decode(s: string): Bytes {
  let n = B0;
  const base = BigInt(58);
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) throw new BykError("bad base58 character");
    n = n * base + BigInt(i);
  }
  const body: number[] = [];
  while (n > B0) {
    body.unshift(Number(n & BigInt(255)));
    n >>= BigInt(8);
  }
  let ones = 0;
  while (ones < s.length && s[ones] === "1") ones++;
  return concat(new Uint8Array(ones), Uint8Array.from(body));
}
