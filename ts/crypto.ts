/* BYK Data Layer v1 (rc6) · Sections 4.3 and 10: Keccak-256 (original padding, as on Ethereum, NOT SHA3-256)
 * and secp256k1 ECDSA over a 32-byte digest with RFC 6979 nonces, low-S, 65-byte r || s || recovery_id. */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

import { B0, B1, BykError, type Bytes, concat, readBig, word } from "./bytes";

const N = secp256k1.CURVE.n;
const HALF_N = N / BigInt(2);

export function keccak256(data: Bytes): Bytes {
  return keccak_256(data);
}

function addressFromUncompressed(pub: Bytes): Bytes {
  // 0x04 || X || Y: the address is the last 20 bytes of keccak256(X || Y)
  return keccak256(pub.subarray(1)).subarray(12);
}

function checkPrivateKey(priv: Bytes): void {
  if (priv.length !== 32) throw new BykError("private key must be 32 bytes");
  const k = readBig(priv, 0, 32);
  if (k < B1 || k >= N) throw new BykError("private key out of range");
}

export function addressOfPrivateKey(priv: Bytes): Bytes {
  checkPrivateKey(priv);
  return addressFromUncompressed(secp256k1.getPublicKey(priv, false));
}

/** Canonical signature over a 32-byte digest. Deterministic: the same key and digest always give the same
 *  65 bytes, which is what lets a re-submitted manifest carry an identical signature. */
export function signDigest(priv: Bytes, digest: Bytes): Bytes {
  checkPrivateKey(priv);
  if (digest.length !== 32) throw new BykError("digest must be 32 bytes");
  const sig = secp256k1.sign(digest, priv, { lowS: true });
  if (sig.r === B0 || sig.s === B0 || sig.recovery === undefined || sig.recovery > 1) {
    throw new BykError("unrepresentable signature (negligible probability)");
  }
  return concat(word(sig.r), word(sig.s), Uint8Array.of(sig.recovery));
}

/** Signer address of a canonical signature. Rejects high-S, a recovery id outside {0, 1} and bad lengths,
 *  so exactly one byte string is accepted per (key, digest). */
export function recoverAddress(digest: Bytes, sig: Bytes): Bytes {
  if (digest.length !== 32 || sig.length !== 65) throw new BykError("bad length");
  const r = readBig(sig, 0, 32);
  const s = readBig(sig, 32, 32);
  const v = sig[64]!;
  if (!(r >= B1 && r < N && s >= B1 && s <= HALF_N && (v === 0 || v === 1))) throw new BykError("non-canonical signature");
  try {
    const point = new secp256k1.Signature(r, s).addRecoveryBit(v).recoverPublicKey(digest);
    return addressFromUncompressed(point.toRawBytes(false));
  } catch {
    throw new BykError("recovery failed");
  }
}

/** Test helper for negative case N1: the same signature with s -> n - s and the recovery id flipped. */
export function highSVariant(sig: Bytes): Bytes {
  if (sig.length !== 65) throw new BykError("bad length");
  return concat(sig.subarray(0, 32), word(N - readBig(sig, 32, 32)), Uint8Array.of(1 - sig[64]!));
}
