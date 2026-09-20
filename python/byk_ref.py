"""BYK Data Layer v1 (rc6) reference implementation.

Pure Python 3.8+, standard library only. Not constant-time: use for test
vectors and verification, never for production signing.
"""
import functools
import hashlib
import hmac
import re
from fractions import Fraction

# =====================================================================
# Keccak-256 (original Keccak padding, as used by Ethereum; NOT SHA3-256)
# =====================================================================
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def _keccak_f(a):
    for rc in _RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M64) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                v = a[x + 5 * y]
                b[y + 5 * ((2 * x + 3 * y) % 5)] = (((v << r) | (v >> (64 - r))) & _M64) if r else v
        a = [b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= rc
    return a


@functools.lru_cache(maxsize=1 << 16)
def _keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    a = [0] * 25
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            a[i] ^= int.from_bytes(msg[off + 8 * i:off + 8 * i + 8], "little")
        a = _keccak_f(a)
    return b"".join(a[i].to_bytes(8, "little") for i in range(4))


def keccak256(data) -> bytes:
    return _keccak256(bytes(data))


assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
assert keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"

# =====================================================================
# secp256k1 ECDSA with RFC 6979 nonces, low-S, public-key recovery
# =====================================================================
P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
HALF_N = N // 2


def _jdouble(p):
    if p is None:
        return None
    x, y, z = p
    if y == 0:
        return None
    yy = y * y % P
    s_ = 4 * x * yy % P
    m = 3 * x * x % P
    x3 = (m * m - 2 * s_) % P
    return (x3, (m * (s_ - x3) - 8 * yy * yy) % P, 2 * y * z % P)


def _jadd(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1z1, z2z2 = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2z2 % P, x2 * z1z1 % P
    s1, s2 = y1 * z2 * z2z2 % P, y2 * z1 * z1z1 % P
    if u1 == u2:
        return _jdouble(p) if s1 == s2 else None
    h, r = (u2 - u1) % P, (s2 - s1) % P
    hh = h * h % P
    hhh = h * hh % P
    v = u1 * hh % P
    x3 = (r * r - hhh - 2 * v) % P
    return (x3, (r * (v - x3) - s1 * hhh) % P, h * z1 * z2 % P)


def _affine(p):
    if p is None:
        return None
    x, y, z = p
    zi = pow(z, P - 2, P)
    zi2 = zi * zi % P
    return (x * zi2 % P, y * zi2 * zi % P)


def _table(pt):
    t = [None, (pt[0], pt[1], 1)]
    for _ in range(14):
        t.append(_jadd(t[-1], t[1]))
    return t


_G_TABLE = _table(G)


def _mul(k, pt):
    """Scalar multiplication, 4-bit fixed window, Jacobian coordinates (not constant-time)."""
    if k == 0 or pt is None:
        return None
    t = _G_TABLE if pt == G else _table(pt)
    acc = None
    for shift in range(252, -1, -4):
        if acc is not None:
            acc = _jdouble(_jdouble(_jdouble(_jdouble(acc))))
        nib = (k >> shift) & 15
        if nib:
            acc = _jadd(acc, t[nib])
    return _affine(acc)


def _add(p1, p2):
    """Affine point addition (used by recovery)."""
    j1 = None if p1 is None else (p1[0], p1[1], 1)
    j2 = None if p2 is None else (p2[0], p2[1], 1)
    return _affine(_jadd(j1, j2))


def address_from_point(pt) -> bytes:
    return keccak256(pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big"))[12:]


@functools.lru_cache(maxsize=None)
def address_of_privkey(priv: int) -> bytes:
    return address_from_point(_mul(priv, G))


def _rfc6979_k(priv: int, digest: bytes) -> int:
    x = priv.to_bytes(32, "big")
    h = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


@functools.lru_cache(maxsize=None)
def sign_digest(priv: int, digest: bytes) -> bytes:
    """Canonical 65-byte signature r || s || recovery_id over a 32-byte digest."""
    assert len(digest) == 32 and 1 <= priv < N
    z = int.from_bytes(digest, "big")
    k = _rfc6979_k(priv, digest)
    rp = _mul(k, G)
    r = rp[0] % N
    s = pow(k, N - 2, N) * (z + r * priv) % N
    recid = (rp[1] & 1) | (2 if rp[0] >= N else 0)
    if s > HALF_N:
        s = N - s
        recid ^= 1
    if r == 0 or s == 0 or recid > 1:
        raise ValueError("unrepresentable signature (negligible probability)")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([recid])


@functools.lru_cache(maxsize=1 << 16)
def recover_address(digest: bytes, sig: bytes) -> bytes:
    """Rejects non-canonical input (high-S, recovery id not in {0,1}, bad lengths)."""
    if len(digest) != 32 or len(sig) != 65:
        raise ValueError("bad length")
    r = int.from_bytes(sig[0:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    v = sig[64]
    if not (1 <= r < N and 1 <= s <= HALF_N and v in (0, 1)):
        raise ValueError("non-canonical signature")
    y2 = (pow(r, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        raise ValueError("r is not an x-coordinate")
    if (y & 1) != v:
        y = P - y
    z = int.from_bytes(digest, "big") % N
    sr = _mul(s, (r, y))
    zg = _mul(z, G)
    q = _mul(pow(r, N - 2, N), _add(sr, None if zg is None else (zg[0], (-zg[1]) % P)))
    if q is None:
        raise ValueError("recovery failed")
    return address_from_point(q)


def high_s_variant(sig: bytes) -> bytes:
    s = int.from_bytes(sig[32:64], "big")
    return sig[0:32] + (N - s).to_bytes(32, "big") + bytes([1 - sig[64]])


# =====================================================================
# Encoding helpers
# =====================================================================
U64_MAX = 2 ** 64 - 1
EPOCH_MS = 300_000
ZERO32 = b"\x00" * 32


def u8(x): return x.to_bytes(1, "big")
def u16(x): return x.to_bytes(2, "big")
def u32(x): return x.to_bytes(4, "big")
def u64(x): return x.to_bytes(8, "big")
def i64(x): return x.to_bytes(8, "big", signed=True)
def rd(b, o, n): return int.from_bytes(b[o:o + n], "big")
def rds(b, o, n): return int.from_bytes(b[o:o + n], "big", signed=True)


def trunc_div(a: int, b: int) -> int:
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def id32(name: str) -> bytes:
    """Section 4.4: non-empty, every byte in 0x21..0x7E (no whitespace, no controls)."""
    if not name or any(not (0x21 <= ord(c) <= 0x7E) for c in name):
        raise ValueError("invalid identifier name: %r" % (name,))
    return keccak256(name.encode("ascii"))


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


STATUS = {"OK": 0, "DEGRADED": 1, "INSUFFICIENT_COVERAGE": 2, "NO_DATA": 3}
STATUS_NAME = {v: k for k, v in STATUS.items()}

# =====================================================================
# Records and Merkle tree
# =====================================================================
LEAF_LEN = 104


def leaf_bytes(status, decimals, feed_id, asset_id, observed_at_ms, value, source_count,
               expected_source_count, coverage_bps, outlier_count, max_source_age_ms, dispersion):
    b = (u8(1) + u8(status) + u8(decimals) + u8(0) + feed_id + asset_id + u64(observed_at_ms) +
         i64(value) + u16(source_count) + u16(expected_source_count) + u16(coverage_bps) +
         u16(outlier_count) + u32(max_source_age_ms) + i64(dispersion))
    validate_leaf(b)
    return b


def validate_leaf(b: bytes):
    if len(b) != LEAF_LEN or b[0] != 1 or b[3] != 0 or b[1] > 3:
        raise ValueError("bad leaf header")
    if b[1] in (2, 3) and (rds(b, 76, 8) != 0 or rds(b, 96, 8) != 0):
        raise ValueError("non-zero value/dispersion with status 2/3")
    if rds(b, 96, 8) < 0 or rd(b, 88, 2) > 10000:
        raise ValueError("bad quality field")


def leaf_hash(lb): return keccak256(b"\x00" + lb)
def node_hash(left, right): return keccak256(b"\x01" + left + right)


def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    if not leaves:
        return keccak256(b"")
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    k = _split(len(leaves))
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def audit_path(m, leaves):
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if m < k:
        return audit_path(m, leaves[:k]) + [mth(leaves[k:])]
    return audit_path(m - k, leaves[k:]) + [mth(leaves[:k])]


def verify_inclusion(leaf_index, tree_size, lh, path, root) -> bool:
    if leaf_index >= tree_size:
        return False
    fn, sn, r = leaf_index, tree_size - 1, lh
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not (fn & 1 or fn == 0):
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# =====================================================================
# Genesis core, manifest, authorization log
# =====================================================================
MAX_GOV_N = 4


def _check_gov(threshold, addrs):
    """Section 11.1: 1 <= M, N <= 4, N >= 2M - 1 (so any compromise of fewer than M keys
    leaves at least M honest keys), addresses 20 bytes strictly ascending."""
    n = len(addrs)
    if not (1 <= threshold and 1 <= n <= MAX_GOV_N and n >= 2 * threshold - 1):
        raise ValueError("governance bounds")
    if any(len(a) != 20 for a in addrs) or any(addrs[i] >= addrs[i + 1] for i in range(n - 1)):
        raise ValueError("governance addresses must be 20 bytes, strictly ascending")


def genesis_core_bytes(threshold, gov_addrs, genesis_epoch_start_ms, stream_name, base_chain_id,
                       solana_genesis_hash, base_eas_address):
    _check_gov(threshold, gov_addrs)
    assert genesis_epoch_start_ms % EPOCH_MS == 0
    assert len(solana_genesis_hash) == 32 and len(base_eas_address) == 20
    return (b"BYKG" + u8(1) + u8(threshold) + u8(len(gov_addrs)) + u8(0) + u64(genesis_epoch_start_ms) +
            id32(stream_name) + u64(base_chain_id) + solana_genesis_hash + base_eas_address + u32(0) +
            b"".join(gov_addrs))


GENESIS_FIXED_LEN = 112


def parse_genesis_core(b: bytes) -> dict:
    if len(b) < GENESIS_FIXED_LEN or b[0:4] != b"BYKG" or b[4] != 1 or b[7] != 0 or rd(b, 108, 4) != 0:
        raise ValueError("bad genesis core")
    m, n = b[5], b[6]
    if len(b) != GENESIS_FIXED_LEN + 20 * n:
        raise ValueError("bad genesis core length")
    addrs = [b[112 + 20 * i:132 + 20 * i] for i in range(n)]
    _check_gov(m, addrs)
    return dict(threshold=m, governance=addrs, genesis_epoch_start_ms=rd(b, 8, 8), stream_name_id=b[16:48],
                base_chain_id=rd(b, 48, 8), solana_genesis_hash=b[56:88], base_eas_address=b[88:108],
                stream_id=keccak256(b))


WK_DATA, WK_AL, WK_GENESIS = 1, 2, 3


def witness_key(stream_id: bytes, kind: int, n: int) -> bytes:
    """Section 12.3: per-item discovery key. Solana: the 32 bytes as an account key. Base: last 20 bytes as recipient."""
    assert len(stream_id) == 32 and kind in (WK_DATA, WK_AL, WK_GENESIS)
    return keccak256(b"BYKW" + stream_id + u8(kind) + u64(n))


MANIFEST_LEN = 200


def manifest_bytes(status, sequence, epoch_start_ms, epoch_end_ms, record_count, stream_id,
                   merkle_root, previous_commitment, schema_hash, methodology_hash):
    b = (b"BYKD" + u8(1) + u8(status) + u16(0) + u64(sequence) + u64(epoch_start_ms) + u64(epoch_end_ms) +
         u32(record_count) + u32(0) + stream_id + merkle_root + previous_commitment + schema_hash +
         methodology_hash)
    parse_manifest(b)
    return b


def parse_manifest(b: bytes) -> dict:
    """Structural checks of Section 13.1 step 1-2."""
    if len(b) != MANIFEST_LEN or b[0:4] != b"BYKD" or b[4] != 1 or rd(b, 6, 2) or rd(b, 36, 4):
        raise ValueError("bad manifest header")
    d = dict(status=b[5], sequence=rd(b, 8, 8), epoch_start_ms=rd(b, 16, 8), epoch_end_ms=rd(b, 24, 8),
             record_count=rd(b, 32, 4), stream_id=b[40:72], merkle_root=b[72:104],
             previous_commitment=b[104:136], schema_hash=b[136:168], methodology_hash=b[168:200])
    dur = d["epoch_end_ms"] - d["epoch_start_ms"]
    if d["status"] not in (0, 1, 3):
        raise ValueError("bad manifest status")
    if d["epoch_start_ms"] % EPOCH_MS or dur <= 0 or dur % EPOCH_MS:
        raise ValueError("bad window")
    if d["status"] in (0, 1) and dur != EPOCH_MS:
        raise ValueError("OK/DEGRADED window must be one epoch")
    if (d["status"] == 3) != (d["record_count"] == 0):
        raise ValueError("NO_DATA iff record_count == 0")
    if d["record_count"] == 0 and d["merkle_root"] != keccak256(b""):
        raise ValueError("empty tree root mismatch")
    if d["sequence"] == 0 and d["previous_commitment"] != ZERO32:
        raise ValueError("genesis previous_commitment must be zero")
    return d


AL_AUTHORIZE, AL_GOVERNANCE_UPDATE, AL_CHECKPOINT, AL_ACK = 1, 2, 3, 4


def _al_header(entry_type, body_len, log_seq, stream_id, prev_hash):
    return b"BYKL" + u8(1) + u8(entry_type) + u16(body_len) + u64(log_seq) + stream_id + prev_hash


def al_authorize(log_seq, stream_id, prev_hash, signer, valid_from, valid_until):
    body = signer + u32(0) + u64(valid_from) + u64(valid_until)
    return _al_header(AL_AUTHORIZE, len(body), log_seq, stream_id, prev_hash) + body


def al_governance_update(log_seq, stream_id, prev_hash, threshold, addrs):
    _check_gov(threshold, addrs)
    body = u8(threshold) + u8(len(addrs)) + u16(0) + b"".join(addrs)
    return _al_header(AL_GOVERNANCE_UPDATE, len(body), log_seq, stream_id, prev_hash) + body


def al_checkpoint(log_seq, stream_id, prev_hash, sequence, commitment):
    body = u64(sequence) + commitment
    return _al_header(AL_CHECKPOINT, len(body), log_seq, stream_id, prev_hash) + body


def al_ack(log_seq, stream_id, prev_hash):
    return _al_header(AL_ACK, 0, log_seq, stream_id, prev_hash)


def parse_al_entry(b: bytes) -> dict:
    if len(b) < 80 or b[0:4] != b"BYKL" or b[4] != 1 or len(b) != 80 + rd(b, 6, 2):
        raise ValueError("bad AL entry header")
    t = b[5]
    d = dict(entry_type=t, log_seq=rd(b, 8, 8), stream_id=b[16:48], previous_entry_hash=b[48:80],
             entry_hash=keccak256(b))
    body = b[80:]
    if t == AL_AUTHORIZE:
        if len(body) != 40 or rd(body, 20, 4):
            raise ValueError("bad AUTHORIZE body")
        d.update(signer=body[0:20], valid_from=rd(body, 24, 8), valid_until=rd(body, 32, 8))
    elif t == AL_GOVERNANCE_UPDATE:
        m, n = body[0], body[1]
        if rd(body, 2, 2) or len(body) != 4 + 20 * n:
            raise ValueError("bad GOVERNANCE_UPDATE body")
        addrs = [body[4 + 20 * i:24 + 20 * i] for i in range(n)]
        _check_gov(m, addrs)
        d.update(threshold=m, governance=addrs)
    elif t == AL_CHECKPOINT:
        if len(body) != 40:
            raise ValueError("bad CHECKPOINT body")
        d.update(sequence=rd(body, 0, 8), commitment=body[8:40])
    elif t == AL_ACK:
        if len(body) != 0:
            raise ValueError("bad ACK body")
    else:
        raise ValueError("unknown AL entry type")
    return d


def make_bundle(digest, privkeys):
    sigs = sorted(((address_of_privkey(k), sign_digest(k, digest)) for k in privkeys), key=lambda x: x[0])
    return b"".join(s for _, s in sigs)


def verify_bundle(digest, bundle, governance, threshold) -> bool:
    if len(bundle) == 0 or len(bundle) % 65:
        return False
    prev, count = b"", 0
    for i in range(0, len(bundle), 65):
        try:
            a = recover_address(digest, bundle[i:i + 65])
        except ValueError:
            return False
        if a not in governance or a <= prev:
            return False
        prev, count = a, count + 1
    return count >= threshold


def build_authorization_log(genesis: dict, found_entries):
    """Section 11.5. found_entries: (entry_bytes, bundle) pairs from admissible anchors within the as-of heights.

    Returns (state, head, status) with status in OK, GOVERNANCE_FORK, GOVERNANCE_FORK_TERMINAL.
    """
    by_seq = {}
    for eb, bundle in found_entries:
        try:
            e = parse_al_entry(eb)
        except ValueError:
            continue
        if e["stream_id"] == genesis["stream_id"]:
            by_seq.setdefault(e["log_seq"], []).append((e, bundle))
    state = dict(auth={}, checkpoints={}, governance=list(genesis["governance"]), threshold=genesis["threshold"])

    def apply(e):
        if e["entry_type"] == AL_AUTHORIZE:
            state["auth"][e["signer"]] = (e["valid_from"], e["valid_until"])
        elif e["entry_type"] == AL_GOVERNANCE_UPDATE:
            state["governance"], state["threshold"] = e["governance"], e["threshold"]
        elif e["entry_type"] == AL_CHECKPOINT:
            state["checkpoints"][e["sequence"]] = e["commitment"]

    prev, seq = ZERO32, 0
    while True:
        i = seq + 1
        valid = {}
        for e, bundle in by_seq.get(i, []):
            if e["previous_entry_hash"] == prev and verify_bundle(e["entry_hash"], bundle, state["governance"], state["threshold"]):
                valid[e["entry_hash"]] = e
        if not valid:
            return state, (seq, prev), "OK"
        if len(valid) == 1:
            e = next(iter(valid.values()))
            apply(e)
            prev, seq = e["entry_hash"], i
            continue
        pre_gov, pre_thr = list(state["governance"]), state["threshold"]
        fork_threshold = min(pre_thr + 1, len(pre_gov))
        conts = {}
        for e2, b2 in by_seq.get(i + 1, []):
            if (e2["entry_type"] == AL_ACK and e2["previous_entry_hash"] in valid
                    and verify_bundle(e2["entry_hash"], b2, pre_gov, fork_threshold)):
                conts[e2["entry_hash"]] = e2
        if not conts:
            return state, (seq, prev), "GOVERNANCE_FORK"
        if len(conts) > 1:
            return state, (seq, prev), "GOVERNANCE_FORK_TERMINAL"
        c = next(iter(conts.values()))
        apply(valid[c["previous_entry_hash"]])
        apply(c)
        prev, seq = c["entry_hash"], i + 1


def authorized(state, signer, sequence) -> bool:
    if signer not in state["auth"]:
        return False
    lo, hi = state["auth"][signer]
    return lo <= sequence and (hi == U64_MAX or sequence < hi)


def validate_manifest_in_stream(m: dict, genesis: dict) -> None:
    """Section 13.2 steps 5-7."""
    g0 = genesis["genesis_epoch_start_ms"]
    if m["stream_id"] != genesis["stream_id"]:
        raise ValueError("stream mismatch")
    if m["epoch_start_ms"] < g0 + m["sequence"] * EPOCH_MS:
        raise ValueError("epoch_start_ms < genesis_epoch_start_ms + sequence * 300000")
    if m["sequence"] == 0 and not (m["epoch_start_ms"] == g0 and m["epoch_end_ms"] == g0 + EPOCH_MS):
        raise ValueError("genesis window mismatch")


def max_sequence(genesis: dict, as_of_ms: int) -> int:
    """Section 13.5: S_max(T) = floor((T - G) / 300000) - 1, or -1 if nothing can have ended."""
    d = as_of_ms - genesis["genesis_epoch_start_ms"]
    return -1 if d < EPOCH_MS else d // EPOCH_MS - 1


def candidates(state, genesis, anchored_payloads, as_of_ms):
    """Section 13.4. anchored_payloads: (manifest_bytes, signature) pairs, each pair taken from ONE
    admissible anchor within the as-of heights. The signature must verify over that same manifest."""
    out = {}
    for mb, sig in anchored_payloads:
        try:
            m = parse_manifest(mb)
            validate_manifest_in_stream(m, genesis)
            signer = recover_address(keccak256(mb), sig)
        except ValueError:
            continue
        if m["epoch_end_ms"] > as_of_ms or not authorized(state, signer, m["sequence"]):
            continue
        out.setdefault(m["sequence"], {})[keccak256(mb)] = m
    return out


def resolve_canonical(state, cands, genesis, as_of_ms, target=None):
    """Section 13.5. Returns {sequence: (commitment or None, [flags])} for 0 .. min(target, S_max(T)).
    The loop bound is derived from T only, never from candidate or checkpoint sequence numbers."""
    result = {}
    prev_c, prev_m, gap = None, None, False
    s_max = max_sequence(genesis, as_of_ms)
    last = s_max if target is None else min(target, s_max)
    cps = {q: c for q, c in state["checkpoints"].items() if q <= s_max}
    assert all(q <= s_max for q in cands)
    for s in range(0, last + 1):
        cs, flags, res = cands.get(s, {}), [], None

        def links(m):
            return m["previous_commitment"] == prev_c and m["epoch_start_ms"] == prev_m["epoch_end_ms"]

        if s in cps:
            k = cps[s]
            if k not in cs:
                flags.append("CHECKPOINT_NOT_CANDIDATE")
            elif s == 0:
                res = k
            elif prev_c is None:
                res, gap = k, True
            elif links(cs[k]):
                res = k
            else:
                flags.append("CHECKPOINT_CONFLICT")
        elif s == 0:
            if len(cs) == 1:
                res = next(iter(cs))
            elif len(cs) > 1:
                flags.append("EQUIVOCATION")
        elif prev_c is not None:
            linked = [c for c, m in cs.items() if links(m)]
            if len(linked) == 1:
                res = linked[0]
            elif len(linked) > 1:
                flags.append("EQUIVOCATION")
        if res is not None and gap:
            flags.append("HISTORY_UNRESOLVED_BEFORE")
        result[s] = (res, flags)
        prev_c = res
        prev_m = cs[res] if res is not None else None
    return result


# =====================================================================
# Witness time (Section 12.7)
# =====================================================================
def base_as_of_block(block_ts_sec: dict, t_ms: int):
    """Highest block whose timestamp (seconds) x 1000 <= T."""
    ok = [b for b, ts in block_ts_sec.items() if ts * 1000 <= t_ms]
    return max(ok) if ok else None


def solana_as_of_slot(slot_time_sec: dict, t_ms: int):
    """Highest finalized slot with available block time whose time x 1000 <= T."""
    ok = [sl for sl, ts in slot_time_sec.items() if ts is not None and ts * 1000 <= t_ms]
    return max(ok) if ok else None


def solana_reported_time(slot_time_sec: dict, slot: int):
    """(time_ms or None, status) with status REPORTED, INFERRED or UNAVAILABLE."""
    if slot_time_sec.get(slot) is not None:
        return slot_time_sec[slot] * 1000, "REPORTED"
    later = sorted(sl for sl, ts in slot_time_sec.items() if sl > slot and ts is not None)
    if later:
        return slot_time_sec[later[0]] * 1000, "INFERRED"
    return None, "UNAVAILABLE"


# =====================================================================
# Witness payloads
# =====================================================================
def _word(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _dyn(b: bytes) -> bytes:
    return _word(len(b)) + b + b"\x00" * ((32 - len(b) % 32) % 32)


def abi_u64_b32_bytes_bytes(n, b32, x, y) -> bytes:
    """abi.encode(uint64, bytes32, bytes, bytes)"""
    tx = _dyn(x)
    return _word(n) + b32 + _word(4 * 32) + _word(4 * 32 + len(tx)) + tx + _dyn(y)


def abi_b32_bytes(b32, x) -> bytes:
    """abi.encode(bytes32, bytes)"""
    return b32 + _word(2 * 32) + _dyn(x)


def eas_schema_uid(schema: str, resolver: bytes = b"\x00" * 20, revocable: bool = False) -> bytes:
    """SchemaRegistry._getUID: keccak256(abi.encodePacked(schema, resolver, revocable))"""
    return keccak256(schema.encode("utf-8") + resolver + (b"\x01" if revocable else b"\x00"))


EAS_DATA_SCHEMA = "uint64 sequence,bytes32 commitment,bytes manifest,bytes signature"
EAS_AL_SCHEMA = "uint64 logSeq,bytes32 entryHash,bytes entry,bytes governanceSignatures"
EAS_GENESIS_SCHEMA = "bytes32 streamId,bytes genesisCore"


def memo_data(mb, sig): return "BYK1 " + mb.hex() + " " + sig.hex()
def memo_al(eb, bundle): return "BYKL1 " + eb.hex() + " " + bundle.hex()
def memo_genesis(core): return "BYKG1 " + core.hex()


# Conservative Solana size model for Section 12.2: legacy transaction, 1 signature,
# 5 account keys (fee payer, index, System, Memo, ComputeBudget), compute-unit-price,
# 0-lamport System transfer to the index address, one memo instruction.
SOLANA_TX_LIMIT = 1232
SOLANA_TX_OVERHEAD = 1 + 64 + 3 + 1 + 5 * 32 + 32 + 1 + (1 + 1 + 1 + 9) + (1 + 1 + 2 + 1 + 12) + (1 + 1 + 2)
MAX_MEMO_BYTES = SOLANA_TX_LIMIT - SOLANA_TX_OVERHEAD


# =====================================================================
# Section 13.8: Level 3 audit
# =====================================================================
def parse_leaf(b: bytes) -> dict:
    validate_leaf(b)
    return dict(status=b[1], decimals=b[2], feed_id=b[4:36], asset_id=b[36:68], observed_at_ms=rd(b, 68, 8),
                value=rds(b, 76, 8), source_count=rd(b, 84, 2), expected_source_count=rd(b, 86, 2),
                coverage_bps=rd(b, 88, 2), outlier_count=rd(b, 90, 2), max_source_age_ms=rd(b, 92, 4),
                dispersion=rds(b, 96, 8))


def audit_range(genesis, resolution, manifests, leaves_by_commitment, catalog, s_from, s_to,
                class_a_snapshots=None, methodology_params=None):
    """Section 13.8. resolution: output of resolve_canonical evaluated from sequence 0.
    manifests: {commitment: manifest_bytes}; leaves_by_commitment: {commitment: [leaf_bytes...]}.
    catalog: [(feed_name, asset_symbol, decimals, class)] with class "A" or "B".
    class_a_snapshots: {(sequence, feed_name, asset_symbol): {"T": ms, "parameters": {...}, "venues": [...]}}.
    methodology_params: the parameter set of the committed methodology document.
    Returns ("PASS", []) or ("FAIL", [reasons])."""
    reasons = []
    class_a_snapshots = class_a_snapshots or {}
    by_key = {id32(f) + id32(a): (f, a, dec, cls) for f, a, dec, cls in catalog}
    cat = sorted((k, v[2]) for k, v in by_key.items())
    for s in range(s_from, s_to + 1):
        if s not in resolution or resolution[s][0] is None:
            reasons.append("sequence %d: not CANONICAL" % s)
            continue
        c, flags = resolution[s]
        if "HISTORY_UNRESOLVED_BEFORE" in flags:
            reasons.append("sequence %d: HISTORY_UNRESOLVED_BEFORE" % s)
        m = parse_manifest(manifests[c])
        validate_manifest_in_stream(m, genesis)
        if s > 0:
            pc = resolution.get(s - 1, (None, []))[0]
            pm = parse_manifest(manifests[pc]) if pc is not None else None
            if pm is None or m["previous_commitment"] != pc or m["epoch_start_ms"] != pm["epoch_end_ms"]:
                reasons.append("sequence %d: chain or window discontinuity" % s)
        if m["status"] == STATUS["NO_DATA"]:
            continue                                     # genesis, gap or single-window NO_DATA: no leaf checks
        ls = leaves_by_commitment.get(c)
        if ls is None or len(ls) != m["record_count"]:
            reasons.append("sequence %d: leaf set missing or count mismatch" % s)
            continue
        try:
            parsed = [parse_leaf(lb) for lb in ls]
        except ValueError as err:
            reasons.append("sequence %d: invalid leaf (%s)" % (s, err))
            continue
        keys = [lb[4:68] for lb in ls]
        if any(keys[i] >= keys[i + 1] for i in range(len(keys) - 1)):
            reasons.append("sequence %d: leaves not strictly ascending" % s)
        if mth(ls) != m["merkle_root"]:
            reasons.append("sequence %d: merkle_root mismatch" % s)
        if any(not (m["epoch_start_ms"] <= q["observed_at_ms"] <= m["epoch_end_ms"]) for q in parsed):
            reasons.append("sequence %d: observed_at_ms outside window" % s)
        if sorted((lb[4:68], lb[2]) for lb in ls) != cat:
            reasons.append("sequence %d: leaf set or decimals differ from catalog" % s)
        derived = STATUS["OK"] if all(q["status"] == STATUS["OK"] for q in parsed) else STATUS["DEGRADED"]
        if derived != m["status"]:
            reasons.append("sequence %d: epoch status not derived from leaves" % s)
        for lb, q in zip(ls, parsed):                    # every Class A leaf, whatever its status
            entry = by_key.get(lb[4:68])
            if entry is None or entry[3] != "A":
                continue
            feed, asset = entry[0], entry[1]
            snap = class_a_snapshots.get((s, feed, asset))
            if snap is None:
                reasons.append("sequence %d: Class A snapshot missing for %s/%s" % (s, feed, asset))
                continue
            if snap["T"] != m["epoch_end_ms"] or snap["parameters"] != methodology_params:
                reasons.append("sequence %d: Class A snapshot T or parameters differ for %s/%s" % (s, feed, asset))
                continue
            try:
                exp, _ = funding_composite(snap["venues"], snap["parameters"], snap["T"])
            except (ValueError, KeyError) as err:
                reasons.append("sequence %d: Class A snapshot invalid for %s/%s (%s)" % (s, feed, asset, err))
                continue
            expected = dict(status=STATUS[exp["status"]], decimals=10, observed_at_ms=snap["T"], value=exp["value"],
                            source_count=exp["source_count"], expected_source_count=exp["expected_source_count"],
                            coverage_bps=exp["coverage_bps"], outlier_count=exp["outlier_count"],
                            max_source_age_ms=exp["max_source_age_ms"], dispersion=exp["dispersion"])
            diff = [k for k, v in expected.items() if q[k] != v]
            if diff:
                reasons.append("sequence %d: Class A recomputation mismatch for %s/%s (%s)" % (s, feed, asset, ", ".join(diff)))
    return ("PASS", []) if not reasons else ("FAIL", reasons)


# =====================================================================
# Annex A: BYK_FUNDING_COMPOSITE_V1 (reference computation)
# =====================================================================
_LEX_UNSIGNED = re.compile(r"^[0-9]+(\.[0-9]+)?$")
_LEX_SIGNED = re.compile(r"^-?[0-9]+(\.[0-9]+)?$")
_LEX_INTEGER = re.compile(r"^[0-9]{1,19}$")
I64_MAX = 2 ** 63 - 1
HOURLY_MAX = 2 ** 62 - 1
HOUR_MS = 3_600_000
RATE_SCALE = {"FRACTION": 10 ** 10, "PERCENT": 10 ** 8, "BPS": 10 ** 6}
TIME_SCALE = {"ms": 1, "s": 1000}
INTERVAL_SCALE = {"ms": 1, "s": 1000, "h": HOUR_MS}
INTERVAL_MIN_MS, INTERVAL_MAX_MS = 60_000, 86_400_000


def parse_lexeme(lex: str, signed: bool) -> Fraction:
    """Annex A.2 decimal lexeme: exact value of a raw token (JSON string content or JSON number token text)."""
    if not isinstance(lex, str) or len(lex) > 24:
        raise ValueError("lexeme length")
    if not (_LEX_SIGNED if signed else _LEX_UNSIGNED).match(lex):
        raise ValueError("lexeme grammar")
    neg = lex.startswith("-")
    whole, _, frac = lex.lstrip("-").partition(".")
    if len(frac) > 18:
        raise ValueError("too many fractional digits")
    v = Fraction(int(whole + frac), 10 ** len(frac))
    return -v if neg else v


def parse_integer_lexeme(lex: str, unit: str, scale: dict) -> int:
    """Annex A.2 integer lexeme: 1-19 ASCII digits, scaled by the catalog unit to milliseconds, <= 2^63 - 1."""
    if not isinstance(lex, str) or not _LEX_INTEGER.match(lex) or unit not in scale:
        raise ValueError("integer lexeme or unit")
    v = int(lex) * scale[unit]
    if v > I64_MAX:
        raise ValueError("integer exceeds 2^63 - 1 after unit scaling")
    return v


def _trunc(q: Fraction) -> int:
    n = abs(q.numerator) // q.denominator
    return -n if q < 0 else n


def _median_int(vals):
    v = sorted(vals)
    return v[len(v) // 2] if len(v) % 2 else trunc_div(v[len(v) // 2 - 1] + v[len(v) // 2], 2)


PARAM_BOUNDS = {                                     # Annex A.10: (min, max), all integers
    "decimals": (10, 10),
    "min_contributors": (1, 65535),
    "max_weight_bps": (1, 10000),
    "coverage_ok_bps": (0, 10000),
    "min_source_ratio_bps": (0, 10000),
    "stale_factor": (1, 1000),
    "oi_max_age_ms": (0, 604_800_000),
    "price_max_skew_ms": (0, 604_800_000),
    "outlier_k": (0, 1000),
    "outlier_floor": (0, HOURLY_MAX),
}


def validate_params(p, catalog_size):
    """Annex A.10 parameter constraints. The bounds make signed 256-bit arithmetic sufficient (A.2)."""
    if set(p) != set(PARAM_BOUNDS):
        raise ValueError("parameter set must contain exactly the A.10 parameters")
    for k, (lo, hi) in PARAM_BOUNDS.items():
        v = p[k]
        if isinstance(v, bool) or not isinstance(v, int) or not (lo <= v <= hi):
            raise ValueError("parameter out of bounds: %s" % k)
    if p["max_weight_bps"] * p["min_contributors"] < 10000 or not (1 <= catalog_size <= 65535):
        raise ValueError("invalid methodology parameters")


def funding_composite(venues, params, t_ms):
    """Annex A.3-A.8. Each venue dict holds catalog units and raw lexemes:
    venue, rate, rate_unit, interval, interval_unit, settlement_ts, settlement_ts_unit, oi_unit, oi_value,
    contract_size, mark_price, oi_ts, oi_ts_unit, price_ts, price_ts_unit.
    Returns (leaf_fields, per_venue_details). Every returned leaf is encodable (Section 7.1)."""
    p = params
    validate_params(p, len(venues))
    det = []
    for v in venues:
        d = dict(venue=v["venue"], vid=id32(v["venue"]), valid_rate=False, valid_oi=False, eligible=False)
        try:
            interval_ms = parse_integer_lexeme(v["interval"], v["interval_unit"], INTERVAL_SCALE)
            if not (INTERVAL_MIN_MS <= interval_ms <= INTERVAL_MAX_MS):
                raise ValueError("interval outside [60000, 86400000] ms")
            settle = parse_integer_lexeme(v["settlement_ts"], v["settlement_ts_unit"], TIME_SCALE)
            if v["rate_unit"] not in RATE_SCALE:
                raise ValueError("rate_unit")
            units = _trunc(parse_lexeme(v["rate"], True) * RATE_SCALE[v["rate_unit"]])
            if abs(units) > I64_MAX:
                raise ValueError("rate units exceed int64")
            hourly = trunc_div(units * HOUR_MS, interval_ms)
            if abs(hourly) > HOURLY_MAX:
                raise ValueError("hourly outside +-(2^62 - 1)")
            if not settle < t_ms:
                raise ValueError("settlement_ts >= T")
            d.update(interval_ms=interval_ms, units=units, hourly=hourly, settle_age=t_ms - settle,
                     valid_rate=True, stale=(t_ms - settle) > p["stale_factor"] * interval_ms)
        except ValueError as err:
            d.update(rate_error=str(err))
        try:
            oi_ts = parse_integer_lexeme(v["oi_ts"], v["oi_ts_unit"], TIME_SCALE)
            q = parse_lexeme(v["oi_value"], False)
            ages = [t_ms - oi_ts]
            if v["oi_unit"] == "QUOTE":
                pass
            elif v["oi_unit"] in ("BASE", "CONTRACTS"):
                if v.get("mark_price") is None or v.get("price_ts") is None:
                    raise ValueError("mark price required")
                price_ts = parse_integer_lexeme(v["price_ts"], v["price_ts_unit"], TIME_SCALE)
                if not (price_ts < t_ms and abs(oi_ts - price_ts) <= p["price_max_skew_ms"]):
                    raise ValueError("price timing")
                q = q * parse_lexeme(v["mark_price"], False)
                if v["oi_unit"] == "CONTRACTS":
                    q = q * parse_lexeme(v["contract_size"], False)
                ages.append(t_ms - price_ts)
            else:
                raise ValueError("oi_unit")
            oi_usd = _trunc(q)
            if not (1 <= oi_usd <= I64_MAX) or not (oi_ts < t_ms and t_ms - oi_ts <= p["oi_max_age_ms"]):
                raise ValueError("oi bounds or timing")
            d.update(oi_usd=oi_usd, valid_oi=True, oi_ages=ages)
        except ValueError as err:
            d.update(oi_error=str(err))
        d["eligible"] = d["valid_rate"] and not d["stale"] and d["valid_oi"] if d["valid_rate"] else False
        det.append(d)

    n_exp = len(venues)
    leaf = dict(value=0, dispersion=0, source_count=0, expected_source_count=n_exp, coverage_bps=0,
                outlier_count=0, max_source_age_ms=0, status="NO_DATA")
    elig = [d for d in det if d["eligible"]]
    if not elig:                                        # A.8 step 2
        return leaf, det

    srt = sorted(elig, key=lambda d: (d["hourly"], d["vid"]))
    tot, cum, m = sum(d["oi_usd"] for d in srt), 0, None
    for d in srt:
        cum += d["oi_usd"]
        if 2 * cum >= tot:
            m = d["hourly"]
            break
    mad = _median_int([abs(d["hourly"] - m) for d in elig])
    tau = max(p["outlier_k"] * mad, p["outlier_floor"])
    contrib = [d for d in elig if abs(d["hourly"] - m) <= tau]       # non-empty (median venue)
    for d in elig:
        d["outlier"] = d not in contrib
    cov = trunc_div(10000 * sum(d["oi_usd"] for d in contrib), sum(d["oi_usd"] for d in det if d["valid_oi"]))
    age = min(max(max([d["settle_age"]] + d["oi_ages"]) for d in contrib), 2 ** 32 - 1)
    leaf.update(source_count=len(contrib), outlier_count=len(elig) - len(contrib), coverage_bps=cov,
                max_source_age_ms=age, median=m, mad=mad, tau=tau)
    if len(contrib) < p["min_contributors"]:          # A.8 step 4
        leaf["status"] = "INSUFFICIENT_COVERAGE"
        return leaf, det

    # A.8 step 5: n >= min_contributors and cap * min_contributors >= 10000, so cap * n >= 10000
    cap, n = p["max_weight_bps"], len(contrib)
    order = sorted(contrib, key=lambda d: (-d["oi_usd"], d["vid"]))
    k = 0
    while True:
        denom = 10000 - cap * k
        assert denom > 0 and k < n                     # proven in A.8
        x = trunc_div(cap * sum(d["oi_usd"] for d in order[k:]), denom)
        if order[k]["oi_usd"] <= x:
            break
        k += 1
    w = {d["venue"]: (x if i < k else d["oi_usd"]) for i, d in enumerate(order)}
    sw = sum(w.values())
    assert all(Fraction(wi, sw) <= Fraction(cap, 10000) for wi in w.values())
    r = trunc_div(sum(w[d["venue"]] * d["hourly"] for d in contrib), sw)
    disp = _median_int([abs(d["hourly"] - r) for d in contrib])
    assert abs(r) <= HOURLY_MAX and 0 <= disp <= I64_MAX   # A.6 bound makes both encodable
    ok = cov >= p["coverage_ok_bps"] and 10000 * n >= p["min_source_ratio_bps"] * n_exp
    leaf.update(value=r, dispersion=disp, status="OK" if ok else "DEGRADED", weights=w, capped_count=k,
                cap_weight=x if k else None, max_weight_share_bps=trunc_div(10000 * max(w.values()), sw))
    return leaf, det
