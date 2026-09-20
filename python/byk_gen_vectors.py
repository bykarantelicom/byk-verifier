#!/usr/bin/env python3
"""BYK Data Layer v1.0.0-rc6 test vector generator. Standard library only.

Usage: python3 byk_gen_vectors.py   ->  writes byk_v1_test_vectors.json
"""
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import byk_ref as R  # noqa: E402

OUT = "byk_v1_test_vectors.json"


def hx(b): return b.hex()
def iso(ms): return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def key(h, expected):
    k = int(h, 16)
    assert "0x" + R.address_of_privkey(k).hex() == expected.lower(), (h, expected)
    return k


# public development keys, TEST ONLY
S1 = key("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
G1 = key("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
G2 = key("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a", "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
G3 = key("7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6", "0x90F79bf6EB2c4f870365E785982E1f101E93b906")
G4 = key("47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a", "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65")
S2 = key("8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba", "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc")
A = R.address_of_privkey

V = {"version": "1.0.0-rc6"}
V["network_constants"] = {
    "base_mainnet_chain_id": 8453, "base_sepolia_chain_id": 84532,
    "solana_mainnet_beta_genesis_hash_b58": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
    "solana_mainnet_beta_genesis_hash_hex": hx(R.b58decode("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d")),
    "solana_devnet_genesis_hash_b58": "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
    "solana_devnet_genesis_hash_hex": hx(R.b58decode("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG")),
    "base_eas_address": "0x4200000000000000000000000000000000000021",
}
V["encoding"] = {
    "keccak256('')": hx(R.keccak256(b"")), "keccak256('abc')": hx(R.keccak256(b"abc")),
    "id32('BYK.BTC.FUNDING.COMPOSITE')": hx(R.id32("BYK.BTC.FUNDING.COMPOSITE")), "id32('BTC')": hx(R.id32("BTC")),
    "int64(-48750)": hx(R.i64(-48750)), "int64(6872)": hx(R.i64(6872)),
    "trunc_div(-7,2)": R.trunc_div(-7, 2), "trunc_div(7,-2)": R.trunc_div(7, -2), "trunc_div(-7,-2)": R.trunc_div(-7, -2),
    "id32 rejects": ["'' (empty)", "'BTC ' (space)", "'B TC'", "'BT\\nC'", "non-ASCII", "0x7F"],
}

# ---------------------------------------------------------------- genesis core
T0 = 1_789_257_600_000
GOV = sorted([A(G1), A(G2), A(G3)])
core = R.genesis_core_bytes(2, GOV, T0, "BYK.DATALAYER.TESTVECTORS", 84532,
                            R.b58decode("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"),
                            bytes.fromhex("4200000000000000000000000000000000000021"))
genesis = R.parse_genesis_core(core)
STREAM = genesis["stream_id"]
V["genesis_core"] = {
    "threshold": 2, "governance_sorted": ["0x" + hx(a) for a in GOV], "genesis_epoch_start_ms": T0,
    "genesis_epoch_start_utc": iso(T0), "stream_name": "BYK.DATALAYER.TESTVECTORS", "base_chain_id": 84532,
    "solana_cluster": "devnet", "genesis_core_hex": hx(core), "genesis_core_length": len(core), "stream_id": hx(STREAM),
}


def wk(kind, n):
    k = R.witness_key(STREAM, kind, n)
    return {"key_hex": hx(k), "solana_address_b58": R.b58encode(k), "base_recipient": "0x" + hx(k[12:])}


V["witness_keys"] = {"data_sequence_0": wk(R.WK_DATA, 0), "data_sequence_1": wk(R.WK_DATA, 1),
                     "al_log_seq_1": wk(R.WK_AL, 1), "genesis": wk(R.WK_GENESIS, 0)}

# ---------------------------------------------------------------- Class A inputs (Annex A) used by the epochs
PRM = dict(decimals=10, min_contributors=5, coverage_ok_bps=9500, min_source_ratio_bps=7000, stale_factor=2,
           oi_max_age_ms=900_000, price_max_skew_ms=60_000, outlier_k=5, outlier_floor=50_000, max_weight_bps=3500)
HOUR = 3_600_000


def ms_or_s(ms, unit):
    assert unit == "ms" or ms % 1000 == 0
    return (str(ms), "ms") if unit == "ms" else (str(ms // 1000), "s")


def venue_at(Tx, name, rate, rate_unit, interval, interval_unit, settle_age, settle_unit, unit, oi, csize, px,
             oi_age=60_000, px_age=55_000, ts_unit="s"):
    st, stu = ms_or_s(Tx - settle_age, settle_unit)
    ot, otu = ms_or_s(Tx - oi_age, ts_unit)
    v = dict(venue=name, rate=rate, rate_unit=rate_unit, interval=interval, interval_unit=interval_unit,
             settlement_ts=st, settlement_ts_unit=stu, oi_unit=unit, oi_value=oi, contract_size=csize, mark_price=px,
             oi_ts=ot, oi_ts_unit=otu, price_ts=None, price_ts_unit=None)
    if px is not None:
        v["price_ts"], v["price_ts_unit"] = ms_or_s(Tx - px_age, ts_unit)
    return v


def venues_main(Tx):
    return [
        venue_at(Tx, "venue-a", "0.0001", "FRACTION", "8", "h", 1_512_000, "s", "BASE", "42000", None, "100000"),
        venue_at(Tx, "venue-b", "0.008", "PERCENT", "28800", "s", 1_512_000, "ms", "QUOTE", "2900000000.75", None, None, ts_unit="ms"),
        venue_at(Tx, "venue-c", "0.000013", "FRACTION", "3600000", "ms", 912_000, "s", "CONTRACTS", "13000000", "0.001", "100000"),
        venue_at(Tx, "venue-d", "1.12", "BPS", "8", "h", 1_512_000, "ms", "BASE", "11000", None, "100000", ts_unit="ms"),
        venue_at(Tx, "venue-e", "0.000046", "FRACTION", "14400", "s", 1_512_000, "s", "CONTRACTS", "900000", "0.01", "100000"),
        venue_at(Tx, "venue-f", "0.00064", "FRACTION", "8", "h", 1_512_000, "s", "QUOTE", "300000000", None, None),
        venue_at(Tx, "venue-g", "0.00009", "FRACTION", "8", "h", 17 * HOUR, "s", "BASE", "5000", None, "100000"),
    ]


def venues_insufficient(Tx):
    vs = venues_main(Tx)
    for v in vs:
        if v["venue"] in ("venue-d", "venue-e"):
            oi_ms = int(v["oi_ts"]) * R.TIME_SCALE[v["oi_ts_unit"]]
            v["price_ts"], v["price_ts_unit"] = str(oi_ms - 120_000), "ms"
    return vs


def venues_negated(Tx):
    vs = venues_main(Tx)
    for v in vs:
        v["rate"] = "-" + v["rate"]
    return vs


VENUE_SETS = {"BYK.BTC.FUNDING.COMPOSITE": ("BTC", venues_main), "BYK.ETH.FUNDING.COMPOSITE": ("ETH", venues_insufficient),
              "BYK.SOL.FUNDING.COMPOSITE": ("SOL", venues_negated)}
CATALOG = [("BYK.BTC.FUNDING.COMPOSITE", "BTC", 10, "A"), ("BYK.ETH.FUNDING.COMPOSITE", "ETH", 10, "A"),
           ("BYK.SOL.FUNDING.COMPOSITE", "SOL", 10, "A"), ("BYK.BTC.VPIN", "BTC", 4, "B")]
LABELS = {"BYK.BTC.FUNDING.COMPOSITE": "BTC funding composite (Class A, from snapshot)",
          "BYK.ETH.FUNDING.COMPOSITE": "ETH funding composite (Class A, INSUFFICIENT_COVERAGE, from snapshot)",
          "BYK.SOL.FUNDING.COMPOSITE": "SOL funding composite (Class A, negative value, from snapshot)",
          "BYK.BTC.VPIN": "BTC VPIN (Class B)"}


def epoch_records(Tx, seq, drop=None, mutate=None):
    """Leaves of an OK/DEGRADED epoch ending at Tx. Class A leaves are computed from snapshots.
    mutate: {feed: {field: new_value}} applied AFTER computation (adversarial vectors)."""
    recs, snaps = [], {}
    for feed, asset, dec, cls in CATALOG:
        if drop == feed:
            continue
        fid, aid = R.id32(feed), R.id32(asset)
        if cls == "A":
            venues = VENUE_SETS[feed][1](Tx)
            lf, _ = R.funding_composite(venues, PRM, Tx)
            f = dict(status=R.STATUS[lf["status"]], value=lf["value"], source_count=lf["source_count"],
                     expected_source_count=lf["expected_source_count"], coverage_bps=lf["coverage_bps"],
                     outlier_count=lf["outlier_count"], max_source_age_ms=lf["max_source_age_ms"], dispersion=lf["dispersion"])
            snaps[(seq, feed, asset)] = {"T": Tx, "parameters": PRM, "venues": venues}
        else:
            f = dict(status=0, value=6872, source_count=11, expected_source_count=11, coverage_bps=10000,
                     outlier_count=0, max_source_age_ms=812, dispersion=0)
        f.update((mutate or {}).get(feed, {}))
        lb = R.leaf_bytes(f["status"], dec, fid, aid, Tx, f["value"], f["source_count"], f["expected_source_count"],
                          f["coverage_bps"], f["outlier_count"], f["max_source_age_ms"], f["dispersion"])
        recs.append((fid + aid, LABELS[feed], feed, asset, lb))
    recs.sort(key=lambda r: r[0])
    status = 0 if all(r[4][1] == 0 for r in recs) else 1
    return recs, snaps, status


# ---------------------------------------------------------------- epochs
schema_hash = R.keccak256(b"BYK test vector schema document v1")
methodology_hash = R.keccak256(b"BYK test vector methodology registry v1")
EMPTY, E = R.keccak256(b""), R.EPOCH_MS

M0 = R.manifest_bytes(3, 0, T0, T0 + E, 0, STREAM, EMPTY, R.ZERO32, schema_hash, methodology_hash)
C0 = R.keccak256(M0)
e1_end = T0 + 2 * E
recs, SNAPS1, st1 = epoch_records(e1_end, 1)
leaves = [r[4] for r in recs]
root1 = R.mth(leaves)
M1 = R.manifest_bytes(st1, 1, T0 + E, e1_end, len(leaves), STREAM, root1, C0, schema_hash, methodology_hash)
C1 = R.keccak256(M1)
sig_M0_S1, sig_M1_S1 = R.sign_digest(S1, C0), R.sign_digest(S1, C1)
V["genesis_manifest"] = {"manifest_hex": hx(M0), "commitment": hx(C0), "signature_S1": hx(sig_M0_S1)}
lv = []
for i, (_, label, feed, asset, lb) in enumerate(recs):
    p = R.audit_path(i, leaves)
    assert R.verify_inclusion(i, len(leaves), R.leaf_hash(lb), p, root1)
    lv.append({"leaf_index": i, "label": label, "feed": feed, "asset": asset, "leaf_hex": hx(lb),
               "leaf_hash": hx(R.leaf_hash(lb)), "audit_path": [hx(x) for x in p]})
V["epoch1"] = {
    "leaves": lv, "internal_node_0_1": hx(R.node_hash(R.leaf_hash(leaves[0]), R.leaf_hash(leaves[1]))),
    "merkle_root": hx(root1), "manifest_hex": hx(M1), "commitment": hx(C1), "signature_S1": hx(sig_M1_S1),
    "signature_r": hx(sig_M1_S1[:32]), "signature_s": hx(sig_M1_S1[32:64]), "recovery_id": sig_M1_S1[64],
    "evm_v": sig_M1_S1[64] + 27, "signer_S1": "0x" + hx(A(S1)), "high_s_variant_must_be_rejected": hx(R.high_s_variant(sig_M1_S1)),
}
_ls5 = [bytes([1, 0, 0, 0]) + bytes([i]) * 100 for i in range(5)]
V["tree_size_finding"] = {"description": "proof for leaf 0 of a 5-leaf tree verifies against the same root when tree_size 6 is claimed",
                          "verifies": R.verify_inclusion(0, 6, R.leaf_hash(_ls5[0]), R.audit_path(0, _ls5), R.mth(_ls5))}
assert V["tree_size_finding"]["verifies"] is True

# ---------------------------------------------------------------- scenario manifests
M2a = R.manifest_bytes(3, 2, T0 + 2 * E, T0 + 3 * E, 0, STREAM, EMPTY, C1, schema_hash, methodology_hash)
M2b = R.manifest_bytes(3, 2, T0 + 2 * E, T0 + 4 * E, 0, STREAM, EMPTY, C1, schema_hash, methodology_hash)
M2bad = R.manifest_bytes(3, 2, T0 + 2 * E, T0 + 3 * E, 0, STREAM, EMPTY, C0, schema_hash, methodology_hash)
C2a, C2b, C2bad = R.keccak256(M2a), R.keccak256(M2b), R.keccak256(M2bad)
M3 = R.manifest_bytes(3, 3, T0 + 3 * E, T0 + 4 * E, 0, STREAM, EMPTY, C2a, schema_hash, methodology_hash)
C3 = R.keccak256(M3)
M4 = R.manifest_bytes(3, 4, T0 + 4 * E, T0 + 5 * E, 0, STREAM, EMPTY, C3, schema_hash, methodology_hash)
C4 = R.keccak256(M4)
M5 = R.manifest_bytes(3, 5, T0 + 5 * E, T0 + 6 * E, 0, STREAM, EMPTY, C4, schema_hash, methodology_hash)
C5 = R.keccak256(M5)
M1x = R.manifest_bytes(3, 1, T0 + E, T0 + 2 * E, 0, STREAM, EMPTY, C0, schema_hash, methodology_hash)
C1x = R.keccak256(M1x)
FAR_SEQ = 1_000_000_000
M_far = R.manifest_bytes(3, FAR_SEQ, T0 + FAR_SEQ * E, T0 + (FAR_SEQ + 1) * E, 0, STREAM, EMPTY, C0, schema_hash, methodology_hash)
MAX_START = ((R.U64_MAX - E) // E) * E
M_max = R.manifest_bytes(3, R.U64_MAX, MAX_START, MAX_START + E, 0, STREAM, EMPTY, C0, schema_hash, methodology_hash)
GARBAGE_SIG = b"\x01" * 65
T_TEST = T0 + 6 * E + 60_000
sig = {n: R.sign_digest(S1, R.keccak256(m)) for n, m in (("M2a", M2a), ("M2b", M2b), ("M2bad", M2bad), ("M3", M3),
                                                           ("M4", M4), ("M5", M5), ("M_far", M_far), ("M_max", M_max))}
sig_S2 = {n: R.sign_digest(S2, R.keccak256(m)) for n, m in (("M2a", M2a), ("M3", M3))}
NAMES = {C0: "C0", C1: "C1", C2a: "C2a", C2b: "C2b", C2bad: "C2bad", C3: "C3", C4: "C4", C5: "C5", C1x: "C1x"}
P_BASE = [(M0, sig_M0_S1), (M1, sig_M1_S1)]
P_FORK = P_BASE + [(M2a, sig["M2a"]), (M2b, sig["M2b"]), (M3, sig["M3"])]
P_BADLINK = P_BASE + [(M2a, sig["M2a"]), (M2bad, sig["M2bad"]), (M3, sig["M3"])]

# ---------------------------------------------------------------- authorization log entries
def entry(eb, signers):
    return eb, R.make_bundle(R.keccak256(eb), signers)


E1 = entry(R.al_authorize(1, STREAM, R.ZERO32, A(S1), 0, R.U64_MAX), [G2, G1])
h1 = R.keccak256(E1[0])
E2b = entry(R.al_checkpoint(2, STREAM, h1, 2, C2a), [G1, G3])
E2c = entry(R.al_checkpoint(2, STREAM, h1, 2, C2b), [G2, G3])
E2d = entry(R.al_authorize(2, STREAM, h1, A(S1), 0, 2), [G1, G2])
E3d = entry(R.al_authorize(3, STREAM, R.keccak256(E2d[0]), A(S2), 2, R.U64_MAX), [G1, G2])
E2bad = entry(R.al_checkpoint(2, STREAM, h1, 2, C2bad), [G1, G2])
E2restart = entry(R.al_checkpoint(2, STREAM, h1, 3, C3), [G1, G2])
GOV2 = sorted([A(G1), A(G2), A(G4)])
E2e = entry(R.al_governance_update(2, STREAM, h1, 2, GOV2), [G2, G3])
E3e_eb = R.al_authorize(3, STREAM, R.keccak256(E2e[0]), A(S2), 4, R.U64_MAX)
E3e_new = (E3e_eb, R.make_bundle(R.keccak256(E3e_eb), [G1, G4]))
E3e_old = (E3e_eb, R.make_bundle(R.keccak256(E3e_eb), [G1, G3]))
ACK_b = R.al_ack(3, STREAM, R.keccak256(E2b[0]))
ACK_c = R.al_ack(3, STREAM, R.keccak256(E2c[0]))
ACK_b_all = (ACK_b, R.make_bundle(R.keccak256(ACK_b), [G1, G2, G3]))
ACK_b_two = (ACK_b, R.make_bundle(R.keccak256(ACK_b), [G1, G2]))
ACK_c_all = (ACK_c, R.make_bundle(R.keccak256(ACK_c), [G1, G2, G3]))
CP_cont = R.al_checkpoint(3, STREAM, R.keccak256(E2b[0]), 1, C1)
CP_cont_all = (CP_cont, R.make_bundle(R.keccak256(CP_cont), [G1, G2, G3]))


def run(log, payloads):
    state, head, status = R.build_authorization_log(genesis, log)
    if status != "OK":
        return {"al_status": status, "head_log_seq": head[0]}
    cands = R.candidates(state, genesis, payloads, T_TEST)
    res = R.resolve_canonical(state, cands, genesis, T_TEST)
    return {"al_status": status, "head_log_seq": head[0],
            "canonical": {str(s): ({"commitment": NAMES[c], "flags": f} if c else {"commitment": "UNRESOLVED", "flags": f})
                          for s, (c, f) in sorted(res.items())}}


def short(r):
    if r["al_status"] != "OK":
        return r["al_status"]
    return {s: v["commitment"] + ("[" + ",".join(v["flags"]) + "]" if v["flags"] else "") for s, v in r["canonical"].items()}


S = {}
S["A_fork_no_action"] = run([E1], P_FORK)
S["B_checkpoint_C2a"] = run([E1, E2b], P_FORK)
S["C_checkpoint_C2b"] = run([E1, E2c], P_FORK)
S["D_revoke_and_resign"] = run([E1, E2d, E3d], P_FORK + [(M2a, sig_S2["M2a"]), (M3, sig_S2["M3"])])
S["E0_orphan_does_not_block"] = run([E1], P_BADLINK)
S["E1_checkpoint_non_linking"] = run([E1, E2bad], P_BADLINK)
S["F_restart_after_unresolved"] = run([E1, E2restart], P_FORK + [(M4, sig["M4"]), (M5, sig["M5"])])
S["G1_governance_fork"] = run([E1, E2b, E2c], P_FORK)
S["G2_fork_resolved_by_ack_3of3"] = run([E1, E2b, E2c, ACK_b_all], P_FORK)
S["G3_ack_below_fork_threshold"] = run([E1, E2b, E2c, ACK_b_two], P_FORK)
S["G4_conflicting_acks"] = run([E1, E2b, E2c, ACK_b_all, ACK_c_all], P_FORK)
S["G5_non_ack_continuation"] = run([E1, E2b, E2c, CP_cont_all], P_FORK)
S["G6_same_ack_two_bundles"] = run([E1, E2b, E2c, ACK_b_all, ACK_b_two], P_FORK)
S["H_signature_binding"] = run([E1], P_BASE[:1] + [(M1, GARBAGE_SIG), (M1x, sig_M1_S1)])
S["I_far_sequence_dos"] = run([E1], P_FORK + [(M_far, sig["M_far"]), (M_max, sig["M_max"])])
SH = {k: short(v) for k, v in S.items()}
assert SH["A_fork_no_action"] == {"0": "C0", "1": "C1", "2": "UNRESOLVED[EQUIVOCATION]", "3": "UNRESOLVED", "4": "UNRESOLVED", "5": "UNRESOLVED"}
assert SH["B_checkpoint_C2a"] == {"0": "C0", "1": "C1", "2": "C2a", "3": "C3", "4": "UNRESOLVED", "5": "UNRESOLVED"}
assert SH["C_checkpoint_C2b"] == {"0": "C0", "1": "C1", "2": "C2b", "3": "UNRESOLVED", "4": "UNRESOLVED", "5": "UNRESOLVED"}
assert SH["D_revoke_and_resign"] == {"0": "C0", "1": "C1", "2": "C2a", "3": "C3", "4": "UNRESOLVED", "5": "UNRESOLVED"}
assert SH["E0_orphan_does_not_block"] == {"0": "C0", "1": "C1", "2": "C2a", "3": "C3", "4": "UNRESOLVED", "5": "UNRESOLVED"}
assert SH["E1_checkpoint_non_linking"] == {"0": "C0", "1": "C1", "2": "UNRESOLVED[CHECKPOINT_CONFLICT]", "3": "UNRESOLVED", "4": "UNRESOLVED", "5": "UNRESOLVED"}
assert SH["F_restart_after_unresolved"] == {"0": "C0", "1": "C1", "2": "UNRESOLVED[EQUIVOCATION]", "3": "C3[HISTORY_UNRESOLVED_BEFORE]",
                                            "4": "C4[HISTORY_UNRESOLVED_BEFORE]", "5": "C5[HISTORY_UNRESOLVED_BEFORE]"}
assert SH["G1_governance_fork"] == "GOVERNANCE_FORK"
assert SH["G2_fork_resolved_by_ack_3of3"] == {"0": "C0", "1": "C1", "2": "C2a", "3": "C3", "4": "UNRESOLVED", "5": "UNRESOLVED"}
assert S["G2_fork_resolved_by_ack_3of3"]["head_log_seq"] == 3
assert SH["G3_ack_below_fork_threshold"] == "GOVERNANCE_FORK"
assert SH["G4_conflicting_acks"] == "GOVERNANCE_FORK_TERMINAL"
assert SH["G5_non_ack_continuation"] == "GOVERNANCE_FORK"
assert SH["G6_same_ack_two_bundles"] == {"0": "C0", "1": "C1", "2": "C2a", "3": "C3", "4": "UNRESOLVED", "5": "UNRESOLVED"}
assert SH["H_signature_binding"] == {"0": "C0", "1": "UNRESOLVED", "2": "UNRESOLVED", "3": "UNRESOLVED", "4": "UNRESOLVED", "5": "UNRESOLVED"}
assert SH["I_far_sequence_dos"] == SH["A_fork_no_action"]

# DoS bound: far manifests are never candidates; the resolver range is bounded by S_max(T)
_stI, _, _ = R.build_authorization_log(genesis, [E1])
_cI = R.candidates(_stI, genesis, P_FORK + [(M_far, sig["M_far"]), (M_max, sig["M_max"])], T_TEST)
assert FAR_SEQ not in _cI and R.U64_MAX not in _cI and max(_cI) == 3
_resI = R.resolve_canonical(_stI, _cI, genesis, T_TEST)
assert max(_resI) == 5
S_MAX_TEST = R.max_sequence(genesis, T_TEST)
assert S_MAX_TEST == 5
try:
    R.validate_manifest_in_stream(R.parse_manifest(M_max), genesis)
    raise AssertionError("M_max must violate the stream sequence rule")
except ValueError:
    pass
R.validate_manifest_in_stream(R.parse_manifest(M_far), genesis)   # structurally valid, excluded only by T

# Literal cross-anchor reading (non-conformant) would accept C1 in scenario H:
_cross = R.recover_address(C1, sig_M1_S1) == A(S1) and any(mb == M1 for mb, _ in [(M1, GARBAGE_SIG)])
assert _cross is True

# Governance bounds N >= 2M - 1
GOV_BOUNDS = {}
for label, thr, members in [("2-of-2", 2, sorted([A(G1), A(G2)])), ("3-of-4", 3, sorted([A(G1), A(G2), A(G3), A(G4)])),
                            ("2-of-3", 2, GOV), ("1-of-1", 1, [A(G1)]), ("2-of-4", 2, sorted([A(G1), A(G2), A(G3), A(G4)]))]:
    try:
        R.genesis_core_bytes(thr, members, T0, "BYK.DATALAYER.TESTVECTORS", 84532, bytes(32), bytes(20))
        GOV_BOUNDS[label] = "valid"
    except ValueError:
        GOV_BOUNDS[label] = "invalid"
assert GOV_BOUNDS == {"2-of-2": "invalid", "3-of-4": "invalid", "2-of-3": "valid", "1-of-1": "valid", "2-of-4": "valid"}

stH_ok, headH_ok, stat_ok = R.build_authorization_log(genesis, [E1, E2e, E3e_new])
stH_bad, headH_bad, stat_bad = R.build_authorization_log(genesis, [E1, E2e, E3e_old])
assert headH_ok[0] == 3 and headH_bad[0] == 2 and stat_ok == stat_bad == "OK"
stD, _, _ = R.build_authorization_log(genesis, [E1, E2d, E3d])
assert R.authorized(stD, A(S1), 1) and not R.authorized(stD, A(S1), 2) and R.authorized(stD, A(S2), 2)

V["authorization_log"] = {
    "E1_authorize_S1_hex": hx(E1[0]), "E1_hash": hx(h1), "E1_bundle_G1_G2": hx(E1[1]),
    "E1_meaning": "log_seq 1: S1 authorized for sequences [0, unbounded)",
    "E2b_checkpoint_seq2_C2a_hex": hx(E2b[0]), "E2b_bundle": hx(E2b[1]),
    "E2c_checkpoint_seq2_C2b_hex": hx(E2c[0]), "E2c_bundle": hx(E2c[1]),
    "E2d_revoke_S1_from_seq2_hex": hx(E2d[0]), "E2d_bundle": hx(E2d[1]),
    "E3d_authorize_S2_from_seq2_hex": hx(E3d[0]), "E3d_bundle": hx(E3d[1]),
    "E2bad_checkpoint_seq2_C2bad_hex": hx(E2bad[0]), "E2bad_bundle": hx(E2bad[1]),
    "E2restart_checkpoint_seq3_C3_hex": hx(E2restart[0]), "E2restart_bundle": hx(E2restart[1]),
    "E2e_governance_update_hex": hx(E2e[0]), "E2e_bundle_old_set_G2_G3": hx(E2e[1]),
    "E3e_authorize_S2_from_seq4_hex": hx(E3e_eb), "E3e_bundle_new_set_G1_G4": hx(E3e_new[1]),
    "E3e_bundle_removed_member_G1_G3_must_fail": hx(E3e_old[1]),
    "ACK3_on_E2b_hex": hx(ACK_b), "ACK3_on_E2b_bundle_G1_G2_G3": hx(ACK_b_all[1]), "ACK3_on_E2b_bundle_G1_G2_only": hx(ACK_b_two[1]),
    "ACK3_on_E2c_hex": hx(ACK_c), "ACK3_on_E2c_bundle_G1_G2_G3": hx(ACK_c_all[1]),
    "CHECKPOINT3_on_E2b_non_ack_continuation_hex": hx(CP_cont), "CHECKPOINT3_on_E2b_bundle_G1_G2_G3": hx(CP_cont_all[1]),
    "new_governance_sorted": ["0x" + hx(a) for a in GOV2], "S2": "0x" + hx(A(S2)),
    "expected_heads_governance_update": {"log[E1,E2e,E3e(new set G1,G4)]": 3, "log[E1,E2e,E3e(G1,G3)]": 2},
}
V["resolution"] = {
    "manifests": {"M2a_hex": hx(M2a), "C2a": hx(C2a), "M2b_hex": hx(M2b), "C2b": hx(C2b), "M2bad_hex": hx(M2bad),
                  "C2bad": hx(C2bad), "M3_hex": hx(M3), "C3": hx(C3)},
    "signatures_S1": {k: hx(v) for k, v in sig.items()}, "signatures_S2": {k: hx(v) for k, v in sig_S2.items()},
    "more_manifests": {"M4_hex": hx(M4), "C4": hx(C4), "M5_hex": hx(M5), "C5": hx(C5), "M1x_hex": hx(M1x), "C1x": hx(C1x),
                       "M_far_hex": hx(M_far), "M_max_hex": hx(M_max)},
    "more_signatures_S1": {"M4": hx(sig["M4"]), "M5": hx(sig["M5"]), "M_far": hx(sig["M_far"]), "M_max": hx(sig["M_max"])},
    "garbage_signature": hx(GARBAGE_SIG),
    "as_of_ms_T_TEST": T_TEST, "S_max_at_T_TEST": S_MAX_TEST,
    "payload_sets": {"P_FORK": "M0,M1,M2a,M2b,M3 (S1)", "P_BADLINK": "M0,M1,M2a,M2bad,M3 (S1)",
                     "F": "P_FORK + M4, M5 (S1)", "H": "(M0,sigS1) + (M1, garbage) + (M1x, sigS1 over C1)",
                     "I": "P_FORK + (M_far, S1) + (M_max, S1)"},
    "governance_bounds": GOV_BOUNDS,
    "scenarios": S, "summary": SH,
}

# ---------------------------------------------------------------- witness time
slot_times = {100: 1_789_258_201, 101: None, 102: 1_789_258_203, 103: None}
base_ts = {5000: 1_789_258_200, 5001: 1_789_258_202, 5002: 1_789_258_204}
tv = {
    "solana_slot_times_sec": {str(k): v for k, v in slot_times.items()},
    "base_block_timestamps_sec": {str(k): v for k, v in base_ts.items()},
    "solana_as_of_slot(T=1789258202000)": R.solana_as_of_slot(slot_times, 1_789_258_202_000),
    "solana_as_of_slot(T=1789258203000)": R.solana_as_of_slot(slot_times, 1_789_258_203_000),
    "base_as_of_block(T=1789258203000)": R.base_as_of_block(base_ts, 1_789_258_203_000),
    "solana_reported_time(100)": list(R.solana_reported_time(slot_times, 100)),
    "solana_reported_time(101)": list(R.solana_reported_time(slot_times, 101)),
    "solana_reported_time(103)": list(R.solana_reported_time(slot_times, 103)),
}
assert tv["solana_as_of_slot(T=1789258202000)"] == 100 and tv["solana_as_of_slot(T=1789258203000)"] == 102
assert tv["base_as_of_block(T=1789258203000)"] == 5001
assert tv["solana_reported_time(101)"] == [1_789_258_203_000, "INFERRED"] and tv["solana_reported_time(103)"] == [None, "UNAVAILABLE"]
V["witness_time"] = tv

# ---------------------------------------------------------------- witness payloads
UID_DATA, UID_AL, UID_GEN = (R.eas_schema_uid(R.EAS_DATA_SCHEMA), R.eas_schema_uid(R.EAS_AL_SCHEMA),
                             R.eas_schema_uid(R.EAS_GENESIS_SCHEMA))
max_al_memo = len("BYKL1 ") + 2 * (80 + 4 + 20 * R.MAX_GOV_N) + 1 + 2 * 65 * R.MAX_GOV_N
max_gen_memo = len("BYKG1 ") + 2 * (R.GENESIS_FIXED_LEN + 20 * R.MAX_GOV_N)
V["witness_payloads"] = {
    "eas_schema_data": R.EAS_DATA_SCHEMA, "eas_schema_uid_data": hx(UID_DATA),
    "eas_schema_al": R.EAS_AL_SCHEMA, "eas_schema_uid_al": hx(UID_AL),
    "eas_schema_genesis": R.EAS_GENESIS_SCHEMA, "eas_schema_uid_genesis": hx(UID_GEN),
    "eas_data_epoch1_recipient": V["witness_keys"]["data_sequence_1"]["base_recipient"],
    "eas_data_epoch1_abi": hx(R.abi_u64_b32_bytes_bytes(1, C1, M1, sig_M1_S1)),
    "eas_al_E1_abi": hx(R.abi_u64_b32_bytes_bytes(1, h1, E1[0], E1[1])),
    "eas_genesis_abi": hx(R.abi_b32_bytes(STREAM, core)),
    "memo_data_epoch1": R.memo_data(M1, sig_M1_S1), "memo_al_E1": R.memo_al(E1[0], E1[1]), "memo_genesis": R.memo_genesis(core),
    "sizes": {"memo_data": len(R.memo_data(M1, sig_M1_S1)), "memo_al_E1": len(R.memo_al(E1[0], E1[1])),
              "memo_genesis_test": len(R.memo_genesis(core)), "memo_al_max": max_al_memo,
              "memo_genesis_max": max_gen_memo, "solana_tx_overhead_model": R.SOLANA_TX_OVERHEAD,
              "max_memo_bytes": R.MAX_MEMO_BYTES},
}
assert max_al_memo <= R.MAX_MEMO_BYTES and max_gen_memo <= R.MAX_MEMO_BYTES

# ---------------------------------------------------------------- Level 3 audit (Section 13.8)
A2 = R.manifest_bytes(3, 2, T0 + 2 * E, T0 + 4 * E, 0, STREAM, EMPTY, C1, schema_hash, methodology_hash)   # gap: 2 windows
CA2 = R.keccak256(A2)
T3 = T0 + 5 * E


def epoch3(drop=None, mutate=None):
    rr, sn, st = epoch_records(T3, 3, drop=drop, mutate=mutate)
    ls = [r[4] for r in rr]
    mb = R.manifest_bytes(st, 3, T0 + 4 * E, T3, len(ls), STREAM, R.mth(ls), CA2, schema_hash, methodology_hash)
    return mb, R.keccak256(mb), ls, sn


A3, CA3, L3, SNAPS3 = epoch3()
VARIANTS = {
    "A3bad_missing_catalog_leaf": epoch3(drop="BYK.BTC.VPIN"),
    "A3_tampered_value": epoch3(mutate={"BYK.BTC.FUNDING.COMPOSITE": {"value": 118867}}),
    "A3_tampered_source_count": epoch3(mutate={"BYK.BTC.FUNDING.COMPOSITE": {"source_count": 6}}),
    "A3_no_data_despite_inputs": epoch3(mutate={"BYK.BTC.FUNDING.COMPOSITE": dict(status=3, value=0, dispersion=0, source_count=0,
                                                                                    coverage_bps=0, outlier_count=0, max_source_age_ms=0)}),
    "A3_insufficient_wrong_quality": epoch3(mutate={"BYK.ETH.FUNDING.COMPOSITE": {"coverage_bps": 9999, "source_count": 4}}),
}
T_AUD = T0 + 5 * E + 60_000
st_aud, _, _ = R.build_authorization_log(genesis, [E1])
MAN = {C0: M0, C1: M1, CA2: A2, CA3: A3}
LEAVES = {C1: leaves, CA3: L3}
for mb, c, ls, _ in VARIANTS.values():
    MAN[c], LEAVES[c] = mb, ls
SNAPS = dict(SNAPS1)
SNAPS.update(SNAPS3)


def audit(epoch3_payload, s_from, s_to, snaps=None):
    mb, c = epoch3_payload
    pay = [(M0, sig_M0_S1), (M1, sig_M1_S1), (A2, R.sign_digest(S1, CA2)), (mb, R.sign_digest(S1, c))]
    res = R.resolve_canonical(st_aud, R.candidates(st_aud, genesis, pay, T_AUD), genesis, T_AUD)
    return R.audit_range(genesis, res, MAN, LEAVES, CATALOG, s_from, s_to,
                         class_a_snapshots=SNAPS if snaps is None else snaps, methodology_params=PRM)


snaps_missing_sol = {k: v for k, v in SNAPS.items() if k != (3, "BYK.SOL.FUNDING.COMPOSITE", "SOL")}
AUD = {
    "AUD1_normal_gap_normal_[0,3]": audit((A3, CA3), 0, 3),
    "AUD2_catalog_leaf_missing_[0,3]": audit(VARIANTS["A3bad_missing_catalog_leaf"][:2], 0, 3),
    "AUD3_range_includes_unresolved_[0,4]": audit((A3, CA3), 0, 4),
    "AUD4_range_starts_after_gap_[3,3]": audit((A3, CA3), 3, 3),
    "AUD5_class_a_value_tampered_[0,3]": audit(VARIANTS["A3_tampered_value"][:2], 0, 3),
    "AUD6_class_a_source_count_tampered_[0,3]": audit(VARIANTS["A3_tampered_source_count"][:2], 0, 3),
    "AUD7_no_data_despite_sufficient_inputs_[0,3]": audit(VARIANTS["A3_no_data_despite_inputs"][:2], 0, 3),
    "AUD8_insufficient_with_wrong_quality_[0,3]": audit(VARIANTS["A3_insufficient_wrong_quality"][:2], 0, 3),
    "AUD9_class_a_snapshot_missing_[0,3]": audit((A3, CA3), 0, 3, snaps=snaps_missing_sol),
    "AUD10_parameters_differ_from_methodology_[0,3]": R.audit_range(
        genesis, R.resolve_canonical(st_aud, R.candidates(st_aud, genesis, [(M0, sig_M0_S1), (M1, sig_M1_S1), (A2, R.sign_digest(S1, CA2)), (A3, R.sign_digest(S1, CA3))], T_AUD), genesis, T_AUD),
        MAN, LEAVES, CATALOG, 0, 3, class_a_snapshots=SNAPS, methodology_params=dict(PRM, outlier_k=6)),
}
assert AUD["AUD1_normal_gap_normal_[0,3]"] == ("PASS", [])
assert AUD["AUD2_catalog_leaf_missing_[0,3]"] == ("FAIL", ["sequence 3: leaf set or decimals differ from catalog"])
assert AUD["AUD3_range_includes_unresolved_[0,4]"] == ("FAIL", ["sequence 4: not CANONICAL"])
assert AUD["AUD4_range_starts_after_gap_[3,3]"] == ("PASS", [])
assert AUD["AUD5_class_a_value_tampered_[0,3]"] == ("FAIL", ["sequence 3: Class A recomputation mismatch for BYK.BTC.FUNDING.COMPOSITE/BTC (value)"])
assert AUD["AUD6_class_a_source_count_tampered_[0,3]"] == ("FAIL", ["sequence 3: Class A recomputation mismatch for BYK.BTC.FUNDING.COMPOSITE/BTC (source_count)"])
assert AUD["AUD7_no_data_despite_sufficient_inputs_[0,3]"][0] == "FAIL" and "status" in AUD["AUD7_no_data_despite_sufficient_inputs_[0,3]"][1][0]
assert AUD["AUD8_insufficient_with_wrong_quality_[0,3]"] == ("FAIL", ["sequence 3: Class A recomputation mismatch for BYK.ETH.FUNDING.COMPOSITE/ETH (source_count, coverage_bps)"])
assert AUD["AUD9_class_a_snapshot_missing_[0,3]"] == ("FAIL", ["sequence 3: Class A snapshot missing for BYK.SOL.FUNDING.COMPOSITE/SOL"])
assert AUD["AUD10_parameters_differ_from_methodology_[0,3]"][0] == "FAIL" and len(AUD["AUD10_parameters_differ_from_methodology_[0,3]"][1]) == 6
# every Class A leaf status is covered: DEGRADED (BTC), INSUFFICIENT_COVERAGE (ETH), DEGRADED negative (SOL)
_st = {r[2]: (R.STATUS_NAME[r[4][1]], R.rds(r[4], 76, 8)) for r in epoch_records(T3, 3)[0]}
assert _st["BYK.ETH.FUNDING.COMPOSITE"][0] == "INSUFFICIENT_COVERAGE" and _st["BYK.SOL.FUNDING.COMPOSITE"][1] < 0


def snap_json(sn):
    return {"%d|%s|%s" % k: v for k, v in sn.items()}


V["audit"] = {
    "as_of_ms": T_AUD, "catalog": [list(c) for c in CATALOG], "methodology_parameters": PRM,
    "manifests": {"A2_gap_hex": hx(A2), "CA2": hx(CA2), "A3_hex": hx(A3), "CA3": hx(CA3)},
    "leaves_A3": [hx(x) for x in L3],
    "variants": {k: {"manifest_hex": hx(v[0]), "commitment": hx(v[1]), "leaves": [hx(x) for x in v[2]],
                     "signature_S1": hx(R.sign_digest(S1, v[1]))} for k, v in VARIANTS.items()},
    "signatures_S1": {"A2": hx(R.sign_digest(S1, CA2)), "A3": hx(R.sign_digest(S1, CA3))},
    "class_a_snapshots": snap_json(SNAPS),
    "results": {k: {"result": v[0], "reasons": v[1]} for k, v in AUD.items()},
}


# ---------------------------------------------------------------- Annex A worked examples (via byk_ref.funding_composite)
T = e1_end
VENUES = venues_main(T)


def summarize(leaf, det):
    keep = ("value", "dispersion", "source_count", "expected_source_count", "coverage_bps", "outlier_count",
            "max_source_age_ms", "status", "median", "mad", "tau", "capped_count", "cap_weight", "max_weight_share_bps", "weights")
    return {"leaf": {k: leaf[k] for k in keep if k in leaf},
            "venues": [{k: v for k, v in d.items() if k != "vid"} for d in det]}


def encodable(leaf):
    """Every Annex A output must encode as a Section 7.1 leaf."""
    st = R.STATUS[leaf["status"]]
    R.leaf_bytes(st, 10, R.id32("BYK.TEST.FUNDING.COMPOSITE"), R.id32("TEST"), T, leaf["value"], leaf["source_count"],
                 leaf["expected_source_count"], leaf["coverage_bps"], leaf["outlier_count"], leaf["max_source_age_ms"],
                 leaf["dispersion"])
    return True


leafA, detA = R.funding_composite(VENUES, PRM, T)
assert [d.get("oi_usd") for d in detA] == [4_200_000_000, 2_900_000_000, 1_300_000_000, 1_100_000_000, 900_000_000, 300_000_000, 500_000_000]
assert (leafA["value"], leafA["status"], leafA["coverage_bps"], leafA["dispersion"], leafA["max_source_age_ms"]) == (118866, "DEGRADED", 9285, 11134, 1_512_000)
assert encodable(leafA)

T_LATE = T + 2 * 24 * HOUR
leafN, detN = R.funding_composite(VENUES, PRM, T_LATE)
assert leafN == dict(value=0, dispersion=0, source_count=0, expected_source_count=7, coverage_bps=0,
                     outlier_count=0, max_source_age_ms=0, status="NO_DATA") and encodable(leafN)

VENUES_I = venues_insufficient(T)
leafI, detI = R.funding_composite(VENUES_I, PRM, T)
assert (leafI["status"], leafI["value"], leafI["dispersion"], leafI["source_count"], leafI["outlier_count"],
        leafI["coverage_bps"], leafI["max_source_age_ms"]) == ("INSUFFICIENT_COVERAGE", 0, 0, 3, 1, 9130, 1_512_000)
assert encodable(leafI)

# rc4 overflow reproduction inputs: |hourly| = 9e18 is now outside +-(2^62-1): all rates invalid -> NO_DATA
def qv(name, rate, oi):
    return dict(venue=name, rate=rate, rate_unit="FRACTION", interval="1", interval_unit="h", settlement_ts=str(T - 1000),
                settlement_ts_unit="ms", oi_unit="QUOTE", oi_value=oi, contract_size=None, mark_price=None,
                oi_ts=str(T - 1000), oi_ts_unit="ms", price_ts=None, price_ts_unit=None)


OVF = [qv("p1", "900000000", "3500"), qv("p2", "900000000", "3500"), qv("n1", "-900000000", "1000"),
       qv("n2", "-900000000", "1000"), qv("n3", "-900000000", "1000")]
leafO, detO = R.funding_composite(OVF, PRM, T)
assert leafO["status"] == "NO_DATA" and all("hourly outside" in d["rate_error"] for d in detO) and encodable(leafO)

HM = "461168601.8427387903"            # units = 2^62 - 1 at 1 h
EXT = [qv("p1", HM, "3500"), qv("p2", HM, "3500"), qv("n1", "-" + HM, "1000"), qv("n2", "-" + HM, "1000"), qv("n3", "-" + HM, "1000")]
leafX, detX = R.funding_composite(EXT, PRM, T)
assert all(d["hourly"] in (R.HOURLY_MAX, -R.HOURLY_MAX) for d in detX)
assert leafX["value"] == 1844674407370955161 and leafX["dispersion"] == 6456360425798343064 <= R.I64_MAX and encodable(leafX)
EXT_OVER = [qv("p1", "461168601.8427387904", "3500")] + EXT[1:]
_, detXO = R.funding_composite(EXT_OVER, PRM, T)
assert "hourly outside" in detXO[0]["rate_error"]

PRM_EQ = dict(PRM, min_contributors=2, max_weight_bps=5000, min_source_ratio_bps=0, coverage_ok_bps=0)
EQ = [qv("big", "0.0000001", "3000"), qv("small", "0.0000002", "1000")]
leafE, detE = R.funding_composite(EQ, PRM_EQ, T)
assert leafE["weights"] == {"big": 1000, "small": 1000} and leafE["max_weight_share_bps"] == 5000 and leafE["value"] == 1500
try:
    R.validate_params(dict(PRM, min_contributors=2), 7)
    raise AssertionError("cap * min_contributors < 10000 must be rejected")
except ValueError:
    pass

PARAM_CASES = {}
for label, change in [("proposed defaults", {}), ("outlier_k = 10^100", {"outlier_k": 10 ** 100}),
                      ("outlier_k = 1000", {"outlier_k": 1000}), ("stale_factor = 1001", {"stale_factor": 1001}),
                      ("outlier_floor = 2^62", {"outlier_floor": 2 ** 62}), ("oi_max_age_ms = 604800001", {"oi_max_age_ms": 604_800_001}),
                      ("min_contributors = 65536", {"min_contributors": 65536}), ("outlier_k = true (bool)", {"outlier_k": True}),
                      ("extra key", {"extra": 1})]:
    try:
        R.validate_params(dict(PRM, **change), 7)
        PARAM_CASES[label] = "valid"
    except ValueError:
        PARAM_CASES[label] = "invalid"
assert PARAM_CASES == {"proposed defaults": "valid", "outlier_k = 10^100": "invalid", "outlier_k = 1000": "valid",
                       "stale_factor = 1001": "invalid", "outlier_floor = 2^62": "invalid", "oi_max_age_ms = 604800001": "invalid",
                       "min_contributors = 65536": "invalid", "outlier_k = true (bool)": "invalid", "extra key": "invalid"}

LEX = {}
for lex, signed in [("100000", False), ("0.001", False), ("2900000000.75", False), ("-0.0001", True), ("-0.0001", False),
                    ("1e5", False), ("+1", True), (" 1", False), ("1,000", False), (".5", False), ("5.", False),
                    ("1" * 25, False), ("0." + "1" * 19, False), ("0." + "1" * 18, False), ("12345678901234567.89", False)]:
    try:
        R.parse_lexeme(lex, signed)
        LEX[f"{lex!r} signed={signed}"] = "valid"
    except ValueError:
        LEX[f"{lex!r} signed={signed}"] = "invalid"

INT = {}
for lex, unit, scale_name, scale in [("1789258140", "s", "time", R.TIME_SCALE), ("1789258140000", "ms", "time", R.TIME_SCALE),
                                     ("0001", "ms", "time", R.TIME_SCALE), ("12345678901234567890", "ms", "time", R.TIME_SCALE),
                                     ("-1", "ms", "time", R.TIME_SCALE), ("1.0", "s", "time", R.TIME_SCALE), ("1e3", "ms", "time", R.TIME_SCALE),
                                     ("9223372036854775", "s", "time", R.TIME_SCALE), ("9223372036854776", "s", "time", R.TIME_SCALE),
                                     ("1789258140", "us", "time", R.TIME_SCALE), ("8", "h", "interval", R.INTERVAL_SCALE),
                                     ("0", "h", "interval", R.INTERVAL_SCALE), ("25", "h", "interval", R.INTERVAL_SCALE),
                                     ("59999", "ms", "interval", R.INTERVAL_SCALE), ("86400", "s", "interval", R.INTERVAL_SCALE),
                                     ("86401", "s", "interval", R.INTERVAL_SCALE)]:
    key_ = f"{lex} {unit} ({scale_name})"
    try:
        val = R.parse_integer_lexeme(lex, unit, scale)
        if scale_name == "interval" and not (R.INTERVAL_MIN_MS <= val <= R.INTERVAL_MAX_MS):
            INT[key_] = "invalid (interval outside [60000, 86400000] ms)"
        else:
            INT[key_] = val
    except ValueError as err:
        INT[key_] = "invalid (" + str(err) + ")"

RATE_UNITS = {f"{lex} {u}": R._trunc(R.parse_lexeme(lex, True) * R.RATE_SCALE[u]) for lex, u in
              [("0.0001", "FRACTION"), ("0.01", "PERCENT"), ("1", "BPS"), ("-0.0375", "PERCENT")]}
assert RATE_UNITS["0.0001 FRACTION"] == RATE_UNITS["0.01 PERCENT"] == RATE_UNITS["1 BPS"] == 1_000_000

exact = R._trunc(R.parse_lexeme("12345678901234567.89", False) * R.parse_lexeme("1.5", False))
float_result = int(float("12345678901234567.89") * float("1.5"))
assert exact == 18518518351851851 and float_result != exact

V["annex_a"] = {
    "parameters": PRM, "T": T, "venues_input": VENUES,
    "example_main": summarize(leafA, detA),
    "example_no_data": dict(T=T_LATE, **summarize(leafN, detN)),
    "example_insufficient_coverage": dict(T=T, note="venue-d and venue-e mark prices 120 s older than OI", **summarize(leafI, detI)),
    "example_rc4_overflow_inputs": summarize(leafO, detO),
    "example_extreme_hourly_bound": summarize(leafX, detX),
    "example_cap_equality": dict(parameters=PRM_EQ, **summarize(leafE, detE)),
    "invalid_parameters": "min_contributors=2 with max_weight_bps=3500 (7000 < 10000)",
    "lexemes": LEX, "integer_lexemes": INT, "rate_units": RATE_UNITS, "parameter_cases": PARAM_CASES,
    "exactness": {"oi BASE 12345678901234567.89 x mark 1.5": exact, "binary64 float result (non-conformant)": float_result},
}

JS_SAFE = 2 ** 53 - 1


def js_safe(o):
    """Section 17: integers outside +-(2^53 - 1) are written as decimal strings so that JSON parsers
    backed by binary64 (for example JavaScript) cannot silently round them."""
    if isinstance(o, bool):
        return o
    if isinstance(o, int) and abs(o) > JS_SAFE:
        return str(o)
    if isinstance(o, dict):
        return {k: js_safe(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [js_safe(v) for v in o]
    return o


with open(OUT, "w") as f:
    json.dump(js_safe(V), f, indent=2)
print("wrote", OUT)
