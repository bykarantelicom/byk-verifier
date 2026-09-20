#!/usr/bin/env python3
"""Optional cross-check of byk_v1_test_vectors.json (rc6) against third-party libraries.
pip install -r requirements-xcheck.txt"""
import json
from Crypto.Hash import keccak
import coincurve
from eth_abi import encode as abi_encode

V = json.load(open("byk_v1_test_vectors.json"))
def H(b):
    h = keccak.new(digest_bits=256); h.update(b); return h.digest()
x = bytes.fromhex
def rec(d, s): return H(coincurve.PublicKey.from_signature_and_message(s, d, hasher=None).format(compressed=False)[1:])[-20:]
n = 0
def ok(c, m):
    global n
    assert c, m; n += 1

g = V["genesis_core"]; core = x(g["genesis_core_hex"]); stream = x(g["stream_id"])
ok(H(core) == stream, "stream_id")
ok(len(core) == 112 + 20 * 3 and core[:4] == b"BYKG" and core[5] == 2 and core[6] == 3, "core layout")
for name, kind, num in [("data_sequence_0", 1, 0), ("data_sequence_1", 1, 1), ("al_log_seq_1", 2, 1), ("genesis", 3, 0)]:
    k = H(b"BYKW" + stream + bytes([kind]) + num.to_bytes(8, "big"))
    ok(k.hex() == V["witness_keys"][name]["key_hex"] and "0x" + k[12:].hex() == V["witness_keys"][name]["base_recipient"], "witness key " + name)
e = V["epoch1"]
ok(H(x(V["genesis_manifest"]["manifest_hex"])).hex() == V["genesis_manifest"]["commitment"], "C0")
ok(H(x(e["manifest_hex"])).hex() == e["commitment"], "C1")
def mth_(ls):
    if len(ls) == 1: return H(b"\x00" + ls[0])
    k = 1
    while k * 2 < len(ls): k *= 2
    return H(b"\x01" + mth_(ls[:k]) + mth_(ls[k:]))
ok(mth_([x(l["leaf_hex"]) for l in e["leaves"]]).hex() == e["merkle_root"], "root (generic MTH)")
ok(len(e["leaves"]) == 4, "epoch 1 has 4 catalog leaves")
S1 = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
ok(rec(x(e["commitment"]), x(e["signature_S1"])).hex() == S1, "sig M1")
ok(coincurve.PrivateKey(x("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")).sign_recoverable(x(e["commitment"]), hasher=None).hex() == e["signature_S1"], "rfc6979 equality")
r = V["resolution"]; mf = r["manifests"]
for k, c in [("M2a", "C2a"), ("M2b", "C2b"), ("M2bad", "C2bad"), ("M3", "C3")]:
    ok(H(x(mf[k + "_hex"])).hex() == mf[c], "commit " + k)
    ok(rec(x(mf[c]), x(r["signatures_S1"][k])).hex() == S1, "S1 sig " + k)
ok(x(mf["M2bad_hex"])[104:136].hex() == V["genesis_manifest"]["commitment"], "M2bad links to C0 (non-linking)")
al = V["authorization_log"]
gov = [a[2:].lower() for a in g["governance_sorted"]]; gov2 = [a[2:].lower() for a in al["new_governance_sorted"]]
def bundle(entry_hex, b_hex, members, need):
    d = H(x(entry_hex)); b = x(b_hex); addrs = [rec(d, b[i:i + 65]).hex() for i in range(0, len(b), 65)]
    return addrs == sorted(addrs) and len(set(addrs)) == len(addrs) and all(a in members for a in addrs) and len(addrs) >= need
ok(H(x(al["E1_authorize_S1_hex"])).hex() == al["E1_hash"], "E1 hash")
for ent, b in [("E1_authorize_S1_hex", "E1_bundle_G1_G2"), ("E2b_checkpoint_seq2_C2a_hex", "E2b_bundle"), ("E2c_checkpoint_seq2_C2b_hex", "E2c_bundle"),
               ("E2d_revoke_S1_from_seq2_hex", "E2d_bundle"), ("E3d_authorize_S2_from_seq2_hex", "E3d_bundle"),
               ("E2bad_checkpoint_seq2_C2bad_hex", "E2bad_bundle"), ("E2restart_checkpoint_seq3_C3_hex", "E2restart_bundle"),
               ("E2e_governance_update_hex", "E2e_bundle_old_set_G2_G3")]:
    ok(bundle(al[ent], al[b], gov, 2), ent)
ok(bundle(al["ACK3_on_E2b_hex"], al["ACK3_on_E2b_bundle_G1_G2_G3"], gov, 3), "ACK fork threshold 3")
ok(not bundle(al["ACK3_on_E2b_hex"], al["ACK3_on_E2b_bundle_G1_G2_only"], gov, 3), "ACK with 2 sigs below fork threshold")
ok(x(al["ACK3_on_E2b_hex"])[48:80] == H(x(al["E2b_checkpoint_seq2_C2a_hex"])) and len(x(al["ACK3_on_E2b_hex"])) == 80, "ACK predecessor + empty body")
ok(bundle(al["E3e_authorize_S2_from_seq4_hex"], al["E3e_bundle_new_set_G1_G4"], gov2, 2), "E3e new set")
ok(not bundle(al["E3e_authorize_S2_from_seq4_hex"], al["E3e_bundle_removed_member_G1_G3_must_fail"], gov2, 2), "E3e removed member")
w = V["witness_payloads"]
for s, u in [("eas_schema_data", "eas_schema_uid_data"), ("eas_schema_al", "eas_schema_uid_al"), ("eas_schema_genesis", "eas_schema_uid_genesis")]:
    ok(H(w[s].encode() + b"\x00" * 21).hex() == w[u], "schema uid " + s)
ok(abi_encode(["uint64", "bytes32", "bytes", "bytes"], [1, x(e["commitment"]), x(e["manifest_hex"]), x(e["signature_S1"])]).hex() == w["eas_data_epoch1_abi"], "eas data abi")
ok(abi_encode(["uint64", "bytes32", "bytes", "bytes"], [1, x(al["E1_hash"]), x(al["E1_authorize_S1_hex"]), x(al["E1_bundle_G1_G2"])]).hex() == w["eas_al_E1_abi"], "eas al abi")
ok(abi_encode(["bytes32", "bytes"], [stream, core]).hex() == w["eas_genesis_abi"], "eas genesis abi")
mm = r["more_manifests"]; ms = r["more_signatures_S1"]
for k, c in [("M4", "C4"), ("M5", "C5"), ("M1x", "C1x")]:
    ok(H(x(mm[k + "_hex"])).hex() == mm[c], "commit " + k)
for k in ["M4", "M5", "M_far", "M_max"]:
    ok(rec(H(x(mm[k + "_hex"])), x(ms[k])).hex() == S1, "S1 sig " + k)
ok(x(mm["M4_hex"])[104:136].hex() == mf["C3"] and x(mm["M5_hex"])[104:136].hex() == mm["C4"], "M4/M5 chain")
# stream sequence rule, computed independently: epoch_start >= G + sequence * 300000
G0 = int.from_bytes(core[8:16], "big")
far, mx = x(mm["M_far_hex"]), x(mm["M_max_hex"])
ok(int.from_bytes(far[16:24], "big") >= G0 + int.from_bytes(far[8:16], "big") * 300000, "M_far satisfies stream rule")
ok(int.from_bytes(mx[16:24], "big") < G0 + int.from_bytes(mx[8:16], "big") * 300000, "M_max violates stream rule")
T_TEST = r["as_of_ms_T_TEST"]
ok(int.from_bytes(far[24:32], "big") > T_TEST, "M_far window ends after T")
ok((T_TEST - G0) // 300000 - 1 == r["S_max_at_T_TEST"], "S_max")
# signature binding: the valid signature over C1 does not verify over M1x
ok(rec(H(x(mm["M1x_hex"])), x(e["signature_S1"])).hex() != S1, "binding: sig(C1) does not verify for M1x")
ok(bundle(al["CHECKPOINT3_on_E2b_non_ack_continuation_hex"], al["CHECKPOINT3_on_E2b_bundle_G1_G2_G3"], gov, 3)
   and x(al["CHECKPOINT3_on_E2b_non_ack_continuation_hex"])[5] == 3, "non-ACK continuation is validly signed but type 3")
# exact decimal arithmetic, independent of byk_ref
from decimal import Decimal, getcontext
getcontext().prec = 80
aa = V["annex_a"]
ok(int(Decimal("12345678901234567.89") * Decimal("1.5")) == int(aa["exactness"]["oi BASE 12345678901234567.89 x mark 1.5"]), "exact OI product")
ok(int(float("12345678901234567.89") * 1.5) == int(aa["exactness"]["binary64 float result (non-conformant)"]), "float differs")
ok(isinstance(aa["exactness"]["oi BASE 12345678901234567.89 x mark 1.5"], str), "large integers are JSON strings")
lf = aa["example_main"]["leaf"]; w = lf["weights"]
hourly = {d["venue"]: d["hourly"] for d in aa["example_main"]["venues"]}
num = sum(w[v] * hourly[v] for v in w); den = sum(w.values())
ok(int(Decimal(num) / Decimal(den)) == int(lf["value"]), "composite R recomputed")
au = V["audit"]; am = au["manifests"]
for k, c in [("A2_gap_hex", "CA2"), ("A3_hex", "CA3")]:
    ok(H(x(am[k])).hex() == am[c], "commit " + k)
for k, c in [("A2", "CA2"), ("A3", "CA3")]:
    ok(rec(x(am[c]), x(au["signatures_S1"][k])).hex() == S1, "sig " + k)
gap = x(am["A2_gap_hex"])
ok(gap[5] == 3 and int.from_bytes(gap[32:36], "big") == 0 and int.from_bytes(gap[24:32], "big") - int.from_bytes(gap[16:24], "big") == 600000, "gap: NO_DATA, 0 records, 2 windows")
ok(mth_([x(l) for l in au["leaves_A3"]]) == x(am["A3_hex"])[72:104], "root A3")
ok(x(am["A3_hex"])[104:136].hex() == am["CA2"] and x(am["A2_gap_hex"])[104:136].hex() == e["commitment"], "audit chain links")
for name, v in au["variants"].items():
    mb = x(v["manifest_hex"])
    ok(H(mb).hex() == v["commitment"] and mth_([x(l) for l in v["leaves"]]) == mb[72:104], "variant commitment and root " + name)
    ok(rec(x(v["commitment"]), x(v["signature_S1"])).hex() == S1, "variant signature " + name)
A3_end = int.from_bytes(x(am["A3_hex"])[24:32], "big"); M1_end = int.from_bytes(x(e["manifest_hex"])[24:32], "big")
for key, snap in au["class_a_snapshots"].items():
    seq = int(key.split("|")[0])
    ok(int(snap["T"]) == (M1_end if seq == 1 else A3_end), "snapshot T equals epoch end " + key)
    ok(snap["parameters"] == au["methodology_parameters"], "snapshot parameters " + key)
tampered = {n: [l for l in v["leaves"]] for n, v in au["variants"].items()}
honest = set(au["leaves_A3"])
ok(len(set(tampered["A3_tampered_value"]) - honest) == 1, "exactly one leaf differs in tampered-value variant")
# extreme hourly bound, recomputed independently
Hm = 2**62 - 1
num = 3500 * Hm + 3500 * Hm - 1000 * Hm * 3
Rv = int(Decimal(num) / Decimal(10000))
disp = sorted([abs(Hm - Rv)] * 2 + [abs(-Hm - Rv)] * 3)[2]
lx = aa["example_extreme_hourly_bound"]["leaf"]
ok(Rv == int(lx["value"]) and disp == int(lx["dispersion"]) and disp <= 2**63 - 1, "extreme bound R and dispersion fit int64")
ok(abs(9 * 10**18 - (-9 * 10**18)) > 2**63 - 1 and aa["example_rc4_overflow_inputs"]["leaf"]["status"] == "NO_DATA", "rc4 overflow inputs now NO_DATA")
le = aa["example_cap_equality"]["leaf"]
ok(le["weights"] == {"big": 1000, "small": 1000} and int(le["value"]) == 1500, "cap equality: equal weights")
ok(aa["rate_units"]["0.0001 FRACTION"] == aa["rate_units"]["0.01 PERCENT"] == aa["rate_units"]["1 BPS"] == 1000000, "rate units")
print("python cross-check passed:", n, "assertions")
