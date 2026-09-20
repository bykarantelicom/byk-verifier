/* BYK Data Layer v1 (rc6) · Section 13.8: the Level 3 audit of a canonical range. It checks chain and
 * window continuity, the leaf set against the catalog, the Merkle root, the epoch status derived from the
 * leaves, and recomputes EVERY Class A leaf (whatever its status) from its retained input snapshot. */
import { BykError, type Bytes, compare, equal, toHex } from "./bytes";
import { fundingComposite, type FundingVenueInput, paramsEqual } from "./funding-composite";
import { id32, leafKey, merkleRoot, parseLeaf, STATUS, type Leaf } from "./records";
import { type Resolution } from "./resolve";
import { type Genesis, parseManifest, validateManifestInStream } from "./stream";

export type CatalogEntry = { feed: string; asset: string; decimals: number; dataClass: "A" | "B" };
export type ClassASnapshot = { T: bigint; parameters: Record<string, unknown>; venues: FundingVenueInput[] };
export type AuditResult = { result: "PASS" | "FAIL"; reasons: string[] };

export const snapshotKey = (sequence: bigint, feed: string, asset: string): string => `${sequence}|${feed}|${asset}`;

/** `resolution` MUST be the output of resolveCanonical evaluated from sequence 0. `manifests` and `leaves`
 *  are keyed by commitment (hex). `snapshots` is keyed by snapshotKey(). `methodologyParams` is the parameter
 *  set of the committed methodology document: a snapshot that carries different parameters fails (AUD10). */
export function auditRange(input: {
  genesis: Genesis;
  resolution: Resolution;
  manifests: Map<string, Bytes>;
  leaves: Map<string, Bytes[]>;
  catalog: CatalogEntry[];
  from: bigint;
  to: bigint;
  snapshots?: Map<string, ClassASnapshot>;
  methodologyParams?: Record<string, unknown>;
}): AuditResult {
  const { genesis, resolution, manifests, leaves, catalog, from, to } = input;
  const snapshots = input.snapshots ?? new Map<string, ClassASnapshot>();
  const reasons: string[] = [];
  const byKey = new Map<string, CatalogEntry>();
  for (const c of catalog) byKey.set(toHex(id32(c.feed)) + toHex(id32(c.asset)), c);
  const cat = [...byKey.entries()].map(([k, c]) => `${k}:${c.decimals}`).sort();

  for (let s = from; s <= to; s += BigInt(1)) {
    const r = resolution.get(s);
    if (!r || r.commitment === null) {
      reasons.push(`sequence ${s}: not CANONICAL`);
      continue;
    }
    if (r.flags.includes("HISTORY_UNRESOLVED_BEFORE")) reasons.push(`sequence ${s}: HISTORY_UNRESOLVED_BEFORE`);
    const mb = manifests.get(toHex(r.commitment));
    if (!mb) throw new BykError(`manifest bytes missing for sequence ${s}`);
    const m = parseManifest(mb);
    validateManifestInStream(m, genesis);
    if (s > BigInt(0)) { // continuity is checked at the range start as well (N26)
      const pc = resolution.get(s - BigInt(1))?.commitment ?? null;
      const pmb = pc ? manifests.get(toHex(pc)) : undefined;
      const pm = pmb ? parseManifest(pmb) : null;
      if (!pc || !pm || !equal(m.previousCommitment, pc) || m.epochStartMs !== pm.epochEndMs) reasons.push(`sequence ${s}: chain or window discontinuity`);
    }
    if (m.status === STATUS.NO_DATA) continue; // genesis, gap or single-window NO_DATA: no leaf checks (N26)
    const ls = leaves.get(toHex(r.commitment));
    if (!ls || ls.length !== m.recordCount) {
      reasons.push(`sequence ${s}: leaf set missing or count mismatch`);
      continue;
    }
    let parsed: Leaf[];
    try {
      parsed = ls.map(parseLeaf);
    } catch (err) {
      if (!(err instanceof BykError)) throw err;
      reasons.push(`sequence ${s}: invalid leaf (${err.message})`);
      continue;
    }
    for (let i = 0; i + 1 < ls.length; i++) {
      if (compare(leafKey(ls[i]!), leafKey(ls[i + 1]!)) >= 0) {
        reasons.push(`sequence ${s}: leaves not strictly ascending`);
        break;
      }
    }
    if (!equal(merkleRoot(ls), m.merkleRoot)) reasons.push(`sequence ${s}: merkle_root mismatch`);
    if (parsed.some((q) => !(m.epochStartMs <= q.observedAtMs && q.observedAtMs <= m.epochEndMs))) reasons.push(`sequence ${s}: observed_at_ms outside window`);
    const have = ls.map((lb) => `${toHex(leafKey(lb))}:${lb[2]}`).sort();
    if (have.length !== cat.length || have.some((h, i) => h !== cat[i])) reasons.push(`sequence ${s}: leaf set or decimals differ from catalog`);
    const derived = parsed.every((q) => q.status === STATUS.OK) ? STATUS.OK : STATUS.DEGRADED;
    if (derived !== m.status) reasons.push(`sequence ${s}: epoch status not derived from leaves`);

    ls.forEach((lb, i) => {
      const entry = byKey.get(toHex(leafKey(lb)));
      if (!entry || entry.dataClass !== "A") return;
      const q = parsed[i]!;
      const label = `${entry.feed}/${entry.asset}`;
      const snap = snapshots.get(snapshotKey(s, entry.feed, entry.asset));
      if (!snap) {
        reasons.push(`sequence ${s}: Class A snapshot missing for ${label}`);
        return;
      }
      if (snap.T !== m.epochEndMs || !input.methodologyParams || !paramsEqual(snap.parameters, input.methodologyParams)) {
        reasons.push(`sequence ${s}: Class A snapshot T or parameters differ for ${label}`);
        return;
      }
      let exp;
      try {
        exp = fundingComposite(snap.venues, snap.parameters, snap.T).leaf;
      } catch (err) {
        if (!(err instanceof BykError)) throw err;
        reasons.push(`sequence ${s}: Class A snapshot invalid for ${label} (${err.message})`);
        return;
      }
      const diff: string[] = [];
      if (q.status !== STATUS[exp.status]) diff.push("status");
      if (q.decimals !== 10) diff.push("decimals");
      if (q.observedAtMs !== snap.T) diff.push("observed_at_ms");
      if (q.value !== exp.value) diff.push("value");
      if (q.sourceCount !== exp.source_count) diff.push("source_count");
      if (q.expectedSourceCount !== exp.expected_source_count) diff.push("expected_source_count");
      if (q.coverageBps !== exp.coverage_bps) diff.push("coverage_bps");
      if (q.outlierCount !== exp.outlier_count) diff.push("outlier_count");
      if (q.maxSourceAgeMs !== exp.max_source_age_ms) diff.push("max_source_age_ms");
      if (q.dispersion !== exp.dispersion) diff.push("dispersion");
      if (diff.length) reasons.push(`sequence ${s}: Class A recomputation mismatch for ${label} (${diff.join(", ")})`);
    });
  }
  return reasons.length ? { result: "FAIL", reasons } : { result: "PASS", reasons: [] };
}
