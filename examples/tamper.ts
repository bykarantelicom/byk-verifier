/* Change one digit of a sealed record and watch the proof fail.
 * Reads one proof from the public Proof API, folds it to the signed root with the library,
 * then repeats the same check with the value moved by one unit.
 *   npx tsx examples/tamper.ts [feed] [asset]        default BYK.FUNDING.COMPOSITE.B BTC */
import { equal, fromHex, toHex } from "../ts/bytes";
import { keccak256 } from "../ts/crypto";
import { encodeLeaf, leafHash, parseLeaf, rootFromInclusion } from "../ts/records";
import { parseManifest } from "../ts/stream";

const API = process.env.BYK_PROOF_API ?? "https://bykaranteli.com/api/v1/proof";
const feed = process.argv[2] ?? "BYK.FUNDING.COMPOSITE.B";
const asset = process.argv[3] ?? "BTC";

const res = await fetch(`${API}/proofs/latest/${encodeURIComponent(feed)}/${encodeURIComponent(asset)}`);
if (!res.ok) throw new Error(`Proof API answered ${res.status}`);
const p = (await res.json()) as { sequence: string; leaf: string; leaf_index: number; audit_path: string[]; manifest: string; commitment: string };

const manifestBytes = fromHex(p.manifest);
const manifest = parseManifest(manifestBytes);
const path = p.audit_path.map(fromHex);
const folds = (leaf: Uint8Array): boolean => {
  const root = rootFromInclusion(p.leaf_index, manifest.recordCount, leafHash(leaf), path);
  return root !== null && equal(root, manifest.merkleRoot);
};

const leaf = fromHex(p.leaf);
const record = parseLeaf(leaf);
const forged = encodeLeaf({ ...record, value: record.value + BigInt(1) });

console.log(`record      ${feed} / ${asset} · epoch #${manifest.sequence} · leaf ${p.leaf_index} of ${manifest.recordCount}`);
console.log(`signed root ${toHex(manifest.merkleRoot)}`);
console.log(`commitment  ${toHex(keccak256(manifestBytes)) === p.commitment ? "matches" : "DOES NOT MATCH"} keccak256(manifest)`);
console.log(`original    value ${record.value}  ->  ${folds(leaf) ? "PASS" : "FAIL"}  the leaf folds to the signed root`);
console.log(`tampered    value ${record.value + BigInt(1)}  ->  ${folds(forged) ? "PASS" : "FAIL"}  the root no longer matches`);
