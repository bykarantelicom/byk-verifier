/* BYK Data Layer · independent verifier. It is given ONE thing out of band, the stream_id, and reads everything
 * else from the two public chains: no database, no ByKaranteli API, no trust in who submitted what.
 *
 *   1. genesis core   from the genesis witness key; accepted only if keccak256(core) is the pinned stream_id
 *   2. authorization  log entries under the AL witness keys 1, 2, ... until a key is empty, built per rc6 11.5
 *   3. manifests      under the data witness keys of the requested range, admissibility per 12.6
 *   4. candidates and canonical resolution from sequence 0 (13.4, 13.5), as of now
 * Result per sequence: CANONICAL with its commitment, or UNRESOLVED with flags; INCOMPLETE when a witness key
 * could not be enumerated to the end (12.7). Exit code 1 unless every requested sequence is CANONICAL.
 *
 * Usage: npx tsx src/scripts/byk-verify.ts --stream <64 hex> [--network devnet|mainnet] [--to <sequence>]
 *        (readers run the same code as one file: node byk-verify.mjs ..., see scripts/byk-verify-bundle.mjs)
 *        [--solana-rpc <url>] [--base-rpc <url>] [--base-from-block <n>] [--no-base] [--json]
 * Beta profile: every manifest is on Solana, one a day on Base, so Solana carries the range and Base is
 * checked for the genesis core, the log entries and whichever manifests it holds. */
import { Connection } from "@solana/web3.js";

import {
  type AnchoredPayload, authorized, base58Decode, BASE_EAS_ADDRESS_HEX, BASE_MAINNET_CHAIN_ID, BASE_SEPOLIA_CHAIN_ID, buildAuthorizationLog, collectCandidates, EPOCH_MS, equal, fromHex, keccak256,
  maxSequence, parseGenesisCore, parseManifest, recoverAddress, resolveCanonical, SOLANA_DEVNET_GENESIS_B58, SOLANA_MAINNET_GENESIS_B58, toHex, WITNESS_KIND, witnessKey,
} from "../lib/byk";
import { type BaseAnchor, BASE_MAINNET_RPC, BASE_SEPOLIA_RPC, type BaseNetwork, blockAtOrBefore, scanStreamAttestations } from "../lib/byk-chain/base";
import { assertSolanaNetwork, readAnchors, SOLANA_DEVNET_RPC, witnessAddress } from "../lib/byk-chain/solana";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const has = (name: string) => process.argv.includes(`--${name}`);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/* Public Solana endpoints rate-limit hard. web3.js retries a 429 on its own but prints a line for every retry, which
 * buried the verdict under dozens of "Server responded with 429" lines. This fetch keeps a steady pace (about eight
 * requests a second) and waits out a 429 quietly with a growing pause; after eight refusals it hands the 429 back so
 * the run fails loudly instead of hanging. */
function politeFetch(minGapMs = 125, maxTries = 8): typeof fetch {
  let next = 0;
  return async (input, init) => {
    for (let attempt = 0; ; attempt++) {
      const wait = next - Date.now();
      next = Math.max(next, Date.now()) + minGapMs;
      if (wait > 0) await sleep(wait);
      const res = await fetch(input, init);
      if (res.status !== 429 || attempt + 1 >= maxTries) return res;
      await sleep(Math.min(16_000, 500 * 2 ** attempt));
    }
  };
}

async function main(): Promise<void> {
  const streamHex = (arg("stream") ?? "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(streamHex)) throw new Error("--stream <64 hex characters> is required: it is the one value a verifier must get out of band");
  const streamId = fromHex(streamHex);
  /* Mainnet by default (2026-09-20): the public stream lives there, and a verifier that silently checked devnet
   * answered "no genesis core" to anyone who omitted the flag. Tests and the devnet rehearsal pass --network devnet. */
  const network = arg("network") ?? "mainnet";
  const mainnet = network === "mainnet";
  /* The default must keep FULL history. A pruned endpoint answers getSignaturesForAddress for an old witness key with
   * an empty list and no error, which reads exactly like "never anchored". PublicNode keeps about 46 hours (first
   * available block 447,502,546 on 18 Sep 2026) and would have stopped verifying this stream from genesis within two
   * days; api.mainnet-beta.solana.com serves from block 0. Any archive node works: --solana-rpc or SOLANA_RPC_URL,
   * and a pruned one is detected below and reported INCOMPLETE rather than trusted. */
  const solRpc = arg("solana-rpc") ?? (mainnet ? process.env.SOLANA_RPC_URL ?? "https://api.mainnet-beta.solana.com" : SOLANA_DEVNET_RPC);
  const baseNet: BaseNetwork = { chainId: mainnet ? BASE_MAINNET_CHAIN_ID : BASE_SEPOLIA_CHAIN_ID, rpcUrl: arg("base-rpc") ?? (mainnet ? BASE_MAINNET_RPC : BASE_SEPOLIA_RPC), easAddress: fromHex(BASE_EAS_ADDRESS_HEX) };
  const useBase = !has("no-base");
  const json = has("json");
  const say = (line: string) => {
    if (!json) console.log(line);
  };
  const conn = new Connection(solRpc, { commitment: "finalized", disableRetryOnRateLimit: true, fetch: politeFetch() });
  await assertSolanaNetwork(conn, base58Decode(mainnet ? SOLANA_MAINNET_GENESIS_B58 : SOLANA_DEVNET_GENESIS_B58));
  let incomplete = false;
  // how far back this endpoint's history reaches; 0 means an archive node
  const firstAvailable = await conn.getFirstAvailableBlock();
  const historyFromMs = firstAvailable > 0 ? ((await conn.getBlockTime(firstAvailable)) ?? Math.floor(Date.now() / 1000)) * 1000 : null;
  const prunedNote = (iso: string) => `this Solana endpoint keeps history only from ${iso}; an anchor older than that is invisible here, so its absence proves nothing. Use an archive endpoint (the default, https://api.mainnet-beta.solana.com) for a verdict`;

  // 1 · genesis core
  const gKey = witnessKey(streamId, WITNESS_KIND.GENESIS, BigInt(0));
  const gSol = await readAnchors(conn, gKey, streamId);
  incomplete ||= !gSol.complete;
  /* Base is read in one chunked pass over the stream's lifetime. The genesis time that bounds the pass comes
   * from the core found on Solana (it is re-checked against the pinned stream_id like any other copy); without
   * it the last two days are scanned. */
  const solCore = gSol.anchors.map((a) => a.payload).find((p) => p.kind === "genesis" && equal(keccak256(p.core), streamId));
  const sinceMs = solCore && solCore.kind === "genesis" ? parseGenesisCore(solCore.core).genesisEpochStartMs : BigInt(Date.now() - 2 * 86_400_000);
  const baseFrom = arg("base-from-block") !== undefined ? BigInt(arg("base-from-block")!) : await blockAtOrBefore(baseNet, sinceMs);
  const baseScan = useBase ? await scanStreamAttestations(baseNet, streamId, baseFrom) : null;
  /* Under the beta profile Solana witnesses every manifest and Base witnesses the genesis, the log entries and
   * one manifest a day, so a bounded Base scan never changes a verdict: it only removes a second copy. It is
   * still reported, because a reader deserves to know which part of the evidence was actually enumerated. */
  const baseIncomplete = Boolean(baseScan && !baseScan.complete);
  const onBase = (k: Uint8Array): BaseAnchor[] => baseScan?.byWitnessKey.get(toHex(k)) ?? [];
  const gBase = { anchors: onBase(gKey) };
  const cores = [...gSol.anchors, ...gBase.anchors].map((a) => a.payload).filter((p) => p.kind === "genesis");
  const core = cores.find((p) => p.kind === "genesis" && equal(keccak256(p.core), streamId));
  if (!core || core.kind !== "genesis") throw new Error(`no genesis core that hashes to the pinned stream_id under witness key ${witnessAddress(gKey)}${historyFromMs !== null ? `; ${prunedNote(new Date(historyFromMs).toISOString())}` : ""}`);
  const genesis = parseGenesisCore(core.core);
  if (historyFromMs !== null && historyFromMs > Number(genesis.genesisEpochStartMs)) {
    incomplete = true;
    say(`WARNING        ${prunedNote(new Date(historyFromMs).toISOString())}. Every sequence below is reported INCOMPLETE.`);
  }
  if (genesis.baseChainId !== baseNet.chainId || !equal(genesis.solanaGenesisHash, base58Decode(mainnet ? SOLANA_MAINNET_GENESIS_B58 : SOLANA_DEVNET_GENESIS_B58))) throw new Error("the genesis core names other networks than the ones being read");
  say(`genesis core   found on solana x${gSol.anchors.length}${baseScan ? `, base x${gBase.anchors.length} (blocks ${baseScan.scannedFrom} to ${baseScan.scannedTo} in ${baseScan.calls} calls of ${baseScan.chunkUsed}${baseScan.complete ? "" : ", STOPPED EARLY: pass --base-from-block or --no-base"})` : ""} · governance ${genesis.threshold}-of-${genesis.governance.length} · genesis ${new Date(Number(genesis.genesisEpochStartMs)).toISOString()}`);

  // 2 · authorization log
  const found: Array<{ entry: Uint8Array; bundle: Uint8Array }> = [];
  for (let logSeq = 1; logSeq < 1000; logSeq++) {
    const k = witnessKey(streamId, WITNESS_KIND.AL, BigInt(logSeq));
    const s = await readAnchors(conn, k, streamId);
    incomplete ||= !s.complete;
    const here = [...s.anchors, ...onBase(k)].map((a) => a.payload);
    if (here.length === 0) break;
    for (const p of here) if (p.kind === "al") found.push({ entry: p.entry, bundle: p.bundle });
    await sleep(120);
  }
  const al = buildAuthorizationLog(genesis, found);
  say(`authorization  ${found.length} anchored entr${found.length === 1 ? "y" : "ies"} · log status ${al.status} · head ${al.head.logSeq} · signers ${[...al.state.auth.keys()].map((a) => "0x" + a.slice(0, 8)).join(", ") || "none"}`);
  if (al.status !== "OK") throw new Error(`authorization log is ${al.status}: every result is undetermined until governance resolves it`);

  // 3 · manifests
  const startedAt = BigInt(Date.now());
  const sMax = maxSequence(genesis, startedAt);
  const to = arg("to") !== undefined ? BigInt(arg("to")!) : sMax;
  const payloads: AnchoredPayload[] = [];
  const witness = new Map<string, { solana: number; base: number; slot: number | null; timeSec: number | null }>();
  let emptyRun = 0;
  for (let s = BigInt(0); s <= to; s += BigInt(1)) {
    const k = witnessKey(streamId, WITNESS_KIND.DATA, s);
    const sol = await readAnchors(conn, k, streamId);
    incomplete ||= !sol.complete;
    const data = sol.anchors.filter((a) => a.payload.kind === "data");
    for (const a of data) if (a.payload.kind === "data") payloads.push({ manifest: a.payload.manifest, signature: a.payload.signature });
    witness.set(s.toString(), { solana: data.length, base: 0, slot: data[0]?.slot ?? null, timeSec: data[0]?.blockTimeSec ?? null });
    emptyRun = data.length === 0 ? emptyRun + 1 : 0;
    if (arg("to") === undefined && emptyRun >= 3) break; // the newest windows may simply not be anchored yet
    await sleep(120);
  }
  for (const [s] of witness) {
    const anchors = onBase(witnessKey(streamId, WITNESS_KIND.DATA, BigInt(s)));
    for (const a of anchors) if (a.payload.kind === "data") payloads.push({ manifest: a.payload.manifest, signature: a.payload.signature });
    witness.get(s)!.base = anchors.length;
  }

  /* 4 · candidates and canonical resolution, always from sequence 0, as of the moment reading FINISHED. Reading a
   * public endpoint takes minutes; a window that closes and gets anchored meanwhile is read, and judging it as of
   * the start would call it UNRESOLVED (a manifest from "the future") although nothing is wrong. Every piece of
   * evidence in hand was observed before this instant, so this is the honest as-of time. */
  const asOf = BigInt(Date.now());
  const cands = collectCandidates(al.state, genesis, payloads, asOf);
  const resolution = resolveCanonical(al.state, cands, genesis, asOf, to);
  const rows: Array<Record<string, unknown>> = [];
  let canonical = 0;
  let checked = 0;
  /* S_max(T) is a work bound derived from time alone (rc6 13.5), and a gap manifest advances the window far
   * faster than the sequence counter: after an outage the stream's head sits well below S_max, and every
   * sequence above it has no manifest because none was ever made. Counting those as UNRESOLVED would make a
   * healthy stream look broken, so the verdict covers the sequences that carry evidence, and the head is
   * printed so a reader can see where the stream actually is. */
  let head = BigInt(-1);
  for (const [s, r] of resolution) {
    const w = witness.get(s.toString());
    if (w && (w.solana > 0 || w.base > 0 || r.commitment !== null) && s > head) head = s;
  }
  for (const [s, r] of resolution) {
    const w = witness.get(s.toString());
    if (!w) continue;
    if (s > head) continue; // beyond the stream's head: not a hole, just not made yet
    checked++;
    const m = r.commitment ? cands.get(s)?.get(toHex(r.commitment))?.manifest : undefined;
    const lateS = m && w.timeSec ? w.timeSec - Number(m.epochEndMs) / 1000 : null;
    const state = incomplete ? "INCOMPLETE" : r.commitment ? "CANONICAL" : "UNRESOLVED";
    if (state === "CANONICAL") canonical++;
    rows.push({ sequence: s.toString(), state, commitment: r.commitment ? toHex(r.commitment) : null, flags: r.flags, status: m ? ["OK", "DEGRADED", "", "NO_DATA"][m.status] : null, records: m?.recordCount ?? null, window_end: m ? new Date(Number(m.epochEndMs)).toISOString() : null, solana_anchors: w.solana, base_anchors: w.base, solana_slot: w.slot, anchored_after_s: lateS, late: lateS !== null && lateS > 120 });
  }
  // the signer of every canonical manifest, recovered from the anchored signature
  for (const p of payloads) {
    const m = parseManifest(p.manifest);
    const c = keccak256(p.manifest);
    const r = resolution.get(m.sequence);
    if (r?.commitment && equal(r.commitment, c)) {
      const signer = recoverAddress(c, p.signature);
      if (!authorized(al.state, signer, m.sequence)) throw new Error(`internal: canonical manifest ${m.sequence} with an unauthorized signer`);
    }
  }
  if (json) console.log(JSON.stringify({ stream_id: streamHex, network, as_of: new Date(Number(asOf)).toISOString(), s_max: sMax.toString(), al_status: al.status, incomplete, base_scan_incomplete: baseIncomplete, sequences: rows }, null, 1));
  else {
    for (const r of rows) say(`seq ${String(r.sequence).padStart(5)}  ${String(r.state).padEnd(10)} ${String(r.commitment ?? "-").slice(0, 16)}  ${String(r.status ?? "-").padEnd(8)} records ${String(r.records ?? "-").padStart(3)}  end ${r.window_end ?? "-"}  solana x${r.solana_anchors}${Number(r.base_anchors) ? ` base x${r.base_anchors}` : ""}  anchored +${r.anchored_after_s ?? "?"} s${r.late ? " LATE" : ""}${(r.flags as string[]).length ? "  [" + (r.flags as string[]).join(",") + "]" : ""}`);
    say(`\n${canonical} of ${checked} sequences CANONICAL · stream head is sequence ${head} of a possible ${sMax} at this time (a gap manifest covers many windows in one sequence)${baseIncomplete ? " · the Base scan stopped early" : ""}${incomplete ? " · a Solana enumeration was INCOMPLETE" : ""}`);
    say(`read from ${solRpc.replace(/\?.*$/, "")}${useBase ? " and " + baseNet.rpcUrl : ""} · window length ${Number(EPOCH_MS) / 1000} s`);
  }
  process.exit(!incomplete && checked > 0 && canonical === checked ? 0 : 1);
}

main().catch((err) => {
  console.error(`[byk-verify] ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
