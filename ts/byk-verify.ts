/* BYK Data Layer · independent verifier. It is given ONE thing out of band, the stream_id, and reads everything
 * else from the two public chains: no database, no ByKaranteli API, no trust in who submitted what.
 *
 *   1. genesis core   from the genesis witness key; accepted only if keccak256(core) is the pinned stream_id
 *   2. authorization  log entries under the AL witness keys 1, 2, ... until a key is empty, built per rc6 11.5
 *   3. manifests      under the data witness keys of the requested range, admissibility per 12.6
 *   4. candidates and canonical resolution from sequence 0 (13.4, 13.5), as of now; or, with a reader checkpoint,
 *      from the reader's own earlier verdict (a RESUMED verdict, not the full one of 13.7)
 * Result per sequence: CANONICAL with its commitment, or UNRESOLVED with flags; INCOMPLETE when a witness key
 * could not be enumerated to the end (12.7). Exit code 1 unless every requested sequence is CANONICAL. A Base
 * witness that cannot be read never changes the verdict (beta profile) and is reported as an incomplete scan.
 *
 * Usage: npx tsx src/scripts/byk-verify.ts --stream <64 hex> [--network devnet|mainnet] [--to <sequence>]
 *        (readers run the same code as one file: node byk-verify.mjs ..., see scripts/byk-verify-bundle.mjs)
 *        [--solana-rpc <url>] [--base-rpc <url>] [--base-scan windows|range] [--base-from-block <n>] [--no-base] [--json]
 *        [--base-extension-hours <h>] [--checkpoint <file>] [--checkpoint-out <file>] [--cache-proof] [--help]
 * Environment: SOLANA_RPC_URL and BASE_RPC_URL stand in for the two --rpc flags on mainnet.
 * Beta profile: every manifest is on Solana, one a day on Base, so Solana carries the range and Base is
 * checked for the genesis core, the log entries and whichever manifests it holds. A Base endpoint that cannot
 * be read (throttled, down, pruned) is reported as an incomplete Base scan and never changes the verdict.
 * Base, two ways (2026-10-18): windows mode (the default) looks for each expected Base copy in a short block range
 * after its Solana anchor, the per-key query of 12.7 bounded in time, which a free endpoint capping eth_getLogs at
 * ten blocks completes in minutes; range mode (--base-scan range, or --base-from-block) is one pass over every block
 * since genesis, the full enumeration, for an endpoint that allows thousands of blocks per call.
 * Reader checkpoint (2026-10-18): --checkpoint-out writes the last CANONICAL sequence, its commitment and the
 * authorization log head after a run that passed; --checkpoint <that file> makes the next run read from that
 * sequence on and seed the resolution with it (the row is flagged READER_CHECKPOINT; nothing before it is re-read
 * in that run, so a late conflicting anchor for an older sequence is only seen by a full run). rc6 13.7 calls a
 * verdict that starts at a checkpoint non-conformant (N20) and allows cached results only when no new log entry
 * and no new anchor exists for the cached keys: the log head is compared (a changed log refuses the checkpoint);
 * without --cache-proof the anchors are not re-listed, so the output says RESUMED and a periodic full run gives
 * the 13.7 verdict; with --cache-proof (lib/byk-chain/cache-proof.ts) every data witness key before the checkpoint
 * is asked for its newest transaction and compared with the one the checkpoint recorded, so a run that finds
 * nothing new (or only failed and inadmissible transactions) carries the FULL verdict at the cost of one call a
 * sequence. The checkpoint is the reader's own earlier verdict, not a protocol object (the log's type 3 checkpoint
 * is governance-signed).
 * Nothing printed or written by this program carries an endpoint's path or query string: a keyed URL (Alchemy,
 * Infura, Helius) is cut to its host wherever it could appear (lib/byk-chain/redact.ts), because the daily run
 * commits its output to a public repository. */
import { readFileSync, writeFileSync } from "node:fs";

import { Connection } from "@solana/web3.js";

import {
  type AnchoredPayload, authorized, base58Decode, BASE_EAS_ADDRESS_HEX, BASE_MAINNET_CHAIN_ID, BASE_SEPOLIA_CHAIN_ID, buildAuthorizationLog, collectCandidates, EPOCH_MS, equal, fromHex, keccak256,
  type Manifest, maxSequence, parseGenesisCore, parseManifest, type ReaderCheckpoint, recoverAddress, resolveCanonical, SOLANA_DEVNET_GENESIS_B58, SOLANA_MAINNET_GENESIS_B58, toHex, WITNESS_KIND, witnessKey,
} from "./index";
import { assertBaseRpc, type BaseAnchor, BASE_MAINNET_RPC, BASE_SEPOLIA_RPC, type BaseNetwork, blockAtOrBefore, FIXED_WINDOW_BEFORE_MS, messageOf, type RangeScan, scanStreamAttestations, scanWitnessWindows, WINDOW_AFTER_MS, WINDOW_EXTENSION_MS, type WindowSpec, type WindowsScan } from "./byk-chain/base";
import { assembleNewestList, type CacheProof, proveCachedSequences, unprovable } from "./byk-chain/cache-proof";
import { alHeadChanged, type CheckpointFile, checkpointBaseFrom, checkpointCommitment, checkpointWindowsThrough, parseCheckpoint } from "./byk-chain/checkpoint";
import { endpointHost, oneLine, redactUrls } from "./byk-chain/redact";
import { assertSolanaNetwork, readAnchors, SOLANA_DEVNET_RPC, type SolanaAnchor, witnessAddress } from "./byk-chain/solana";
import { checkpointSequence, dataCopyWindows, fixedCopyWindow, windowsMarks } from "./byk-chain/windows";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const has = (name: string) => process.argv.includes(`--${name}`);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const USAGE = `byk-verify: independent verifier of a BYK Data Layer stream (reads only the Solana and Base chains)
  node byk-verify.mjs --stream <64 hex stream id> [--network mainnet|devnet] [--to <sequence>] [--json]
    --solana-rpc <url>        archive endpoint (default https://api.mainnet-beta.solana.com, or SOLANA_RPC_URL)
    --base-rpc <url>          Base endpoint (default https://mainnet.base.org, or BASE_RPC_URL)
    --base-scan windows|range windows (default): each expected Base copy is looked for in a short block range around the
                              time the engine sent it (the end of the manifest's window, the Solana anchor's time for the
                              genesis core and a log entry), about fifty calls a copy on a free endpoint that caps
                              eth_getLogs at ten blocks (a copy with no Solana twin is invisible to this mode, and the
                              genesis core must be on the Solana endpoint: an archive one); range: one pass over every
                              block since genesis (or the checkpoint, or --base-from-block), the full enumeration, for an
                              endpoint that allows thousands of blocks per call
    --base-from-block <n>     first Base block of a range scan (default: the genesis time, or the checkpoint's last scanned block)
    --base-extension-hours <h> windows mode: how far beyond its window a copy that is not there is looked for (default 6;
                              a periodic full run may pass 24 to settle a copy the daily runs reported MISSING)
    --no-base                 skip the Base witness (the verdict rests on Solana under the beta profile)
    --checkpoint <file>       continue from a checkpoint written by an earlier run (--checkpoint-out)
    --checkpoint-out <file>   after a run that passed, write the last CANONICAL sequence for the next run
    --cache-proof             with --checkpoint: ask every data witness key before the checkpoint for its newest
                              transaction (one call a sequence) and compare it with the one the checkpoint recorded;
                              when nothing new was anchored under any of them (failed and inadmissible transactions
                              do not count), the cached sequences are provably unchanged and the verdict is FULL under
                              rc6 13.7 instead of RESUMED; a full run with --checkpoint-out records the signatures
  Exit code 0 only when every checked sequence is CANONICAL and no Solana enumeration was incomplete.`;

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

const errorText = (err: unknown): string => redactUrls(messageOf(err));

async function main(): Promise<void> {
  if (has("help")) {
    console.log(USAGE);
    return;
  }
  const streamHex = (arg("stream") ?? "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(streamHex)) throw new Error("--stream <64 hex characters> is required: it is the one value a verifier must get out of band");
  const streamId = fromHex(streamHex);
  /* Mainnet is the default since 20 Sep 2026: the first public day showed that a devnet default silently
   * answered "no genesis core" to anyone who omitted the flag. Tests and the devnet rehearsal pass --network devnet. */
  const network = arg("network") ?? "mainnet";
  const mainnet = network === "mainnet";
  /* The default must keep FULL history. A pruned endpoint answers getSignaturesForAddress for an old witness key with
   * an empty list and no error, which reads exactly like "never anchored". PublicNode keeps about 46 hours (first
   * available block 447,502,546 on 18 Sep 2026) and would have stopped verifying this stream from genesis within two
   * days; api.mainnet-beta.solana.com serves from block 0. Any archive node works: --solana-rpc or SOLANA_RPC_URL,
   * and a pruned one is detected below and reported INCOMPLETE rather than trusted. */
  const solRpc = arg("solana-rpc") ?? (mainnet ? process.env.SOLANA_RPC_URL ?? "https://api.mainnet-beta.solana.com" : SOLANA_DEVNET_RPC);
  const baseNet: BaseNetwork = { chainId: mainnet ? BASE_MAINNET_CHAIN_ID : BASE_SEPOLIA_CHAIN_ID, rpcUrl: arg("base-rpc") ?? (mainnet ? process.env.BASE_RPC_URL ?? BASE_MAINNET_RPC : BASE_SEPOLIA_RPC), easAddress: fromHex(BASE_EAS_ADDRESS_HEX) };
  const useBase = !has("no-base");
  const baseFromFlag = arg("base-from-block");
  if (baseFromFlag !== undefined && !/^\d+$/.test(baseFromFlag)) throw new Error("--base-from-block takes a block number");
  const baseScanArg = arg("base-scan");
  if (baseScanArg !== undefined && baseScanArg !== "windows" && baseScanArg !== "range") throw new Error("--base-scan takes windows or range");
  if (baseScanArg === "windows" && baseFromFlag !== undefined) throw new Error("--base-from-block belongs to range mode: drop it or pass --base-scan range");
  const baseMode: "windows" | "range" = baseScanArg ?? (baseFromFlag !== undefined ? "range" : "windows");
  const extensionArg = arg("base-extension-hours");
  if (extensionArg !== undefined && !/^\d{1,3}$/.test(extensionArg)) throw new Error("--base-extension-hours takes a whole number of hours");
  if (extensionArg !== undefined && baseMode === "range") throw new Error("--base-extension-hours belongs to windows mode: range mode reads every block and extends nothing");
  const extensionMs = extensionArg !== undefined ? BigInt(extensionArg) * BigInt(3_600_000) : WINDOW_EXTENSION_MS;
  const json = has("json");
  const cpPath = arg("checkpoint");
  let cpText: string | null = null;
  if (cpPath !== undefined) {
    try {
      cpText = readFileSync(cpPath, "utf8");
    } catch (err) {
      throw new Error(`--checkpoint ${cpPath} could not be read: ${messageOf(err)}`);
    }
  }
  const cp: CheckpointFile | null = cpText !== null ? parseCheckpoint(cpText, streamHex, network, `--checkpoint ${cpPath}`) : null;
  const seed: ReaderCheckpoint | undefined = cp ? { sequence: BigInt(cp.sequence), commitment: checkpointCommitment(cp), historyUnresolvedBefore: cp.history_unresolved_before === true } : undefined;
  const cacheProof = has("cache-proof");
  if (cacheProof && cp === null) throw new Error("--cache-proof belongs to a resumed run: pass --checkpoint <file> as well (a full run with --checkpoint-out records the signatures the proof compares against)");
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
  /* Range mode reads Base here, in one chunked pass over the stream's lifetime. The genesis time that bounds the pass
   * comes from the core found on Solana (it is re-checked against the pinned stream_id like any other copy); without
   * it the last two days are scanned. Windows mode reads Base after the Solana anchors, which it needs to place the
   * windows (step 3b). */
  const solCore = gSol.anchors.map((a) => a.payload).find((p) => p.kind === "genesis" && equal(keccak256(p.core), streamId));
  const sinceMs = solCore && solCore.kind === "genesis" ? parseGenesisCore(solCore.core).genesisEpochStartMs : BigInt(Date.now() - 2 * 86_400_000);
  /* Under the beta profile Solana witnesses every manifest and Base witnesses the genesis, the log entries and
   * one manifest a day, so a bounded Base scan never changes a verdict: it only removes a second copy. It is
   * still reported, because a reader deserves to know which part of the evidence was actually enumerated. Every
   * Base call sits inside a try: an endpoint that throttles for good, is down, is pruned or is another chain
   * is reported the same way instead of ending the run (18 Oct 2026: mainnet.base.org answered "request limit
   * reached" and the default command exited 1). A checkpoint carries the last Base block its range scan covered; the
   * next range scan starts an hour of blocks earlier so a reorganised or late-indexed attestation is not missed;
   * without one the pass starts at the genesis time. */
  const baseHits = new Map<string, BaseAnchor[]>();
  let baseScan: RangeScan | null = null;
  let baseWindows: WindowsScan | null = null;
  let baseError: string | null = null;
  // a range scan that started at the genesis time (not at --base-from-block, not at a checkpoint's block) and reached the head covered every window
  let rangeFromGenesis = false;
  if (useBase && baseMode === "range") {
    try {
      await assertBaseRpc(baseNet);
      const cpBaseFrom = cp ? checkpointBaseFrom(cp) : null;
      rangeFromGenesis = baseFromFlag === undefined && cpBaseFrom === null && solCore !== undefined; // without the core on Solana the pass starts two days back, not at genesis
      const baseFrom = baseFromFlag !== undefined ? BigInt(baseFromFlag) : cpBaseFrom !== null ? cpBaseFrom : await blockAtOrBefore(baseNet, sinceMs);
      baseScan = await scanStreamAttestations(baseNet, streamId, baseFrom);
      for (const [k, list] of baseScan.byWitnessKey) baseHits.set(k, list);
    } catch (err) {
      baseError = errorText(err);
    }
  }
  const notReadAdvice = "Under the beta profile every manifest is on Solana, so the verdict below rests on Solana alone; pass --base-rpc <url> (or BASE_RPC_URL) for the second copy, or --no-base to skip it.";
  const warnBase = () => say(`${baseMode === "windows" ? "base witness   NOT READ" : "WARNING        the Base witness could not be read"}: ${oneLine(baseError!)}. ${notReadAdvice}`);
  const warnBaseWindows = () => say(`base witness   NOT READ: not one block was read before the endpoint ${baseWindows?.stopReason === "error" ? `failed (${oneLine(baseWindows.error ?? "", 160)})` : "throttled for good"}. ${notReadAdvice}`);
  if (baseError !== null) warnBase();
  const onBase = (k: Uint8Array): BaseAnchor[] => baseHits.get(toHex(k)) ?? [];
  const cores = [...gSol.anchors, ...onBase(gKey)].map((a) => a.payload).filter((p) => p.kind === "genesis");
  const core = cores.find((p) => p.kind === "genesis" && equal(keccak256(p.core), streamId));
  if (!core || core.kind !== "genesis") throw new Error(`no genesis core that hashes to the pinned stream_id under witness key ${witnessAddress(gKey)}${historyFromMs !== null ? `; ${prunedNote(new Date(historyFromMs).toISOString())}` : ""}`);
  const genesis = parseGenesisCore(core.core);
  const pruned = historyFromMs !== null && historyFromMs > Number(genesis.genesisEpochStartMs);
  if (pruned) {
    incomplete = true;
    say(`WARNING        ${prunedNote(new Date(historyFromMs).toISOString())}. Every sequence below is reported INCOMPLETE.`);
  }
  if (genesis.baseChainId !== baseNet.chainId || !equal(genesis.solanaGenesisHash, base58Decode(mainnet ? SOLANA_MAINNET_GENESIS_B58 : SOLANA_DEVNET_GENESIS_B58))) throw new Error("the genesis core names other networks than the ones being read");
  const baseStop = baseScan && !baseScan.complete ? (baseScan.stopReason === "rate_limited" ? ", STOPPED EARLY: the endpoint kept throttling; pass --base-rpc, --base-from-block or --no-base" : ", STOPPED EARLY: call budget; pass --base-from-block or --no-base") : "";
  const baseNote = baseScan ? `, base x${onBase(gKey).length} (blocks ${baseScan.scannedFrom} to ${baseScan.scannedTo} in ${baseScan.calls} calls of ${baseScan.chunkUsed}${baseStop})` : useBase && baseMode === "windows" && baseError === null ? ", base: read after the Solana anchors (windows mode, the base witness line below)" : useBase ? ", base NOT READ" : "";
  say(`genesis core   found on solana x${gSol.anchors.length}${baseNote} · governance ${genesis.threshold}-of-${genesis.governance.length} · genesis ${new Date(Number(genesis.genesisEpochStartMs)).toISOString()}`);

  // 2 · authorization log
  const found: Array<{ entry: Uint8Array; bundle: Uint8Array }> = [];
  const alSolana = new Map<bigint, SolanaAnchor[]>();
  for (let logSeq = 1; logSeq < 1000; logSeq++) {
    const k = witnessKey(streamId, WITNESS_KIND.AL, BigInt(logSeq));
    const s = await readAnchors(conn, k, streamId);
    incomplete ||= !s.complete;
    const here = [...s.anchors, ...onBase(k)].map((a) => a.payload);
    if (here.length === 0) break;
    if (s.anchors.length > 0) alSolana.set(BigInt(logSeq), s.anchors);
    for (const p of here) if (p.kind === "al") found.push({ entry: p.entry, bundle: p.bundle });
    await sleep(120);
  }
  const al = buildAuthorizationLog(genesis, found);
  say(`authorization  ${found.length} anchored entr${found.length === 1 ? "y" : "ies"} · log status ${al.status} · head ${al.head.logSeq} · signers ${[...al.state.auth.keys()].map((a) => "0x" + a.slice(0, 8)).join(", ") || "none"}`);
  if (al.status !== "OK") throw new Error(`authorization log is ${al.status}: every result is undetermined until governance resolves it`);
  if (cp) {
    const changed = alHeadChanged(cp, al.head);
    if (changed !== null) throw new Error(changed);
  }

  /* 2b · cache proof (rc6 13.7, --cache-proof): the sequences before the checkpoint are not re-read; instead every one of
   * their data witness keys is asked for its newest transaction and compared with the one the checkpoint recorded. Nothing
   * new, or only failed and inadmissible transactions, means no new admissible anchor under any cached key, which with the
   * unchanged log head above is the 13.7 condition for reusing the cached results: the verdict is then FULL. */
  let proof: CacheProof | null = null;
  if (cp && seed && cacheProof) {
    const stored = cp.newest_signatures ?? null;
    if (stored === null) proof = unprovable("the checkpoint carries no newest_signatures list (written before a full run of this reader recorded one); a full run with --checkpoint-out records every key", []);
    else if (pruned) proof = unprovable("this Solana endpoint is pruned, so a key that lists nothing here proves nothing; use an archive endpoint", stored);
    else {
      say(`cache proof    asking the ${seed.sequence} data witness keys before the checkpoint for their newest transaction (one call each, rc6 13.7)`);
      try {
        proof = await proveCachedSequences(conn, streamId, stored, seed.sequence);
      } catch (err) {
        /* the proof is optional: an endpoint error inside it leaves the verdict RESUMED instead of ending the run */
        proof = unprovable(`the proof stopped on an endpoint error: ${oneLine(errorText(err), 300)}`, stored);
      }
    }
    if (proof.proven) say(`cache proof    HELD on the Solana witness: ${proof.checked} cached sequences, ${proof.changed} with new transactions, all ${proof.inadmissible} of them inadmissible, ${proof.calls} calls: with the unchanged log head the cached results are provably identical to a full evaluation, so this run carries the FULL verdict (the Base copies of cached sequences are not read again; the Sunday full run looks for them)`);
    else say(`cache proof    NOT HELD after ${proof.checked} sequences and ${proof.calls} calls: ${proof.reason}. The verdict below stays RESUMED.`);
  }

  // 3 · manifests
  const startedAt = BigInt(Date.now());
  const sMax = maxSequence(genesis, startedAt);
  const to = arg("to") !== undefined ? BigInt(arg("to")!) : sMax;
  const from = seed ? seed.sequence : BigInt(0);
  if (from > to) throw new Error(`the checkpoint sequence ${from} is beyond the requested range (--to ${to})`);
  if (seed) say(`checkpoint     ${proof?.proven ? "FULL (unless an enumeration below is incomplete)" : "RESUMED"} from sequence ${from} (reader checkpoint${cp?.as_of ? ` of ${cp.as_of}` : ""}): sequences before it ${proof?.proven ? "are not re-read, but every one of their witness keys was shown to carry nothing new since that run (cache proof), the rc6 13.7 condition for reusing them" : "rely on the run that wrote it and are not re-read here; this is not the full rc6 13.7 verdict"}`);
  const payloads: AnchoredPayload[] = [];
  const newestBySeq = new Map<bigint, string | null>(); // the newest transaction under each key read here, for the next checkpoint's cache proof
  const witness = new Map<string, { solana: number; base: number; slot: number | null; timeSec: number | null }>();
  const dataSolana = new Map<bigint, { anchors: SolanaAnchor[]; manifest: Manifest }>();
  let emptyRun = 0;
  for (let s = from; s <= to; s += BigInt(1)) {
    const k = witnessKey(streamId, WITNESS_KIND.DATA, s);
    const sol = await readAnchors(conn, k, streamId);
    incomplete ||= !sol.complete;
    newestBySeq.set(s, sol.newestSignature);
    const data = sol.anchors.filter((a) => a.payload.kind === "data");
    for (const a of data) if (a.payload.kind === "data") payloads.push({ manifest: a.payload.manifest, signature: a.payload.signature });
    const firstData = data[0]?.payload;
    if (firstData && firstData.kind === "data") dataSolana.set(s, { anchors: data, manifest: parseManifest(firstData.manifest) });
    witness.set(s.toString(), { solana: data.length, base: 0, slot: data[0]?.slot ?? null, timeSec: data[0]?.blockTimeSec ?? null });
    emptyRun = data.length === 0 ? emptyRun + 1 : 0;
    if (arg("to") === undefined && emptyRun >= 3) break; // the newest windows may simply not be anchored yet
    await sleep(120);
  }

  /* 3b · the Base copies, windows mode: one or two windows per expected copy, placed from what was just read on Solana
   * (lib/byk-chain/windows.ts says where: a data manifest's copy right after the end of its window, the genesis core's and
   * a log entry's around the Solana block time). Expected means what the beta profile sends to Base: the genesis manifest
   * and the one whose window ends at or crosses 00:00 UTC, planned within the engine's horizon. A resumed run walks only
   * what its checkpoint has not: the data windows after base_windows_through, and the genesis and log windows unless
   * base_fixed_windows says an earlier run of this reader walked them (a changed log head refused the checkpoint above, so
   * the log windows it covered still hold). What this mode cannot see is a copy with no Solana twin: there is no time to
   * place its window, so a log entry anchored only on Base stays invisible here and is found by range mode alone. */
  const fixedSkipped = cp?.base_fixed_windows === true;
  const windowsThroughBefore = cp ? checkpointWindowsThrough(cp) : BigInt(-1);
  let unplacedFixed = 0;
  const blockTimes = (anchors: SolanaAnchor[]): number[] => anchors.map((a) => a.blockTimeSec).filter((t): t is number => t !== null);
  if (useBase && baseMode === "windows") {
    try {
      await assertBaseRpc(baseNet);
      const specs: WindowSpec[] = [];
      if (!fixedSkipped) {
        const fixed = (key: Uint8Array, kind: "genesis" | "al", n: bigint, anchors: SolanaAnchor[]) => {
          const spec = fixedCopyWindow(key, kind, n, blockTimes(anchors));
          if (spec) specs.push(spec);
          else unplacedFixed++; // a Solana anchor without a block time cannot place a window: reported, never guessed
        };
        fixed(gKey, "genesis", BigInt(0), gSol.anchors);
        for (const [logSeq, anchors] of alSolana) fixed(witnessKey(streamId, WITNESS_KIND.AL, logSeq), "al", logSeq, anchors);
      }
      for (const [s, { anchors, manifest }] of dataSolana) {
        if (s <= windowsThroughBefore) continue;
        specs.push(...dataCopyWindows(witnessKey(streamId, WITNESS_KIND.DATA, s), s, manifest, blockTimes(anchors)));
      }
      baseWindows = await scanWitnessWindows(baseNet, streamId, specs, { extensionMs });
      for (const [k, list] of baseWindows.byWitnessKey) baseHits.set(k, list);
    } catch (err) {
      baseError = errorText(err);
      warnBase();
    }
  }
  if (baseWindows) {
    const w = baseWindows;
    const of = (kind: WindowSpec["kind"]) => w.copies.filter((x) => x.kind === kind).length;
    const stop = !w.complete ? (w.stopReason === "rate_limited" ? " · STOPPED EARLY: the endpoint kept throttling; the windows after that are not walked" : w.stopReason === "error" ? ` · STOPPED EARLY: the endpoint failed (${oneLine(w.error ?? "", 160)}); the windows after that are not walked` : " · STOPPED EARLY: call budget; the windows after that are not walked") : "";
    say(`base witness   windows mode: ${w.copies.length} expected cop${w.copies.length === 1 ? "y" : "ies"} (genesis ${of("genesis")}, log ${of("al")}, data ${of("data")}${fixedSkipped ? "; genesis and log windows walked by the run that wrote the checkpoint" : ""}) in ${w.windows.length} window${w.windows.length === 1 ? "" : "s"} · found ${w.found} · missing ${w.missing} · still open ${w.open} · not walked ${w.notWalked} · ${w.calls} calls of up to ${w.chunkUsed + BigInt(1)} blocks${unplacedFixed ? ` · ${unplacedFixed} not placed (no block time on Solana)` : ""}${w.driftBlocks !== BigInt(0) ? ` · clock drift ${w.driftBlocks} blocks` : ""}${w.driftRejected !== null ? ` · WARNING: the probe block disagreed with the arithmetic by ${w.driftRejected} blocks, not believed; the windows stand on the arithmetic` : ""}${stop}`);
    for (const c of w.copies) if (c.status === "missing") say(`base witness   MISSING: ${c.kind === "data" ? `manifest ${c.n}` : c.kind === "al" ? `log entry ${c.n}` : "genesis core"} has no Base copy in ${w.windows.filter((x) => x.kind === c.kind && x.n === c.n).map((x) => `blocks ${x.from} to ${x.to}${x.extended ? " (extended)" : ""}`).join(" nor ")}; a run without --checkpoint and with --base-extension-hours 24, or range mode (--base-scan range), looks further`);
    if (w.latestBlock < BigInt(0)) warnBaseWindows();
  }
  for (const [s] of witness) {
    const anchors = onBase(witnessKey(streamId, WITNESS_KIND.DATA, BigInt(s)));
    for (const a of anchors) if (a.payload.kind === "data") payloads.push({ manifest: a.payload.manifest, signature: a.payload.signature });
    witness.get(s)!.base = anchors.length;
  }
  const baseIncomplete = useBase && (baseMode === "range" ? baseScan === null || !baseScan.complete : baseWindows === null || !baseWindows.complete);
  /* Read at all: a range scan that ran, or a windows pass that read at least the latest block (a pass that could not even
   * do that, throttled or failed, read nothing and is treated like an endpoint that could not be reached). */
  const baseRead = useBase && (baseScan !== null || (baseWindows !== null && baseWindows.latestBlock >= BigInt(0)));

  /* 4 · candidates and canonical resolution, always from sequence 0, as of the moment reading FINISHED. Reading a
   * public endpoint takes minutes; a window that closes and gets anchored meanwhile is read, and judging it as of
   * the start would call it UNRESOLVED (a manifest from "the future") although nothing is wrong. Every piece of
   * evidence in hand was observed before this instant, so this is the honest as-of time. */
  const asOf = BigInt(Date.now());
  const cands = collectCandidates(al.state, genesis, payloads, asOf);
  const resolution = resolveCanonical(al.state, cands, genesis, asOf, to, seed);
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
    const isSeed = seed !== undefined && s === seed.sequence;
    if (!isSeed) checked++;
    const m = r.commitment ? cands.get(s)?.get(toHex(r.commitment))?.manifest : undefined;
    const lateS = m && w.timeSec ? w.timeSec - Number(m.epochEndMs) / 1000 : null;
    const state = isSeed ? "CHECKPOINT" : incomplete ? "INCOMPLETE" : r.commitment ? "CANONICAL" : "UNRESOLVED";
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
  /* A resumed run with no sequence after its checkpoint yet has nothing to check and still passes (the checkpoint is
   * carried forward); a full run with nothing to check does not. */
  const passed = !incomplete && canonical === checked && (checked > 0 || seed !== undefined);
  const headRow = head >= BigInt(0) ? resolution.get(head) : undefined;
  const cpOut = arg("checkpoint-out");
  let written: CheckpointFile | null = null;
  /* A run that could not read the Base witness at all keeps the previous checkpoint. In range mode its log head would come
   * from Solana alone and a log entry anchored only on Base would surface one run later as a puzzling "log head differs";
   * in windows mode the log is built from Solana in every run (a Base copy found later is counted, not fed into the log),
   * and the checkpoint's windows marks must not say "walked" for a run that read nothing. */
  const baseUnread = useBase && !baseRead;
  /* Windows mode: the checkpoint stops right before the first data copy whose window was not walked to the end, and never
   * goes behind the seed (lib/byk-chain/windows.ts, checkpointSequence). */
  const { sequence: cpSequence, heldBy } = checkpointSequence(head, seed !== undefined ? seed.sequence : null, baseWindows ? baseWindows.copies : null);
  const cpRow = cpSequence >= BigInt(0) ? resolution.get(cpSequence) : undefined;
  if (cpOut !== undefined && passed && headRow?.commitment && !baseUnread && cpRow?.commitment) {
    const seedHistory = seed !== undefined && cpSequence === seed.sequence && seed.historyUnresolvedBefore === true;
    /* The Base coverage carried forward is the furthest block any range scan actually read: a scan stopped by the budget or
     * by throttling still advances it (scannedTo is the last block covered), so the next range scan continues from there.
     * Windows mode carries the highest data sequence whose window was walked completely (the windows are walked in
     * sequence order and a stopped walker stays stopped, so the complete ones are a prefix) and whether the genesis and log
     * windows were walked; a range run carries the windows fields of its checkpoint unchanged, and the other way round. */
    const scannedBefore = cp?.base_scanned_to ? BigInt(cp.base_scanned_to) : BigInt(-1);
    const scannedNow = baseScan ? baseScan.scannedTo : BigInt(-1);
    const baseTo = scannedNow > scannedBefore ? scannedNow : scannedBefore;
    /* A range scan read Base before the Solana anchors, up to its latest block: the copies it can vouch for are the ones
     * whose window, plus the hours windows mode looks beyond one before calling a copy missing, had closed by that block's
     * time (a data manifest's from its window end, the genesis core's and a log entry's from their Solana block time with
     * the long lead); later ones are left to windows mode. */
    let rangeCovered: { through: bigint; fixed: boolean } | null = null;
    if (baseScan && baseScan.complete && rangeFromGenesis) {
      const closedBy = baseScan.latestTimeMs;
      let through = BigInt(-1);
      /* A copy is sent in the tick that sends the Solana copy, so a manifest whose Solana anchor landed after the scan read the
       * head (sealed late, during the run) was not scanned either, however old its window: its Solana time counts as well. */
      for (const [s, { anchors, manifest }] of dataSolana) {
        const times = blockTimes(anchors);
        const sentBy = times.length ? BigInt(Math.max(...times)) * BigInt(1000) : null;
        if (sentBy === null) continue;
        const latestSend = sentBy > manifest.epochEndMs ? sentBy : manifest.epochEndMs;
        if (latestSend + WINDOW_AFTER_MS + WINDOW_EXTENSION_MS <= closedBy && s > through) through = s;
      }
      const fixedTimes = [...gSol.anchors, ...[...alSolana.values()].flat()].map((a) => a.blockTimeSec);
      const fixedClosed = fixedTimes.length > 0 && fixedTimes.every((t) => t !== null && BigInt(t) * BigInt(1000) + FIXED_WINDOW_BEFORE_MS + WINDOW_AFTER_MS + WINDOW_EXTENSION_MS <= closedBy);
      rangeCovered = { through, fixed: fixedClosed };
    }
    const { through: windowsThrough, fixed: fixedWindows } = windowsMarks({ copies: baseWindows ? baseWindows.copies : null, cpSequence, throughBefore: windowsThroughBefore, fixedBefore: fixedSkipped, unplacedFixed, rangeCovered });
    /* The cache proof's record (rc6 13.7): the newest transaction under each data witness key up to the checkpoint sequence.
     * A full run listed every key and records them all; a resumed run keeps the cached part of the list it continued from
     * (moved forward on the keys whose new transactions the proof saw were all inadmissible) and adds the keys it read
     * itself; a resumed run from a checkpoint without a list records none, since the keys before its seed were never
     * listed by this reader's lineage. */
    const cachedPart: Array<string | null> | null = seed === undefined ? [] : proof !== null && proof.newest.length > 0 ? proof.newest : (cp?.newest_signatures ?? null);
    const newestSignatures = assembleNewestList(cachedPart, from, cpSequence, newestBySeq);
    written = { stream_id: streamHex, network, sequence: cpSequence.toString(), commitment: toHex(cpRow.commitment), history_unresolved_before: cpRow.flags.includes("HISTORY_UNRESOLVED_BEFORE") || seedHistory, al_head: { log_seq: al.head.logSeq.toString(), entry_hash: toHex(al.head.entryHash) }, solana_slot: witness.get(cpSequence.toString())?.slot ?? null, base_scanned_to: baseTo >= BigInt(0) ? baseTo.toString() : null, base_windows_through: windowsThrough >= BigInt(0) ? windowsThrough.toString() : null, base_fixed_windows: fixedWindows, as_of: new Date(Number(asOf)).toISOString(), previous: cp ? { sequence: cp.sequence, commitment: cp.commitment } : null, newest_signatures: newestSignatures };
    writeFileSync(cpOut, JSON.stringify(written, null, 1) + "\n");
  }
  const baseSummary = baseScan
    ? { mode: "range" as const, from: baseScan.scannedFrom.toString(), to: baseScan.scannedTo.toString(), calls: baseScan.calls, complete: baseScan.complete, stop: baseScan.stopReason }
    : baseWindows
      ? { mode: "windows" as const, copies: baseWindows.copies.length, windows: baseWindows.windows.length, found: baseWindows.found, missing: baseWindows.missing, open: baseWindows.open, not_walked: baseWindows.notWalked, unplaced: unplacedFixed, fixed_windows_from_checkpoint: fixedSkipped, calls: baseWindows.calls, chunk: baseWindows.chunkUsed.toString(), latest_block: baseWindows.latestBlock.toString(), drift_blocks: baseWindows.driftBlocks.toString(), drift_rejected: baseWindows.driftRejected?.toString() ?? null, complete: baseWindows.complete, stop: baseWindows.stopReason, error: baseWindows.error !== null ? oneLine(baseWindows.error, 400) : null }
      : null;
  /* FULL: every sequence read in this run, or the cached ones proven unchanged (rc6 13.7) and the rest enumerated to the end;
   * RESUMED otherwise. */
  const verdict: "full" | "resumed" = seed === undefined || (proof?.proven === true && !incomplete) ? "full" : "resumed";
  if (json) console.log(JSON.stringify({ stream_id: streamHex, network, as_of: new Date(Number(asOf)).toISOString(), s_max: sMax.toString(), al_status: al.status, incomplete, base_scan_incomplete: baseIncomplete, base_scan_error: baseError, base_scan: baseSummary, base_copies: baseWindows ? baseWindows.copies : null, base_windows: baseWindows ? baseWindows.windows : null, verdict, cache_proof: proof ? { proven: proof.proven, witness: "solana", checked: proof.checked, changed: proof.changed, inadmissible: proof.inadmissible, calls: proof.calls, reason: proof.reason, sequence: proof.sequence } : null, resolved_from: cp ? { sequence: cp.sequence, commitment: cp.commitment, note: verdict === "full" ? "reader checkpoint from an earlier run: sequences before it were not re-read, but every data witness key before it was shown to carry nothing new on the Solana witness since that run (cache proof), so the cached results are provably identical to a full evaluation and this is a full verdict under rc6 13.7" : proof?.proven ? "reader checkpoint from an earlier run: the cache proof held, but a Solana enumeration of this run was incomplete, so this is a resumed verdict" : "reader checkpoint from an earlier run: sequences before it were not re-read, so this is a resumed verdict, not the full rc6 13.7 one" } : null, checkpoint_written: written ? { path: cpOut, sequence: written.sequence } : null, checkpoint_kept: cpOut !== undefined && !written ? (baseUnread ? "the Base witness was not read" : !passed ? "the run did not pass" : heldBy !== null ? `the Base window of sequence ${heldBy} is not walked yet` : "nothing to write") : null, checkpoint_held_before: written && heldBy !== null && BigInt(written.sequence) < head ? heldBy.toString() : null, checked, canonical, passed, sequences: rows }, null, 1));
  else {
    for (const r of rows) say(`seq ${String(r.sequence).padStart(5)}  ${String(r.state).padEnd(10)} ${String(r.commitment ?? "-").slice(0, 16)}  ${String(r.status ?? "-").padEnd(8)} records ${String(r.records ?? "-").padStart(3)}  end ${r.window_end ?? "-"}  solana x${r.solana_anchors}${Number(r.base_anchors) ? ` base x${r.base_anchors}` : ""}  anchored +${r.anchored_after_s ?? "?"} s${r.late ? " LATE" : ""}${(r.flags as string[]).length ? "  [" + (r.flags as string[]).join(",") + "]" : ""}`);
    if (seed && checked === 0) say(`no sequence after the checkpoint at ${seed.sequence} is anchored yet; the checkpoint is carried forward`);
    const baseTail = baseIncomplete ? (baseError ? " · the Base witness was not read" : " · the Base scan stopped early") : baseWindows ? ` · Base copies ${baseWindows.found} of ${baseWindows.copies.length} expected${baseWindows.missing ? ` (${baseWindows.missing} MISSING)` : ""}${baseWindows.open ? ` (${baseWindows.open} still open)` : ""}` : "";
    say(`\n${canonical} of ${checked} sequences CANONICAL${seed ? ` after the reader checkpoint at ${seed.sequence} (${verdict === "full" ? "FULL verdict, cache proof held" : "RESUMED verdict"})` : ""} · stream head is sequence ${head} of a possible ${sMax} at this time (a gap manifest covers many windows in one sequence)${baseTail}${incomplete ? " · a Solana enumeration was INCOMPLETE" : ""}`);
    if (written) say(`checkpoint     written to ${cpOut}: sequence ${written.sequence}${BigInt(written.sequence) < head ? ` (held before sequence ${heldBy}, whose Base window is not walked yet: the next run reads it again)` : ""}${written.newest_signatures ? `, ${written.newest_signatures.length} newest signatures recorded for the cache proof` : ", no newest-signature list (a full run records one)"}, next run continues from there`);
    else if (cpOut !== undefined && baseUnread) say(`checkpoint     not written: the Base witness was not read in this run; the previous checkpoint stands`);
    say(`read from ${endpointHost(solRpc)}${useBase ? " and " + endpointHost(baseNet.rpcUrl) : ""} · window length ${Number(EPOCH_MS) / 1000} s`);
  }
  process.exit(passed ? 0 : 1);
}

main().catch((err) => {
  console.error(`[byk-verify] ${errorText(err)}`);
  process.exit(1);
});
