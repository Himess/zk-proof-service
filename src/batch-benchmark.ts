/**
 * Batch Benchmark — measures ZK proof generation performance.
 *
 * Runs 3 sequential proof generations via direct localhost fetch (no MPP)
 * to measure warm performance characteristics.
 *
 * Usage: npx tsx src/batch-benchmark.ts
 *
 * Requires: Server running on localhost:3402 in free mode,
 *           or MPP disabled for benchmarking.
 */
// @ts-ignore
import { buildPoseidon } from "circomlibjs";

const SERVER_URL = "http://localhost:3402";
const RUNS = 3;

// ─── Pretty Logging ──────────────────────────────────────────────────────────

const CYAN = "\x1b[36m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";

function banner(text: string) {
  const line = "═".repeat(60);
  console.log(`\n${CYAN}${line}${RESET}`);
  console.log(`${CYAN}  ${BOLD}${text}${RESET}`);
  console.log(`${CYAN}${line}${RESET}\n`);
}

function pad(str: string, len: number): string {
  return str.padEnd(len);
}

function rpad(str: string, len: number): string {
  return str.padStart(len);
}

// ─── Circuit Input Builder ───────────────────────────────────────────────────

function buildCircuitInput(poseidon: any, F: any, runIndex: number) {
  const hash1 = (a: bigint): bigint => F.toObject(poseidon([a]));
  const hash2 = (a: bigint, b: bigint): bigint =>
    F.toObject(poseidon([a, b]));
  const hash3 = (a: bigint, b: bigint, c: bigint): bigint =>
    F.toObject(poseidon([a, b, c]));

  let currentHash = 0n;
  for (let i = 0; i < 20; i++) currentHash = hash2(currentHash, currentHash);
  const emptyRoot = currentHash;

  const dummyKey = 1n;
  const dummyPubkey = hash1(dummyKey);
  const dummyCommitment = hash3(0n, dummyPubkey, 0n);
  const dummyNullifier = hash3(dummyCommitment, 0n, dummyKey);

  // Vary the inputs slightly per run for realism
  const recipientKey = BigInt(55555 + runIndex);
  const recipientPubkey = hash1(recipientKey);
  const blinding = BigInt(444 + runIndex);
  const depositAmount = BigInt(10_000_000 + runIndex * 1_000_000);

  const outputCommitment1 = hash3(depositAmount, recipientPubkey, blinding);
  const outputCommitment2 = hash3(0n, dummyPubkey, 0n);
  const extDataHash = hash3(0n, 0n, 0n);

  return {
    root: emptyRoot.toString(),
    publicAmount: depositAmount.toString(),
    extDataHash: extDataHash.toString(),
    protocolFee: "0",
    inputNullifiers: [dummyNullifier.toString()],
    outputCommitments: [
      outputCommitment1.toString(),
      outputCommitment2.toString(),
    ],
    inAmount: ["0"],
    inPrivateKey: [dummyKey.toString()],
    inBlinding: ["0"],
    inPathIndices: ["0"],
    inPathElements: [Array(20).fill("0")],
    outAmount: [depositAmount.toString(), "0"],
    outPubkey: [recipientPubkey.toString(), dummyPubkey.toString()],
    outBlinding: [blinding.toString(), "0"],
  };
}

// ─── Main ────────────────────────────────────────────────────────────────────

interface RunResult {
  run: number;
  proveTimeMs: number;
  serverProveMs: number;
  verifyTimeMs: number;
  serverVerifyMs: number;
  valid: boolean;
  publicSignals: number;
}

async function main() {
  banner("ZK PROOF BENCHMARK — 1x2 JoinSplit (Groth16)");

  // Health check
  console.log(`${DIM}  Server: ${SERVER_URL}${RESET}`);
  console.log(`${DIM}  Runs:   ${RUNS} sequential proof generations${RESET}`);
  console.log(`${DIM}  Mode:   Direct fetch (no MPP payment overhead)${RESET}`);
  console.log("");

  try {
    const healthRes = await fetch(`${SERVER_URL}/health`);
    if (!healthRes.ok) throw new Error(`HTTP ${healthRes.status}`);
    const health = (await healthRes.json()) as any;
    console.log(`${GREEN}  Server online${RESET} — ${health.wallet?.slice(0, 14)}...`);
  } catch {
    console.log(`${RED}  Server unreachable at ${SERVER_URL}${RESET}`);
    console.log(`${DIM}  Start the server: npm run dev${RESET}\n`);
    process.exit(1);
  }

  // Init Poseidon
  console.log(`${DIM}  Initializing Poseidon hasher...${RESET}`);
  const poseidon = await buildPoseidon();
  console.log(`${GREEN}  Poseidon ready${RESET}\n`);

  // Run benchmarks
  const results: RunResult[] = [];

  console.log(
    `${BOLD}  Run  | Prove (e2e) | Prove (server) | Verify (e2e) | Verify (svr) | Valid${RESET}`
  );
  console.log(`  ${"─".repeat(76)}`);

  for (let i = 0; i < RUNS; i++) {
    const input = buildCircuitInput(poseidon, poseidon.F, i);

    // ── Prove ──
    const proveStart = Date.now();
    const proveRes = await fetch(`${SERVER_URL}/prove/1x2`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    const proveElapsed = Date.now() - proveStart;

    if (proveRes.status === 402) {
      console.log(
        `\n${RED}  Got 402 — server has MPP enabled. Run with MPP_SECRET_KEY unset or use test mode.${RESET}`
      );
      console.log(
        `${DIM}  This benchmark requires direct access without payment gating.${RESET}\n`
      );
      process.exit(1);
    }

    const proveData = (await proveRes.json()) as any;

    if (!proveData.success) {
      console.log(`${RED}  Run ${i + 1}: Proof generation failed — ${proveData.error}${RESET}`);
      continue;
    }

    // ── Verify ──
    const verifyStart = Date.now();
    const verifyRes = await fetch(`${SERVER_URL}/verify/1x2`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        proof: proveData.proof,
        publicSignals: proveData.publicSignals,
      }),
    });
    const verifyElapsed = Date.now() - verifyStart;
    const verifyData = (await verifyRes.json()) as any;

    const result: RunResult = {
      run: i + 1,
      proveTimeMs: proveElapsed,
      serverProveMs: proveData.generationTimeMs,
      verifyTimeMs: verifyElapsed,
      serverVerifyMs: verifyData.verificationTimeMs ?? 0,
      valid: verifyData.valid,
      publicSignals: proveData.publicSignals?.length ?? 0,
    };
    results.push(result);

    const tag = i === 0 ? `${YELLOW}(cold)${RESET}` : `${GREEN}(warm)${RESET}`;
    const validStr = result.valid ? `${GREEN}yes${RESET}` : `${RED}NO${RESET}`;

    console.log(
      `  ${rpad(String(result.run), 4)} | ${rpad(result.proveTimeMs + "ms", 11)} | ${rpad(result.serverProveMs + "ms", 14)} | ${rpad(result.verifyTimeMs + "ms", 12)} | ${rpad(result.serverVerifyMs + "ms", 12)} | ${validStr}  ${tag}`
    );
  }

  // ── Statistics ──────────────────────────────────────────────────────────
  if (results.length === 0) {
    console.log(`\n${RED}  No successful runs. Cannot compute statistics.${RESET}\n`);
    process.exit(1);
  }

  const proveTimes = results.map((r) => r.proveTimeMs);
  const serverProveTimes = results.map((r) => r.serverProveMs);
  const verifyTimes = results.map((r) => r.verifyTimeMs);
  const serverVerifyTimes = results.map((r) => r.serverVerifyMs);

  const warmProveTimes = proveTimes.slice(1);
  const warmServerProveTimes = serverProveTimes.slice(1);

  const avg = (arr: number[]) =>
    arr.length > 0 ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length) : 0;
  const min = (arr: number[]) => (arr.length > 0 ? Math.min(...arr) : 0);
  const max = (arr: number[]) => (arr.length > 0 ? Math.max(...arr) : 0);

  banner("RESULTS");

  console.log(`  ${BOLD}Proof Generation (end-to-end)${RESET}`);
  console.log(`  ${"─".repeat(40)}`);
  console.log(`  First run (cold):     ${YELLOW}${BOLD}${proveTimes[0]}ms${RESET}`);
  if (warmProveTimes.length > 0) {
    console.log(`  Warm average:         ${GREEN}${BOLD}${avg(warmProveTimes)}ms${RESET}`);
    console.log(`  Warm min:             ${GREEN}${min(warmProveTimes)}ms${RESET}`);
    console.log(`  Warm max:             ${DIM}${max(warmProveTimes)}ms${RESET}`);
  }
  console.log(`  Overall average:      ${avg(proveTimes)}ms`);
  console.log(`  Overall min:          ${min(proveTimes)}ms`);
  console.log(`  Overall max:          ${max(proveTimes)}ms`);

  console.log("");
  console.log(`  ${BOLD}Proof Generation (server-side only)${RESET}`);
  console.log(`  ${"─".repeat(40)}`);
  console.log(`  First run (cold):     ${YELLOW}${BOLD}${serverProveTimes[0]}ms${RESET}`);
  if (warmServerProveTimes.length > 0) {
    console.log(`  Warm average:         ${GREEN}${BOLD}${avg(warmServerProveTimes)}ms${RESET}`);
    console.log(`  Warm min:             ${GREEN}${min(warmServerProveTimes)}ms${RESET}`);
    console.log(`  Warm max:             ${DIM}${max(warmServerProveTimes)}ms${RESET}`);
  }
  console.log(`  Overall average:      ${avg(serverProveTimes)}ms`);

  console.log("");
  console.log(`  ${BOLD}Verification${RESET}`);
  console.log(`  ${"─".repeat(40)}`);
  console.log(`  Avg round-trip:       ${avg(verifyTimes)}ms`);
  console.log(`  Avg server-side:      ${avg(serverVerifyTimes)}ms`);
  console.log(`  Network overhead:     ~${avg(verifyTimes) - avg(serverVerifyTimes)}ms`);

  console.log("");
  console.log(`  ${BOLD}Summary${RESET}`);
  console.log(`  ${"─".repeat(40)}`);
  console.log(`  Circuit:              1x2 JoinSplit (Groth16 / BN254)`);
  console.log(`  Constraints:          13,726`);
  console.log(`  Proofs generated:     ${results.length}`);
  console.log(`  All valid:            ${results.every((r) => r.valid) ? `${GREEN}yes${RESET}` : `${RED}NO${RESET}`}`);

  if (warmServerProveTimes.length > 0) {
    const throughput = (1000 / avg(warmServerProveTimes)).toFixed(2);
    console.log(`  Warm throughput:      ~${throughput} proofs/sec`);
  }

  const networkOverhead = avg(proveTimes) - avg(serverProveTimes);
  console.log(`  Avg network overhead: ~${networkOverhead}ms`);
  console.log("");
}

main().catch((e) => {
  console.error(`${RED}Fatal: ${e.message}${RESET}`);
  process.exit(1);
});
