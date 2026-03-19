/**
 * AI Agent Consumer Demo — autonomous agent consuming paid ZK compute services.
 *
 * Demonstrates the vision: agents discover APIs, reason about tasks,
 * pay for compute via MPP, and verify results — all autonomously.
 *
 * Usage: npx tsx src/agent-consumer.ts
 *
 * Requires:
 *   - Server running on localhost:3402 (npm run dev)
 *   - `tempo` CLI logged in (tempo wallet login)
 */
// @ts-ignore
import { buildPoseidon } from "circomlibjs";
import { execSync } from "child_process";

const SERVER_URL = "http://localhost:3402";

// ─── Pretty Logging ──────────────────────────────────────────────────────────

const CYAN = "\x1b[36m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";
const MAGENTA = "\x1b[35m";

function banner(text: string) {
  const line = "═".repeat(60);
  console.log(`\n${CYAN}${line}${RESET}`);
  console.log(`${CYAN}  ${BOLD}${text}${RESET}`);
  console.log(`${CYAN}${line}${RESET}\n`);
}

function step(n: number, text: string) {
  console.log(`${YELLOW}[Step ${n}]${RESET} ${BOLD}${text}${RESET}`);
}

function agent(text: string) {
  console.log(`${MAGENTA}  > Agent: ${text}${RESET}`);
}

function info(text: string) {
  console.log(`${DIM}    ${text}${RESET}`);
}

function success(text: string) {
  console.log(`${GREEN}    [OK] ${text}${RESET}`);
}

function fail(text: string) {
  console.log(`${RED}    [FAIL] ${text}${RESET}`);
}

function money(text: string) {
  console.log(`${GREEN}${BOLD}    $ ${text}${RESET}`);
}

// ─── Circuit Input Builder (from test-prove.ts) ──────────────────────────────

function buildCircuitInput(
  poseidon: any,
  F: any,
  circuit: "1x2" | "2x2",
  depositAmount: bigint
) {
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

  const recipientKey = BigInt(Math.floor(Math.random() * 100000) + 1000);
  const recipientPubkey = hash1(recipientKey);
  const blinding = BigInt(Math.floor(Math.random() * 10000));

  const outputCommitment1 = hash3(depositAmount, recipientPubkey, blinding);
  const outputCommitment2 = hash3(0n, dummyPubkey, 0n);
  const extDataHash = hash3(0n, 0n, 0n);

  if (circuit === "1x2") {
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

  // 2x2
  const dummyKey2 = 2n;
  const dummyPubkey2 = hash1(dummyKey2);
  const dummyCommitment2 = hash3(0n, dummyPubkey2, 0n);
  const dummyNullifier2 = hash3(dummyCommitment2, 0n, dummyKey2);

  return {
    root: emptyRoot.toString(),
    publicAmount: depositAmount.toString(),
    extDataHash: extDataHash.toString(),
    protocolFee: "0",
    inputNullifiers: [dummyNullifier.toString(), dummyNullifier2.toString()],
    outputCommitments: [
      outputCommitment1.toString(),
      outputCommitment2.toString(),
    ],
    inAmount: ["0", "0"],
    inPrivateKey: [dummyKey.toString(), dummyKey2.toString()],
    inBlinding: ["0", "0"],
    inPathIndices: ["0", "0"],
    inPathElements: [Array(20).fill("0"), Array(20).fill("0")],
    outAmount: [depositAmount.toString(), "0"],
    outPubkey: [recipientPubkey.toString(), dummyPubkey2.toString()],
    outBlinding: [blinding.toString(), "0"],
  };
}

// ─── Simulated Agent Tasks ───────────────────────────────────────────────────

interface AgentTask {
  name: string;
  description: string;
  circuit: "1x2" | "2x2";
  amount: bigint;
  reasoning: string;
}

const TASKS: AgentTask[] = [
  {
    name: "Private Deposit",
    description: "Shield 5 USDC into the privacy pool",
    circuit: "1x2",
    amount: 5_000_000n,
    reasoning:
      "Single input deposit — 1x2 circuit is sufficient. Cost: $0.01. Worth it for privacy.",
  },
  {
    name: "Private Transfer",
    description: "Transfer 25 USDC privately between two parties",
    circuit: "1x2",
    amount: 25_000_000n,
    reasoning:
      "Standard private transfer, one input note. 1x2 handles this. Cost-effective at $0.01.",
  },
  {
    name: "Large Withdrawal",
    description: "Withdraw 100 USDC from the privacy pool",
    circuit: "1x2",
    amount: 100_000_000n,
    reasoning:
      "Large withdrawal from shielded pool. 1x2 circuit at $0.01 — trivial cost for 100 USDC privacy.",
  },
];

// ─── Main Agent Loop ─────────────────────────────────────────────────────────

async function main() {
  banner("ZK PROOF AGENT — Autonomous Compute Consumer");

  console.log(
    `${DIM}  Vision: AI agents autonomously discover, pay for, and consume${RESET}`
  );
  console.log(
    `${DIM}  ZK compute services via micropayments. No API keys. No accounts.${RESET}`
  );
  console.log(
    `${DIM}  Just a wallet and a task.${RESET}\n`
  );

  let totalSpent = 0;
  let proofsGenerated = 0;
  let proofsVerified = 0;

  // ── Step 1: Health Check ───────────────────────────────────────────────
  step(1, "Checking service availability");
  try {
    const healthRes = await fetch(`${SERVER_URL}/health`);
    const health = (await healthRes.json()) as any;
    success(`Service online — wallet ${health.wallet.slice(0, 10)}...`);
    info(`Chain: ${health.chain} (ID: ${health.chainId})`);
  } catch (e) {
    fail(`Service unreachable at ${SERVER_URL}`);
    console.log(`\n${RED}  Start the server first: npm run dev${RESET}\n`);
    process.exit(1);
  }

  // ── Step 2: Discover Circuits ──────────────────────────────────────────
  step(2, "Discovering available circuits");
  const circuitsRes = await fetch(`${SERVER_URL}/circuits`);
  const circuitsData = (await circuitsRes.json()) as any;

  for (const c of circuitsData.circuits) {
    info(`${c.id}: ${c.description}`);
    info(`   Constraints: ${c.constraintCount.toLocaleString()} | Signals: ${c.publicSignals}`);
  }

  agent("I see two circuits available. Let me check pricing...");

  for (const [id, pricing] of Object.entries(circuitsData.pricing) as any) {
    money(`${id}: ${pricing.description} per proof`);
  }

  agent("Affordable. I have tasks that need ZK proofs. Let me proceed.");

  // ── Step 3: Initialize Poseidon ────────────────────────────────────────
  step(3, "Initializing cryptographic primitives");
  const poseidon = await buildPoseidon();
  success("Poseidon hasher ready");

  // ── Step 4-N: Execute Tasks ────────────────────────────────────────────
  for (let i = 0; i < TASKS.length; i++) {
    const task = TASKS[i];
    const stepNum = 4 + i * 2;

    console.log("");
    console.log(
      `${CYAN}${"─".repeat(60)}${RESET}`
    );
    console.log(
      `${CYAN}  Task ${i + 1}/${TASKS.length}: ${BOLD}${task.name}${RESET}`
    );
    console.log(
      `${CYAN}${"─".repeat(60)}${RESET}`
    );

    // Agent reasoning
    step(stepNum, `Agent reasoning about "${task.description}"`);
    agent(task.reasoning);
    info(`Circuit: ${task.circuit} | Amount: ${(Number(task.amount) / 1e6).toFixed(2)} USDC`);

    // Build circuit input
    const circuitInput = buildCircuitInput(
      poseidon,
      poseidon.F,
      task.circuit,
      task.amount
    );

    // Pay and generate proof via tempo CLI
    step(stepNum + 1, `Paying & generating ${task.circuit} proof via MPP`);

    const price = task.circuit === "1x2" ? 0.01 : 0.02;

    const startTime = Date.now();
    let proofResult: any;

    try {
      const inputJson = JSON.stringify(circuitInput);
      // Write input to temp file to avoid shell escaping issues with large JSON
      const fs = await import("fs");
      const tmpFile = `/tmp/zk-agent-input-${i}.json`;
      fs.writeFileSync(tmpFile, inputJson);
      // Use tempo request CLI which handles the MPP payment flow
      const cmd = `tempo request -X POST "${SERVER_URL}/prove/${task.circuit}" -H "Content-Type: application/json" -d @${tmpFile}`;

      info("Sending paid request via `tempo request`...");
      const raw = execSync(cmd, {
        encoding: "utf8",
        timeout: 120_000,
        maxBuffer: 10 * 1024 * 1024,
      });

      // tempo request outputs the response body
      proofResult = JSON.parse(raw);
      const elapsed = Date.now() - startTime;

      if (proofResult.success) {
        proofsGenerated++;
        totalSpent += price;

        success(`Proof generated in ${proofResult.generationTimeMs}ms`);
        info(`Total request time (incl. payment): ${elapsed}ms`);
        info(`Public signals: ${proofResult.publicSignals.length}`);
        info(
          `Proof pi_a[0]: ${proofResult.proof.pi_a[0].slice(0, 30)}...`
        );
        money(`Spent: $${price.toFixed(2)} | Running total: $${totalSpent.toFixed(2)}`);

        // Verify the proof (free) — small delay to let server finish any cleanup
        await new Promise((r) => setTimeout(r, 500));
        console.log("");
        info("Verifying proof (free endpoint)...");
        const verifyStart = Date.now();
        const verifyRes = await fetch(
          `${SERVER_URL}/verify/${task.circuit}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              proof: proofResult.proof,
              publicSignals: proofResult.publicSignals,
            }),
          }
        );
        const verifyData = (await verifyRes.json()) as any;
        const verifyElapsed = Date.now() - verifyStart;

        if (verifyData.valid) {
          proofsVerified++;
          success(`Proof VALID (${verifyData.verificationTimeMs}ms server-side, ${verifyElapsed}ms round-trip)`);
        } else {
          fail("Proof verification returned invalid!");
        }
      } else {
        fail(`Proof generation failed: ${proofResult.error}`);
      }
    } catch (e: any) {
      const elapsed = Date.now() - startTime;
      const errMsg = e.stderr?.split("\n")[0] || e.message?.split("\n")[0] || "Unknown error";
      fail(`Request failed after ${elapsed}ms: ${errMsg}`);
    }
  }

  // ── Summary ────────────────────────────────────────────────────────────
  banner("MISSION COMPLETE");

  console.log(`  ${BOLD}Agent Performance Summary${RESET}`);
  console.log(`  ${"─".repeat(40)}`);
  console.log(
    `  Tasks attempted:    ${BOLD}${TASKS.length}${RESET}`
  );
  console.log(
    `  Proofs generated:   ${BOLD}${proofsGenerated}${RESET}`
  );
  console.log(
    `  Proofs verified:    ${BOLD}${proofsVerified}${RESET}`
  );
  console.log(
    `  Total spent:        ${GREEN}${BOLD}$${totalSpent.toFixed(2)}${RESET}`
  );
  console.log(
    `  Avg cost/proof:     ${GREEN}$${proofsGenerated > 0 ? (totalSpent / proofsGenerated).toFixed(3) : "N/A"}${RESET}`
  );
  console.log(`  ${"─".repeat(40)}`);
  console.log("");
  console.log(
    `${DIM}  This is the future: autonomous agents consuming paid compute${RESET}`
  );
  console.log(
    `${DIM}  services with micropayments. No API keys. No rate limits.${RESET}`
  );
  console.log(
    `${DIM}  Just cryptographic proofs and economic alignment.${RESET}`
  );
  console.log("");
}

main().catch((e) => {
  console.error(`${RED}Fatal error: ${e.message}${RESET}`);
  process.exit(1);
});
