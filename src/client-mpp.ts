/**
 * MPP Client — pays for ZK proofs via Tempo MPP protocol.
 *
 * Usage:
 *   TEMPO_KEY=0x... npx tsx src/client-mpp.ts [1x2|2x2]
 *
 * Get your key from: tempo wallet whoami --json
 */
// @ts-ignore
import { buildPoseidon } from "circomlibjs";
import { privateKeyToAccount } from "viem/accounts";
import { Mppx, tempo } from "mppx/client";

const SERVER_URL = process.env.SERVER_URL || "http://localhost:3402";
const CIRCUIT = (process.argv[2] || "1x2") as "1x2" | "2x2";

// Get key from env or tempo CLI
async function getTempoKey(): Promise<`0x${string}`> {
  if (process.env.TEMPO_KEY) {
    return process.env.TEMPO_KEY as `0x${string}`;
  }

  // Try to get from tempo wallet whoami
  const { execSync } = await import("child_process");
  try {
    const raw = execSync("tempo wallet whoami -j", { encoding: "utf8" });
    const data = JSON.parse(raw);
    if (data.key?.key) return data.key.key as `0x${string}`;
  } catch {}

  throw new Error("Set TEMPO_KEY env var or run 'tempo wallet login'");
}

function buildCircuitInput(poseidon: any, F: any) {
  const hash1 = (a: bigint): bigint => F.toObject(poseidon([a]));
  const hash2 = (a: bigint, b: bigint): bigint => F.toObject(poseidon([a, b]));
  const hash3 = (a: bigint, b: bigint, c: bigint): bigint => F.toObject(poseidon([a, b, c]));

  let currentHash = 0n;
  for (let i = 0; i < 20; i++) currentHash = hash2(currentHash, currentHash);
  const emptyRoot = currentHash;

  const dummyKey = 1n;
  const dummyPubkey = hash1(dummyKey);
  const dummyCommitment = hash3(0n, dummyPubkey, 0n);
  const dummyNullifier = hash3(dummyCommitment, 0n, dummyKey);

  const recipientKey = 55555n;
  const recipientPubkey = hash1(recipientKey);
  const blinding = 444n;
  const depositAmount = 10_000_000n;

  const outputCommitment1 = hash3(depositAmount, recipientPubkey, blinding);
  const outputCommitment2 = hash3(0n, dummyPubkey, 0n);
  const extDataHash = hash3(0n, 0n, 0n);

  if (CIRCUIT === "1x2") {
    return {
      root: emptyRoot.toString(),
      publicAmount: depositAmount.toString(),
      extDataHash: extDataHash.toString(),
      protocolFee: "0",
      inputNullifiers: [dummyNullifier.toString()],
      outputCommitments: [outputCommitment1.toString(), outputCommitment2.toString()],
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
    outputCommitments: [outputCommitment1.toString(), outputCommitment2.toString()],
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

async function main() {
  console.log(`\n=== ZK Proof MPP Client ===`);
  console.log(`Server: ${SERVER_URL}`);
  console.log(`Circuit: ${CIRCUIT}\n`);

  // Step 1: Get tempo key and create account
  const key = await getTempoKey();
  const account = privateKeyToAccount(key);
  console.log(`Payer wallet: ${account.address}`);

  // Step 2: Create mppx client — auto-handles 402 → pay → retry
  const mppx = Mppx.create({
    methods: [
      tempo({ account, autoSwap: true }),
    ],
    polyfill: false,
  });

  // Step 3: Check server health
  const healthRes = await mppx.fetch(`${SERVER_URL}/health`);
  const health = await healthRes.json() as any;
  console.log(`Server: ${health.status}, recipient: ${health.wallet}\n`);

  // Step 4: Build circuit input
  console.log("Building Poseidon hasher & circuit input...");
  const poseidon = await buildPoseidon();
  const circuitInput = buildCircuitInput(poseidon, poseidon.F);

  // Step 5: Request proof — mppx.fetch handles 402 automatically
  console.log(`\nRequesting ${CIRCUIT} proof (mppx handles payment)...`);
  const startTime = Date.now();

  const res = await mppx.fetch(`${SERVER_URL}/prove/${CIRCUIT}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(circuitInput),
  });

  const elapsed = Date.now() - startTime;

  if (!res.ok) {
    console.error(`Request failed: ${res.status}`);
    console.error(await res.text());
    return;
  }

  const result = await res.json() as any;

  console.log("\n=== Proof Generated! ===");
  console.log(`  Circuit: ${result.circuit}`);
  console.log(`  Proof generation: ${result.generationTimeMs}ms`);
  console.log(`  Public signals: ${result.publicSignals?.length}`);
  console.log(`  Total (incl. payment): ${elapsed}ms`);

  // Step 6: Verify (free)
  console.log("\nVerifying proof...");
  const verifyRes = await fetch(`${SERVER_URL}/verify/${CIRCUIT}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ proof: result.proof, publicSignals: result.publicSignals }),
  });
  const verifyData = await verifyRes.json() as any;
  console.log(`  Valid: ${verifyData.valid}`);
  console.log(`  Verification time: ${verifyData.verificationTimeMs}ms`);

  console.log("\n=== Complete ===");
  console.log(`  Payment: MPP via Tempo (pathUSD)`);
  console.log(`  Proof: Groth16 ${CIRCUIT} JoinSplit`);
  console.log(`  Verified: ${verifyData.valid}`);
}

main().catch(console.error);
