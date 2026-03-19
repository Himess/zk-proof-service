/**
 * Test script: generates a valid 1x2 circuit input and calls the proof API.
 * Usage: npx tsx src/test-prove.ts
 */
// @ts-ignore
import { buildPoseidon } from "circomlibjs";

async function main() {
  console.log("Building Poseidon hasher...");
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const hash1 = (a: bigint): bigint => F.toObject(poseidon([a]));
  const hash2 = (a: bigint, b: bigint): bigint =>
    F.toObject(poseidon([a, b]));
  const hash3 = (a: bigint, b: bigint, c: bigint): bigint =>
    F.toObject(poseidon([a, b, c]));

  // Compute empty Merkle tree root (depth 20)
  let currentHash = 0n;
  for (let i = 0; i < 20; i++) {
    currentHash = hash2(currentHash, currentHash);
  }
  const emptyRoot = currentHash;

  // Dummy input UTXO (amount=0)
  const dummyKey = 1n;
  const dummyPubkey = hash1(dummyKey);
  const dummyCommitment = hash3(0n, dummyPubkey, 0n);
  const dummyNullifier = hash3(dummyCommitment, 0n, dummyKey);

  // Output UTXOs: deposit 10 USDC (10_000_000 base units)
  const recipientKey = 55555n;
  const recipientPubkey = hash1(recipientKey);
  const blinding = 444n;
  const depositAmount = 10_000_000n;

  const outputCommitment1 = hash3(depositAmount, recipientPubkey, blinding);
  const outputCommitment2 = hash3(0n, dummyPubkey, 0n); // zero-change

  const extDataHash = hash3(0n, 0n, 0n);

  const circuitInput = {
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

  console.log("\nCircuit input prepared. Calling proof API...\n");

  // Call the local server
  const start = Date.now();
  const res = await fetch("http://localhost:3402/prove/1x2", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(circuitInput),
  });

  const elapsed = Date.now() - start;

  if (res.status === 402) {
    console.log("Got 402 Payment Required (MPP gate working!)");
    console.log("WWW-Authenticate:", res.headers.get("www-authenticate")?.slice(0, 200));
    console.log("\nTo pay, use mppx client with a funded Tempo testnet wallet.");
    return;
  }

  const data = await res.json();

  if (data.success) {
    console.log("Proof generated successfully!");
    console.log(`  Circuit: ${data.circuit}`);
    console.log(`  Generation time: ${data.generationTimeMs}ms`);
    console.log(`  Public signals: ${data.publicSignals.length}`);
    console.log(`  Contract proof (uint256[8]):`, data.contractProof?.map((p: string) => p.slice(0, 20) + "..."));

    // Verify the proof
    console.log("\nVerifying proof...");
    const verifyRes = await fetch("http://localhost:3402/verify/1x2", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        proof: data.proof,
        publicSignals: data.publicSignals,
      }),
    });
    const verifyData = await verifyRes.json();
    console.log(`  Valid: ${verifyData.valid}`);
    console.log(`  Verification time: ${verifyData.verificationTimeMs}ms`);
  } else {
    console.log("Proof generation failed:", data.error, data.details);
  }

  console.log(`\nTotal request time: ${elapsed}ms`);
}

main().catch(console.error);
