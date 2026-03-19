import { Hono } from "hono";
import { cors } from "hono/cors";
import { serve } from "@hono/node-server";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createClient, http } from "viem";
import {
  generateProof,
  verifyProof,
  listCircuits,
  formatProofForContract,
} from "./prover.js";
import type { CircuitType } from "./prover.js";

// --- Configuration ---
const PORT = Number(process.env.PORT) || 3402;
const PRIVATE_KEY = (process.env.SERVER_PRIVATE_KEY ||
  generatePrivateKey()) as `0x${string}`;
const account = privateKeyToAccount(PRIVATE_KEY);
const PATHUSD = "0x20c000000000000000000000b9537d11c60e8b50" as const;

console.log(`Server wallet: ${account.address}`);
console.log(`Private key: ${PRIVATE_KEY}`);

// --- Fund server on testnet ---
async function fundServer() {
  try {
    const client = createClient({
      transport: http("https://rpc.moderato.tempo.xyz"),
    });

    console.log("Requesting testnet funds...");
    const result = await client.request({
      // @ts-ignore
      method: "tempo_fundAddress",
      params: [account.address],
    });
    console.log("Funded:", result);
  } catch (e) {
    console.warn("Faucet failed (may already be funded):", (e as Error).message);
  }
}

// --- Prove handler (shared logic) ---
async function handleProve(c: any) {
  const url = new URL(c.req.url);
  const circuit = url.pathname.split("/").pop() as CircuitType;

  if (circuit !== "1x2" && circuit !== "2x2") {
    return c.json({ error: "Invalid circuit. Use '1x2' or '2x2'" }, 400);
  }

  let circuitInput: Record<string, unknown>;
  try {
    circuitInput = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  if (!circuitInput || typeof circuitInput !== "object") {
    return c.json({ error: "Body must be a JSON object with circuit inputs" }, 400);
  }

  try {
    console.log(`Generating ${circuit} proof...`);
    const result = await generateProof(circuit, circuitInput);
    const contractProof = formatProofForContract(result.proof);
    console.log(`Proof generated in ${result.generationTimeMs}ms`);

    return c.json({
      success: true,
      circuit,
      proof: result.proof,
      publicSignals: result.publicSignals,
      contractProof,
      generationTimeMs: result.generationTimeMs,
    });
  } catch (e) {
    console.error("Proof generation failed:", e);
    return c.json({ error: "Proof generation failed", details: (e as Error).message }, 500);
  }
}

// --- App ---
async function main() {
  await fundServer();

  const app = new Hono();
  app.use("*", cors());

  // Health check (free)
  app.get("/health", (c) =>
    c.json({
      status: "ok",
      wallet: account.address,
      chain: "tempo-moderato",
      chainId: 42431,
    })
  );

  // LLMs.txt (free)
  app.get("/llms.txt", (c) => {
    c.header("Content-Type", "text/plain");
    return c.body(`# ZK Proof Service
> Pay-per-proof Groth16 ZK proving via MPP. Real compute, not a proxy.

## Live
https://himess-zk-proof-service.hf.space

## Endpoints
- GET /health — Health check (free)
- GET /circuits — List circuits and pricing (free)
- POST /prove/1x2 — Generate 1x2 JoinSplit proof ($0.01 MPP)
- POST /prove/2x2 — Generate 2x2 JoinSplit proof ($0.02 MPP)
- POST /verify/:circuit — Verify a proof (free)

## Pricing
- 1x2 circuit: $0.01 per proof
- 2x2 circuit: $0.02 per proof
- Payment: USDC via Tempo MPP (automatic 402 flow)

## What This Does
Generates Groth16 zero-knowledge proofs for JoinSplit circuits (private UTXO transactions).
Returns proof, public signals, and uint256[8] contract-ready format for on-chain Solidity verifiers.
Proof generation: ~3-5s warm. Verification: ~50ms.

## Source
https://github.com/Himess/zk-proof-service`);
  });

  // List circuits (free)
  app.get("/circuits", (c) =>
    c.json({
      circuits: listCircuits(),
      pricing: {
        "1x2": { amount: "0.01", currency: "USDC", description: "$0.01" },
        "2x2": { amount: "0.02", currency: "USDC", description: "$0.02" },
      },
    })
  );

  // Setup MPP-gated prove routes
  try {
    if (process.env.NO_MPP === "1") throw new Error("MPP disabled via NO_MPP=1");
    const { Mppx, tempo } = await import("mppx/hono");
    const mppx = Mppx.create({
      methods: [
        tempo({
          currency: PATHUSD,
          recipient: account.address,
          feePayer: true,
        }),
      ],
      secretKey: process.env.MPP_SECRET_KEY || "dev-secret-key-change-in-production",
    });

    app.post("/prove/1x2", mppx.charge({ amount: "0.01", description: "ZK proof (1x2)" }), handleProve);
    app.post("/prove/2x2", mppx.charge({ amount: "0.02", description: "ZK proof (2x2)" }), handleProve);
    console.log("MPP payment gating enabled");
  } catch (e) {
    console.warn("mppx not available, running free:", (e as Error).message);
    app.post("/prove/1x2", handleProve);
    app.post("/prove/2x2", handleProve);
  }

  // Verify proof (free)
  app.post("/verify/:circuit", async (c) => {
    const circuit = c.req.param("circuit") as CircuitType;

    if (circuit !== "1x2" && circuit !== "2x2") {
      return c.json({ error: "Invalid circuit. Use '1x2' or '2x2'" }, 400);
    }

    let body: { proof: unknown; publicSignals: string[] };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }

    if (!body.proof || !body.publicSignals) {
      return c.json({ error: "Body must contain 'proof' and 'publicSignals'" }, 400);
    }

    try {
      const result = await verifyProof(circuit, body.proof, body.publicSignals);
      return c.json({ success: true, valid: result.valid, verificationTimeMs: result.verificationTimeMs });
    } catch (e) {
      return c.json({ error: "Verification failed", details: (e as Error).message }, 500);
    }
  });

  // Start
  serve({ fetch: app.fetch, port: PORT }, () => {
    console.log(`\nZK Proof Service running on http://localhost:${PORT}`);
    console.log(`\nEndpoints:`);
    console.log(`  GET  /health        — Health check (free)`);
    console.log(`  GET  /circuits      — List circuits (free)`);
    console.log(`  POST /prove/1x2     — Generate 1x2 proof ($0.01 MPP)`);
    console.log(`  POST /prove/2x2     — Generate 2x2 proof ($0.02 MPP)`);
    console.log(`  POST /verify/1x2    — Verify 1x2 proof (free)`);
    console.log(`  POST /verify/2x2    — Verify 2x2 proof (free)`);
  });
}

main().catch(console.error);
