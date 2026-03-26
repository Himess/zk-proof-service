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
const OWNER_WALLET = "0x4013AE1C1473f6CB37AA44eedf58BDF7Fa4068F7" as const;

console.log(`Server wallet: ${account.address}`);
console.log(`Payment recipient: ${OWNER_WALLET}`);

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

  // Landing page
  app.get("/", (c) => {
    c.header("Content-Type", "text/html");
    return c.body(`<!DOCTYPE html>
<html><head><title>ZKProver</title>
<style>body{font-family:system-ui;max-width:700px;margin:60px auto;padding:0 20px;background:#0a0a0a;color:#e0e0e0}
h1{color:#fff}a{color:#58a6ff}code{background:#1a1a2e;padding:2px 6px;border-radius:4px;font-size:14px}
pre{background:#1a1a2e;padding:16px;border-radius:8px;overflow-x:auto;font-size:13px}
.badge{display:inline-block;background:#238636;color:#fff;padding:4px 10px;border-radius:12px;font-size:13px;margin:4px}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #333;padding:8px;text-align:left}th{background:#1a1a2e}</style></head>
<body>
<h1>ZKProver</h1>
<p><span class="badge">LIVE</span> <span class="badge">Groth16</span> <span class="badge">MPP</span></p>
<p>Pay-per-proof ZK proving via <a href="https://mpp.dev">Tempo MPP</a>. Real compute, not a proxy.</p>

<h2>Try it</h2>
<pre>tempo request -t https://himess-zk-proof-service.hf.space/circuits

tempo request -v -X POST \\
  -H "Content-Type: application/json" \\
  -d @input.json \\
  https://himess-zk-proof-service.hf.space/prove/1x2</pre>

<h2>Endpoints</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>GET</td><td><a href="/health">/health</a></td><td>Free</td><td>Health check</td></tr>
<tr><td>GET</td><td><a href="/circuits">/circuits</a></td><td>Free</td><td>List circuits & pricing</td></tr>
<tr><td>GET</td><td><a href="/llms.txt">/llms.txt</a></td><td>Free</td><td>Agent discovery</td></tr>
<tr><td>POST</td><td>/prove/1x2</td><td>$0.01</td><td>Generate 1x2 proof</td></tr>
<tr><td>POST</td><td>/prove/2x2</td><td>$0.02</td><td>Generate 2x2 proof</td></tr>
<tr><td>POST</td><td>/verify/:circuit</td><td>Free</td><td>Verify a proof</td></tr>
</table>

<h2>Performance</h2>
<p>~2-5s proof generation · ~50ms verification · 13,726 constraints · BN254 curve</p>

<h2>Links</h2>
<p><a href="https://github.com/Himess/zk-proof-service">GitHub</a> · <a href="/llms.txt">llms.txt</a> · <a href="/circuits">API</a></p>
</body></html>`);
  });

  // Health check (free)
  app.get("/health", (c) =>
    c.json({
      status: "ok",
      wallet: OWNER_WALLET,
      chain: "tempo-moderato",
      chainId: 42431,
    })
  );

  // OpenAPI Discovery (required for MPPscan)
  app.get("/openapi.json", (c) =>
    c.json({
      openapi: "3.1.0",
      info: {
        title: "ZKProver",
        version: "1.0.0",
        description: "Pay-per-proof Groth16 ZK proving service. Real SNARK compute via MPP — not a proxy.",
        "x-guidance": "Use ZKProver to generate and verify Groth16 zero-knowledge proofs for JoinSplit circuits. POST circuit inputs to /prove/1x2 ($0.01) or /prove/2x2 ($0.02). Payment is automatic via MPP 402 flow. Verification at /verify/:circuit is free. Check /circuits for available circuits and pricing.",
      },
      "x-service-info": {
        categories: ["compute", "developer-tools"],
        docs: {
          homepage: "https://github.com/Himess/zk-proof-service",
          llms: "https://himess-zk-proof-service.hf.space/llms.txt",
        },
      },
      servers: [{ url: "https://himess-zk-proof-service.hf.space" }],
      paths: {
        "/health": {
          get: {
            summary: "Health check",
            description: "Returns service status, wallet address, and chain info. Free, no payment required.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0",
              protocols: ["mpp"],
            },
            parameters: [
              {
                name: "format",
                in: "query",
                required: false,
                schema: { type: "string", enum: ["json"], default: "json" },
              },
            ],
            responses: {
              "200": {
                description: "Service is healthy",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        status: { type: "string", example: "ok" },
                        wallet: { type: "string" },
                        chain: { type: "string" },
                        chainId: { type: "integer" },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        "/circuits": {
          get: {
            summary: "List available circuits and pricing",
            description: "Returns all supported ZK circuits with constraint counts and per-proof pricing. Free, no payment required.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0",
              protocols: ["mpp"],
            },
            parameters: [
              {
                name: "format",
                in: "query",
                required: false,
                schema: { type: "string", enum: ["json"], default: "json" },
              },
            ],
            responses: {
              "200": {
                description: "Circuit list with pricing",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        circuits: {
                          type: "array",
                          items: {
                            type: "object",
                            properties: {
                              id: { type: "string" },
                              description: { type: "string" },
                              constraintCount: { type: "integer" },
                              publicSignals: { type: "integer" },
                            },
                          },
                        },
                        pricing: { type: "object" },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        "/prove/1x2": {
          post: {
            summary: "Generate Groth16 proof (1-input, 2-output JoinSplit)",
            description: "Generates a Groth16 ZK proof for a 1x2 JoinSplit circuit. Requires MPP payment of $0.01 USDC.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "10000",
              protocols: ["mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    description: "Circuit-specific inputs (nullifiers, commitments, paths, etc.)",
                    additionalProperties: true,
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Proof generated successfully",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        circuit: { type: "string" },
                        proof: { type: "object", description: "Groth16 proof (pi_a, pi_b, pi_c)" },
                        publicSignals: { type: "array", items: { type: "string" } },
                        contractProof: { type: "array", items: { type: "string" }, description: "uint256[8] for Solidity verifier" },
                        generationTimeMs: { type: "number" },
                      },
                      required: ["success", "circuit", "proof", "publicSignals", "contractProof"],
                    },
                  },
                },
              },
              "402": { description: "Payment Required — MPP payment needed" },
            },
          },
        },
        "/prove/2x2": {
          post: {
            summary: "Generate Groth16 proof (2-input, 2-output JoinSplit)",
            description: "Generates a Groth16 ZK proof for a 2x2 JoinSplit circuit. Requires MPP payment of $0.02 USDC.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "20000",
              protocols: ["mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    description: "Circuit-specific inputs (nullifiers, commitments, paths, etc.)",
                    additionalProperties: true,
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Proof generated successfully",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        circuit: { type: "string" },
                        proof: { type: "object", description: "Groth16 proof (pi_a, pi_b, pi_c)" },
                        publicSignals: { type: "array", items: { type: "string" } },
                        contractProof: { type: "array", items: { type: "string" }, description: "uint256[8] for Solidity verifier" },
                        generationTimeMs: { type: "number" },
                      },
                      required: ["success", "circuit", "proof", "publicSignals", "contractProof"],
                    },
                  },
                },
              },
              "402": { description: "Payment Required — MPP payment needed" },
            },
          },
        },
        "/verify/{circuit}": {
          post: {
            summary: "Verify a Groth16 proof",
            description: "Verifies a previously generated proof. Free, no payment required.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0",
              protocols: ["mpp"],
            },
            parameters: [
              {
                name: "circuit",
                in: "path",
                required: true,
                schema: { type: "string", enum: ["1x2", "2x2"] },
              },
            ],
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      proof: { type: "object", description: "Groth16 proof object" },
                      publicSignals: { type: "array", items: { type: "string" } },
                    },
                    required: ["proof", "publicSignals"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Verification result",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        valid: { type: "boolean" },
                        verificationTimeMs: { type: "number" },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    })
  );

  // Well-known x402 discovery (fallback for agents that cannot read OpenAPI)
  app.get("/.well-known/x402", (c) =>
    c.json({
      version: 1,
      resources: [
        "POST /prove/1x2",
        "POST /prove/2x2",
      ],
      description: "ZKProver: pay-per-proof Groth16 ZK proving service via MPP. POST circuit inputs to /prove/1x2 ($0.01) or /prove/2x2 ($0.02). Verification at /verify/:circuit is free.",
    })
  );

  // LLMs.txt (free)
  app.get("/llms.txt", (c) => {
    c.header("Content-Type", "text/plain");
    return c.body(`# ZKProver
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
          recipient: OWNER_WALLET,
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
    console.log(`\nZKProver running on http://localhost:${PORT}`);
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
