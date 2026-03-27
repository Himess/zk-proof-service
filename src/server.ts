import { Hono } from "hono";
import { cors } from "hono/cors";
import { serve } from "@hono/node-server";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createClient, http } from "viem";
import {
  generateProof,
  verifyProof,
  listCircuits,
  formatProofForContract,
} from "./prover.js";
import type { CircuitType } from "./prover.js";
import type { PoseidonHash } from "./crypto.js";

// --- x402 v2 schema helper ---
// MPPscan validates input schemas from the 402 response's PAYMENT-REQUIRED header
// (x402 v2 format with extensions.bazaar.schema), NOT from the OpenAPI spec.
// This middleware intercepts mppx 402 responses and adds the required header.
function withX402Schema(
  schema: { input: Record<string, unknown>; output?: Record<string, unknown> },
  description: string,
  amount: string,
) {
  return async (c: any, next: () => Promise<void>) => {
    await next();
    // Only augment 402 Payment Required responses
    if (!c.res || c.res.status !== 402) return;

    // Build x402 v2 PAYMENT-REQUIRED payload with bazaar schema extension
    const x402Payload = {
      x402Version: 2,
      resource: {
        url: c.req.url,
        method: "POST",
        description,
        mimeType: "application/json",
      },
      accepts: [{
        scheme: "exact",
        network: "eip155:42431",
        amount,
        maxTimeoutSeconds: 300,
        asset: PATHUSD,
        payTo: OWNER_WALLET,
      }],
      extensions: {
        bazaar: {
          info: {
            input: { type: "http", bodyType: "json", body: {} },
          },
          schema: {
            $schema: "https://json-schema.org/draft/2020-12/schema",
            type: "object",
            properties: {
              input: {
                type: "object",
                properties: {
                  type: { type: "string", const: "http" },
                  bodyType: { type: "string", enum: ["json"] },
                  body: schema.input,
                },
                required: ["type", "bodyType", "body"],
                additionalProperties: false,
              },
              ...(schema.output
                ? {
                    output: {
                      type: "object",
                      properties: {
                        example: schema.output,
                      },
                    },
                  }
                : {}),
            },
            required: ["input"],
          },
        },
      },
    };

    const encoded = Buffer.from(JSON.stringify(x402Payload)).toString("base64");

    // Clone response with PAYMENT-REQUIRED header added
    const original = c.res;
    const body = await original.clone().arrayBuffer();
    const newHeaders = new Headers(original.headers);
    newHeaders.set("PAYMENT-REQUIRED", encoded);
    c.res = new Response(body, {
      status: 402,
      headers: newHeaders,
    });
  };
}

// --- Circuit input/output schemas for x402 bazaar discovery ---
const CIRCUIT_INPUT_SCHEMA_1x2 = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    root: { type: "string", minLength: 1, description: "Merkle tree root" },
    publicAmount: { type: "string", minLength: 1, description: "Public amount for deposit/withdrawal" },
    extDataHash: { type: "string", minLength: 1, description: "External data hash" },
    protocolFee: { type: "string", description: "Protocol fee" },
    inputNullifiers: { type: "array", items: { type: "string" } },
    outputCommitments: { type: "array", items: { type: "string" } },
    inAmount: { type: "array", items: { type: "string" } },
    inPrivateKey: { type: "array", items: { type: "string" } },
    inBlinding: { type: "array", items: { type: "string" } },
    inPathIndices: { type: "array", items: { type: "string" } },
    inPathElements: { type: "array", items: { type: "array", items: { type: "string" } } },
    outAmount: { type: "array", items: { type: "string" } },
    outPubkey: { type: "array", items: { type: "string" } },
    outBlinding: { type: "array", items: { type: "string" } },
  },
  required: ["root", "publicAmount", "extDataHash", "inputNullifiers", "outputCommitments", "inAmount", "inPrivateKey", "inBlinding", "inPathIndices", "inPathElements", "outAmount", "outPubkey", "outBlinding"],
  additionalProperties: false,
} as const;

const CIRCUIT_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    success: { type: "boolean" },
    circuit: { type: "string" },
    proof: { type: "object" },
    publicSignals: { type: "array", items: { type: "string" } },
    contractProof: { type: "array", items: { type: "string" } },
    generationTimeMs: { type: "number" },
  },
  required: ["success", "circuit", "proof", "publicSignals", "contractProof"],
} as const;

// --- Configuration ---
const PORT = Number(process.env.PORT) || 3402;
const PRIVATE_KEY = (process.env.SERVER_PRIVATE_KEY ||
  generatePrivateKey()) as `0x${string}`;
const account = privateKeyToAccount(PRIVATE_KEY);
const PATHUSD = "0x20c000000000000000000000b9537d11c60e8b50" as const;
const OWNER_WALLET = "0x4013AE1C1473f6CB37AA44eedf58BDF7Fa4068F7" as const;

// Base Sepolia PrivAgent contracts
const POOL_ADDRESS = "0x8F1ae8209156C22dFD972352A415880040fB0b0c";
const USDC_BASE = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const BASE_RPC = "https://sepolia.base.org";
const DEPLOY_BLOCK = 38347380;

console.log(`Server wallet: ${account.address}`);
console.log(`Payment recipient: ${OWNER_WALLET}`);

// --- Lazy-loaded privacy engine ---
let privacyEngine: PrivacyEngine | null = null;

interface PrivacyEngine {
  initialized: boolean;
  generateDepositProof(amount: bigint): Promise<any>;
  generateTransferProof(amount: bigint, recipientPubkey: string): Promise<any>;
  generateWithdrawProof(amount: bigint, recipient: string): Promise<any>;
  verifyPrivacyProof(proof: any, publicSignals: string[]): Promise<boolean>;
  getPoolInfo(): any;
}

async function getEngine(): Promise<PrivacyEngine> {
  if (privacyEngine?.initialized) return privacyEngine;

  const __dirnameCrypto = dirname(fileURLToPath(import.meta.url));
  const circuitDir = resolve(__dirnameCrypto, "../circuits");
  const snarkjs = await import("snarkjs");

  const privCircuits: Record<string, { wasm: string; zkey: string; vkey: any }> = {};

  for (const id of ["1x2", "2x2"]) {
    const dir = resolve(circuitDir, id);
    try {
      privCircuits[id] = {
        wasm: resolve(dir, `joinSplit_${id}.wasm`),
        zkey: resolve(dir, `joinSplit_${id}_final.zkey`),
        vkey: JSON.parse(readFileSync(resolve(dir, "verification_key.json"), "utf-8")),
      };
    } catch {
      console.warn(`Privacy circuit ${id} artifacts not found, skipping`);
    }
  }

  const { initPoseidon } = await import("./crypto.js");
  const poseidon: PoseidonHash = await initPoseidon();

  // Compute empty Merkle root: hash(0,0) repeated 20 times
  let currentHash = BigInt(0);
  for (let i = 0; i < 20; i++) {
    currentHash = poseidon.hash2(currentHash, currentHash);
  }
  const emptyRoot = currentHash;

  privacyEngine = {
    initialized: true,

    async generateDepositProof(amount: bigint) {
      const circuit = privCircuits["1x2"];
      if (!circuit) throw new Error("1x2 circuit not available");

      const dummyKey = BigInt(1);
      const dummyPubkey = poseidon.hash1(dummyKey);
      const dummyCommitment = poseidon.hash3(BigInt(0), dummyPubkey, BigInt(0));
      const dummyNullifier = poseidon.hash3(dummyCommitment, BigInt(0), dummyKey);

      const recipientKey = BigInt(55555);
      const recipientPubkey = poseidon.hash1(recipientKey);
      const blinding = BigInt(Math.floor(Math.random() * 2 ** 48));
      const commitment = poseidon.hash3(amount, recipientPubkey, blinding);
      const dummyOutCommitment = poseidon.hash3(BigInt(0), dummyPubkey, BigInt(0));
      const extDataHash = poseidon.hash3(BigInt(0), BigInt(0), BigInt(0));

      const input = {
        root: emptyRoot.toString(),
        publicAmount: amount.toString(),
        extDataHash: extDataHash.toString(),
        protocolFee: "0",
        inputNullifiers: [dummyNullifier.toString()],
        outputCommitments: [commitment.toString(), dummyOutCommitment.toString()],
        inAmount: ["0"],
        inPrivateKey: [dummyKey.toString()],
        inBlinding: ["0"],
        inPathIndices: ["0"],
        inPathElements: [Array(20).fill("0")],
        outAmount: [amount.toString(), "0"],
        outPubkey: [recipientPubkey.toString(), dummyPubkey.toString()],
        outBlinding: [blinding.toString(), "0"],
      };

      const startTime = Date.now();
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input, circuit.wasm, circuit.zkey,
      );
      const generationTimeMs = Date.now() - startTime;
      const valid = await snarkjs.groth16.verify(circuit.vkey, publicSignals, proof);

      return {
        success: true, operation: "deposit", amount: amount.toString(),
        proof, publicSignals, commitment: commitment.toString(),
        valid, generationTimeMs,
      };
    },

    async generateTransferProof(amount: bigint, recipientPubkey: string) {
      const circuit = privCircuits["1x2"];
      if (!circuit) throw new Error("1x2 circuit not available");

      const senderKey = BigInt(1);
      const senderPubkey = poseidon.hash1(senderKey);
      const inBlinding = BigInt(0);
      const inCommitment = poseidon.hash3(amount, senderPubkey, inBlinding);
      const nullifier = poseidon.hash3(inCommitment, BigInt(0), senderKey);
      const recipPubkey = BigInt(recipientPubkey);

      const payBlinding = BigInt(Math.floor(Math.random() * 2 ** 48));
      const payCommitment = poseidon.hash3(amount, recipPubkey, payBlinding);
      const changeCommitment = poseidon.hash3(BigInt(0), senderPubkey, BigInt(0));
      const extDataHash = poseidon.hash3(BigInt(0), BigInt(0), BigInt(0));

      let customRoot = inCommitment;
      let sibling = BigInt(0);
      for (let i = 0; i < 20; i++) {
        const left = customRoot;
        sibling = i === 0 ? BigInt(0) : poseidon.hash2(sibling, sibling);
        customRoot = poseidon.hash2(left, sibling);
      }

      const pathElements: string[] = [];
      let sib = BigInt(0);
      for (let i = 0; i < 20; i++) {
        pathElements.push(sib.toString());
        sib = poseidon.hash2(sib, sib);
      }

      const input = {
        root: customRoot.toString(),
        publicAmount: "0",
        extDataHash: extDataHash.toString(),
        protocolFee: "0",
        inputNullifiers: [nullifier.toString()],
        outputCommitments: [payCommitment.toString(), changeCommitment.toString()],
        inAmount: [amount.toString()],
        inPrivateKey: [senderKey.toString()],
        inBlinding: [inBlinding.toString()],
        inPathIndices: ["0"],
        inPathElements: [pathElements],
        outAmount: [amount.toString(), "0"],
        outPubkey: [recipPubkey.toString(), senderPubkey.toString()],
        outBlinding: [payBlinding.toString(), "0"],
      };

      const startTime = Date.now();
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input, circuit.wasm, circuit.zkey,
      );
      const generationTimeMs = Date.now() - startTime;
      const valid = await snarkjs.groth16.verify(circuit.vkey, publicSignals, proof);

      return {
        success: true, operation: "transfer", amount: amount.toString(),
        recipientPubkey, proof, publicSignals,
        paymentCommitment: payCommitment.toString(),
        changeCommitment: changeCommitment.toString(),
        valid, generationTimeMs,
      };
    },

    async generateWithdrawProof(amount: bigint, recipient: string) {
      const circuit = privCircuits["1x2"];
      if (!circuit) throw new Error("1x2 circuit not available");

      const fieldPrime = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
      const privKey = BigInt(1);
      const pubkey = poseidon.hash1(privKey);
      const inBlinding = BigInt(0);
      const inCommitment = poseidon.hash3(amount, pubkey, inBlinding);
      const nullifier = poseidon.hash3(inCommitment, BigInt(0), privKey);

      let customRoot = inCommitment;
      let sib = BigInt(0);
      const pathElements: string[] = [];
      for (let i = 0; i < 20; i++) {
        pathElements.push(sib.toString());
        customRoot = poseidon.hash2(customRoot, sib);
        sib = poseidon.hash2(sib, sib);
      }

      const dummyCommitment1 = poseidon.hash3(BigInt(0), pubkey, BigInt(0));
      const dummyCommitment2 = poseidon.hash3(BigInt(0), pubkey, BigInt(0));
      const publicAmount = (fieldPrime - amount) % fieldPrime;
      const extDataHash = poseidon.hash3(BigInt(0), BigInt(0), BigInt(0));

      const input = {
        root: customRoot.toString(),
        publicAmount: publicAmount.toString(),
        extDataHash: extDataHash.toString(),
        protocolFee: "0",
        inputNullifiers: [nullifier.toString()],
        outputCommitments: [dummyCommitment1.toString(), dummyCommitment2.toString()],
        inAmount: [amount.toString()],
        inPrivateKey: [privKey.toString()],
        inBlinding: [inBlinding.toString()],
        inPathIndices: ["0"],
        inPathElements: [pathElements],
        outAmount: ["0", "0"],
        outPubkey: [pubkey.toString(), pubkey.toString()],
        outBlinding: ["0", "0"],
      };

      const startTime = Date.now();
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input, circuit.wasm, circuit.zkey,
      );
      const generationTimeMs = Date.now() - startTime;
      const valid = await snarkjs.groth16.verify(circuit.vkey, publicSignals, proof);

      return {
        success: true, operation: "withdraw", amount: amount.toString(),
        recipient, proof, publicSignals, valid, generationTimeMs,
      };
    },

    async verifyPrivacyProof(proof: any, publicSignals: string[]) {
      const circuit = privCircuits["1x2"];
      if (!circuit) throw new Error("1x2 circuit not available");
      return snarkjs.groth16.verify(circuit.vkey, publicSignals, proof);
    },

    getPoolInfo() {
      return {
        pool: POOL_ADDRESS,
        chain: "base-sepolia",
        chainId: 84532,
        usdc: USDC_BASE,
        deployBlock: DEPLOY_BLOCK,
        circuits: Object.keys(privCircuits),
        merkleDepth: 20,
        maxLeaves: 1048576,
      };
    },
  };

  return privacyEngine;
}

// --- Privacy endpoint handlers ---
async function handleDeposit(c: any) {
  let body: { amount: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }
  if (!body.amount) return c.json({ error: "amount is required" }, 400);

  try {
    const engine = await getEngine();
    const result = await engine.generateDepositProof(BigInt(body.amount));
    return c.json(result);
  } catch (e) {
    return c.json({ error: "Deposit proof generation failed", details: (e as Error).message }, 500);
  }
}

async function handleTransfer(c: any) {
  let body: { amount: string; recipientPubkey: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }
  if (!body.amount || !body.recipientPubkey) {
    return c.json({ error: "amount and recipientPubkey are required" }, 400);
  }

  try {
    const engine = await getEngine();
    const result = await engine.generateTransferProof(BigInt(body.amount), body.recipientPubkey);
    return c.json(result);
  } catch (e) {
    return c.json({ error: "Transfer proof generation failed", details: (e as Error).message }, 500);
  }
}

async function handleWithdraw(c: any) {
  let body: { amount: string; recipient: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }
  if (!body.amount || !body.recipient) {
    return c.json({ error: "amount and recipient are required" }, 400);
  }

  try {
    const engine = await getEngine();
    const result = await engine.generateWithdrawProof(BigInt(body.amount), body.recipient);
    return c.json(result);
  } catch (e) {
    return c.json({ error: "Withdrawal proof generation failed", details: (e as Error).message }, 500);
  }
}

// --- Privacy x402 schema definitions ---
const PRIVACY_DEPOSIT_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    amount: { type: "string", minLength: 1, description: "USDC amount in micro-units (6 decimals). e.g. '10000000' = 10 USDC" },
  },
  required: ["amount"],
  additionalProperties: false,
} as const;

const PRIVACY_TRANSFER_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    amount: { type: "string", minLength: 1, description: "USDC amount in micro-units" },
    recipientPubkey: { type: "string", minLength: 1, description: "Recipient Poseidon public key" },
  },
  required: ["amount", "recipientPubkey"],
  additionalProperties: false,
} as const;

const PRIVACY_WITHDRAW_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    amount: { type: "string", minLength: 1, description: "USDC amount in micro-units" },
    recipient: { type: "string", minLength: 1, description: "Recipient Ethereum address for withdrawal" },
  },
  required: ["amount", "recipient"],
  additionalProperties: false,
} as const;

const PRIVACY_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    success: { type: "boolean" },
    operation: { type: "string" },
    proof: { type: "object" },
    publicSignals: { type: "array", items: { type: "string" } },
    generationTimeMs: { type: "number" },
  },
  required: ["success", "proof", "publicSignals"],
} as const;

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
<link rel="icon" type="image/png" href="/favicon.png">
<style>body{font-family:system-ui;max-width:700px;margin:60px auto;padding:0 20px;background:#0a0a0a;color:#e0e0e0}
h1{color:#fff}a{color:#58a6ff}code{background:#1a1a2e;padding:2px 6px;border-radius:4px;font-size:14px}
pre{background:#1a1a2e;padding:16px;border-radius:8px;overflow-x:auto;font-size:13px}
.badge{display:inline-block;background:#238636;color:#fff;padding:4px 10px;border-radius:12px;font-size:13px;margin:4px}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #333;padding:8px;text-align:left}th{background:#1a1a2e}</style></head>
<body>
<h1>ZKProver</h1>
<p><span class="badge">LIVE</span> <span class="badge">Groth16</span> <span class="badge">Privacy</span> <span class="badge">MPP</span></p>
<p>Pay-per-proof ZK proving via <a href="https://mpp.dev">Tempo MPP</a>. Real compute, not a proxy. Now with privacy-preserving proofs.</p>

<h2>Try it</h2>
<pre>tempo request -t https://himess-zk-proof-service.hf.space/circuits

tempo request -v -X POST \\
  -H "Content-Type: application/json" \\
  -d @input.json \\
  https://himess-zk-proof-service.hf.space/prove/1x2

tempo request -v -X POST \\
  -H "Content-Type: application/json" \\
  -d '{"amount":"1000000"}' \\
  https://himess-zk-proof-service.hf.space/privacy/deposit</pre>

<h2>Proving Endpoints</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>GET</td><td><a href="/health">/health</a></td><td>Free</td><td>Health check</td></tr>
<tr><td>GET</td><td><a href="/circuits">/circuits</a></td><td>Free</td><td>List circuits & pricing</td></tr>
<tr><td>GET</td><td><a href="/llms.txt">/llms.txt</a></td><td>Free</td><td>Agent discovery</td></tr>
<tr><td>POST</td><td>/prove/1x2</td><td>$0.01</td><td>Generate 1x2 proof</td></tr>
<tr><td>POST</td><td>/prove/2x2</td><td>$0.02</td><td>Generate 2x2 proof</td></tr>
<tr><td>POST</td><td>/verify/:circuit</td><td>Free</td><td>Verify a proof</td></tr>
</table>

<h2>Privacy Endpoints</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>GET</td><td><a href="/pool">/pool</a></td><td>Free</td><td>Pool info & circuits</td></tr>
<tr><td>POST</td><td>/privacy/deposit</td><td>$0.03</td><td>Shielded deposit proof</td></tr>
<tr><td>POST</td><td>/privacy/transfer</td><td>$0.03</td><td>Private transfer proof</td></tr>
<tr><td>POST</td><td>/privacy/withdraw</td><td>$0.03</td><td>Withdrawal proof</td></tr>
</table>

<h2>Performance</h2>
<p>~2-5s proof generation · ~50ms verification · 13,726 constraints · BN254 curve</p>

<h2>Links</h2>
<p><a href="https://github.com/Himess/zk-proof-service">GitHub</a> · <a href="/llms.txt">llms.txt</a> · <a href="/circuits">API</a> · <a href="/pool">Pool Info</a></p>
</body></html>`);
  });

  // Favicon
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const faviconBuf = readFileSync(resolve(__dirname, "../favicon.png"));
  app.get("/favicon.png", (c) => {
    c.header("Content-Type", "image/png");
    c.header("Cache-Control", "public, max-age=86400");
    return c.body(faviconBuf);
  });
  app.get("/favicon.ico", (c) => {
    c.header("Content-Type", "image/png");
    c.header("Cache-Control", "public, max-age=86400");
    return c.body(faviconBuf);
  });

  // Health check (free)
  app.get("/health", (c) =>
    c.json({
      status: "ok",
      wallet: OWNER_WALLET,
      chain: "tempo-moderato",
      chainId: 42431,
      privacyPool: POOL_ADDRESS,
      poolChain: "base-sepolia",
    })
  );

  // Pool info (free)
  app.get("/pool", async (c) => {
    const engine = await getEngine();
    return c.json(engine.getPoolInfo());
  });

  // OpenAPI Discovery (required for MPPscan)
  app.get("/openapi.json", (c) =>
    c.json({
      openapi: "3.1.0",
      info: {
        title: "ZKProver",
        version: "2.0.0",
        description: "Pay-per-proof Groth16 ZK proving service on Tempo MPP. Now with privacy-preserving shielded deposits, transfers, and withdrawals.",
        "x-guidance": "Use ZKProver to generate and verify Groth16 zero-knowledge proofs for JoinSplit circuits. POST circuit inputs to /prove/1x2 ($0.01) or /prove/2x2 ($0.02). For privacy operations: POST to /privacy/deposit ($0.03) to shield funds, /privacy/transfer ($0.03) for private transfers, /privacy/withdraw ($0.03) to unshield. Payment is automatic via MPP 402 flow. Verification at /verify/:circuit is free. Check /circuits for available circuits and pricing.",
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
            security: [],
            "x-payment-info": { pricingMode: "fixed", price: "0", protocols: ["mpp"] },
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
            security: [],
            "x-payment-info": { pricingMode: "fixed", price: "0", protocols: ["mpp"] },
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
            operationId: "prove1x2",
            summary: "Generate Groth16 proof (1-input, 2-output JoinSplit)",
            tags: ["Proving"],
            description: "Generates a Groth16 ZK proof for a 1x2 JoinSplit circuit. Requires MPP payment of $0.01 USDC.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.010000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      root: { type: "string", minLength: 1, description: "Merkle tree root" },
                      publicAmount: { type: "string", minLength: 1, description: "Public amount for deposit/withdrawal" },
                      extDataHash: { type: "string", minLength: 1, description: "External data hash" },
                      protocolFee: { type: "string", description: "Protocol fee" },
                      inputNullifiers: { type: "array", items: { type: "string" } },
                      outputCommitments: { type: "array", items: { type: "string" } },
                      inAmount: { type: "array", items: { type: "string" } },
                      inPrivateKey: { type: "array", items: { type: "string" } },
                      inBlinding: { type: "array", items: { type: "string" } },
                      inPathIndices: { type: "array", items: { type: "string" } },
                      inPathElements: { type: "array", items: { type: "array", items: { type: "string" } } },
                      outAmount: { type: "array", items: { type: "string" } },
                      outPubkey: { type: "array", items: { type: "string" } },
                      outBlinding: { type: "array", items: { type: "string" } },
                    },
                    required: ["root", "publicAmount", "extDataHash", "inputNullifiers", "outputCommitments", "inAmount", "inPrivateKey", "inBlinding", "inPathIndices", "inPathElements", "outAmount", "outPubkey", "outBlinding"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Successful response",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        circuit: { type: "string" },
                        proof: { type: "object" },
                        publicSignals: { type: "array", items: { type: "string" } },
                        contractProof: { type: "array", items: { type: "string" } },
                        generationTimeMs: { type: "number" },
                      },
                      required: ["success", "circuit", "proof", "publicSignals", "contractProof"],
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/prove/2x2": {
          post: {
            operationId: "prove2x2",
            summary: "Generate Groth16 proof (2-input, 2-output JoinSplit)",
            tags: ["Proving"],
            description: "Generates a Groth16 ZK proof for a 2x2 JoinSplit circuit. Requires MPP payment of $0.02 USDC.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.020000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      root: { type: "string", minLength: 1, description: "Merkle tree root" },
                      publicAmount: { type: "string", minLength: 1, description: "Public amount for deposit/withdrawal" },
                      extDataHash: { type: "string", minLength: 1, description: "External data hash" },
                      protocolFee: { type: "string", description: "Protocol fee" },
                      inputNullifiers: { type: "array", items: { type: "string" } },
                      outputCommitments: { type: "array", items: { type: "string" } },
                      inAmount: { type: "array", items: { type: "string" } },
                      inPrivateKey: { type: "array", items: { type: "string" } },
                      inBlinding: { type: "array", items: { type: "string" } },
                      inPathIndices: { type: "array", items: { type: "string" } },
                      inPathElements: { type: "array", items: { type: "array", items: { type: "string" } } },
                      outAmount: { type: "array", items: { type: "string" } },
                      outPubkey: { type: "array", items: { type: "string" } },
                      outBlinding: { type: "array", items: { type: "string" } },
                    },
                    required: ["root", "publicAmount", "extDataHash", "inputNullifiers", "outputCommitments", "inAmount", "inPrivateKey", "inBlinding", "inPathIndices", "inPathElements", "outAmount", "outPubkey", "outBlinding"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Successful response",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        circuit: { type: "string" },
                        proof: { type: "object" },
                        publicSignals: { type: "array", items: { type: "string" } },
                        contractProof: { type: "array", items: { type: "string" } },
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
            security: [],
            "x-payment-info": { pricingMode: "fixed", price: "0", protocols: ["mpp"] },
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
        "/pool": {
          get: {
            summary: "Privacy pool info",
            description: "Returns privacy pool contract addresses, chain info, and available circuits. Free.",
            security: [],
            "x-payment-info": { pricingMode: "fixed", price: "0", protocols: ["mpp"] },
            responses: {
              "200": {
                description: "Pool info",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        pool: { type: "string" },
                        chain: { type: "string" },
                        chainId: { type: "integer" },
                        usdc: { type: "string" },
                        circuits: { type: "array", items: { type: "string" } },
                        merkleDepth: { type: "integer" },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        "/privacy/deposit": {
          post: {
            operationId: "privacyDeposit",
            summary: "Generate shielded deposit proof",
            tags: ["Privacy"],
            description: "Generates a Groth16 ZK proof for a shielded deposit (public to private). Requires MPP payment of $0.03 USDC.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.030000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      amount: { type: "string", minLength: 1, description: "USDC amount in micro-units (6 decimals). e.g. '10000000' = 10 USDC" },
                    },
                    required: ["amount"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Deposit proof generated",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        operation: { type: "string" },
                        proof: { type: "object" },
                        publicSignals: { type: "array", items: { type: "string" } },
                        commitment: { type: "string" },
                        generationTimeMs: { type: "number" },
                      },
                      required: ["success", "proof", "publicSignals"],
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/privacy/transfer": {
          post: {
            operationId: "privacyTransfer",
            summary: "Generate private transfer proof",
            tags: ["Privacy"],
            description: "Generates a Groth16 ZK proof for a private transfer (private to private). Requires MPP payment of $0.03 USDC.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.030000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      amount: { type: "string", minLength: 1, description: "USDC amount in micro-units" },
                      recipientPubkey: { type: "string", minLength: 1, description: "Recipient Poseidon public key" },
                    },
                    required: ["amount", "recipientPubkey"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Transfer proof generated",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        operation: { type: "string" },
                        proof: { type: "object" },
                        publicSignals: { type: "array", items: { type: "string" } },
                        paymentCommitment: { type: "string" },
                        changeCommitment: { type: "string" },
                        generationTimeMs: { type: "number" },
                      },
                      required: ["success", "proof", "publicSignals"],
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/privacy/withdraw": {
          post: {
            operationId: "privacyWithdraw",
            summary: "Generate withdrawal proof",
            tags: ["Privacy"],
            description: "Generates a Groth16 ZK proof for a withdrawal (private to public). Requires MPP payment of $0.03 USDC.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.030000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      amount: { type: "string", minLength: 1, description: "USDC amount in micro-units" },
                      recipient: { type: "string", minLength: 1, description: "Recipient Ethereum address for withdrawal" },
                    },
                    required: ["amount", "recipient"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Withdrawal proof generated",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        operation: { type: "string" },
                        proof: { type: "object" },
                        publicSignals: { type: "array", items: { type: "string" } },
                        generationTimeMs: { type: "number" },
                      },
                      required: ["success", "proof", "publicSignals"],
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
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
        "POST /privacy/deposit",
        "POST /privacy/transfer",
        "POST /privacy/withdraw",
      ],
      description: "ZKProver: pay-per-proof Groth16 ZK proving service via MPP. POST circuit inputs to /prove/1x2 ($0.01) or /prove/2x2 ($0.02). Privacy operations: /privacy/deposit ($0.03), /privacy/transfer ($0.03), /privacy/withdraw ($0.03). Verification at /verify/:circuit is free.",
    })
  );

  // LLMs.txt (free)
  app.get("/llms.txt", (c) => {
    c.header("Content-Type", "text/plain");
    return c.body(`# ZKProver
> Pay-per-proof Groth16 ZK proving via MPP. Real compute, not a proxy. Now with privacy-preserving proofs.

## Live
https://himess-zk-proof-service.hf.space

## Proving Endpoints
- GET /health — Health check (free)
- GET /circuits — List circuits and pricing (free)
- POST /prove/1x2 — Generate 1x2 JoinSplit proof ($0.01 MPP)
- POST /prove/2x2 — Generate 2x2 JoinSplit proof ($0.02 MPP)
- POST /verify/:circuit — Verify a proof (free)

## Privacy Endpoints
- GET /pool — Privacy pool info and available circuits (free)
- POST /privacy/deposit — Generate shielded deposit proof ($0.03 MPP)
- POST /privacy/transfer — Generate private transfer proof ($0.03 MPP)
- POST /privacy/withdraw — Generate withdrawal proof ($0.03 MPP)

## Pricing
- 1x2 circuit: $0.01 per proof
- 2x2 circuit: $0.02 per proof
- Privacy proofs (deposit/transfer/withdraw): $0.03 per proof
- Payment: USDC via Tempo MPP (automatic 402 flow)

## What This Does
Generates Groth16 zero-knowledge proofs for JoinSplit circuits (private UTXO transactions).
Returns proof, public signals, and uint256[8] contract-ready format for on-chain Solidity verifiers.
Privacy endpoints generate proofs for shielded deposits (public to private), private transfers, and withdrawals (private to public) using Poseidon hashing and BN254 curve.
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
      realm: "himess-zk-proof-service.hf.space",
      methods: [
        tempo({
          currency: PATHUSD,
          recipient: OWNER_WALLET,
          feePayer: true,
        }),
      ],
      secretKey: process.env.MPP_SECRET_KEY || "dev-secret-key-change-in-production",
    });

    app.post(
      "/prove/1x2",
      withX402Schema(
        { input: CIRCUIT_INPUT_SCHEMA_1x2, output: CIRCUIT_OUTPUT_SCHEMA },
        "Generate Groth16 proof (1-input, 2-output JoinSplit)",
        "10000",
      ),
      mppx.charge({ amount: "0.01", description: "ZK proof (1x2)" }),
      handleProve,
    );
    app.post(
      "/prove/2x2",
      withX402Schema(
        { input: CIRCUIT_INPUT_SCHEMA_1x2, output: CIRCUIT_OUTPUT_SCHEMA },
        "Generate Groth16 proof (2-input, 2-output JoinSplit)",
        "20000",
      ),
      mppx.charge({ amount: "0.02", description: "ZK proof (2x2)" }),
      handleProve,
    );

    // Privacy routes (MPP-gated)
    app.post(
      "/privacy/deposit",
      withX402Schema(
        { input: PRIVACY_DEPOSIT_SCHEMA, output: PRIVACY_OUTPUT_SCHEMA },
        "Generate shielded deposit proof",
        "30000",
      ),
      mppx.charge({ amount: "0.03", description: "Shielded deposit proof" }),
      handleDeposit,
    );
    app.post(
      "/privacy/transfer",
      withX402Schema(
        { input: PRIVACY_TRANSFER_SCHEMA, output: PRIVACY_OUTPUT_SCHEMA },
        "Generate private transfer proof",
        "30000",
      ),
      mppx.charge({ amount: "0.03", description: "Private transfer proof" }),
      handleTransfer,
    );
    app.post(
      "/privacy/withdraw",
      withX402Schema(
        { input: PRIVACY_WITHDRAW_SCHEMA, output: PRIVACY_OUTPUT_SCHEMA },
        "Generate withdrawal proof",
        "30000",
      ),
      mppx.charge({ amount: "0.03", description: "Withdrawal proof" }),
      handleWithdraw,
    );

    console.log("MPP payment gating enabled");
  } catch (e) {
    console.warn("mppx not available, running free:", (e as Error).message);
    app.post("/prove/1x2", handleProve);
    app.post("/prove/2x2", handleProve);
    app.post("/privacy/deposit", handleDeposit);
    app.post("/privacy/transfer", handleTransfer);
    app.post("/privacy/withdraw", handleWithdraw);
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
    console.log(`  GET  /health              — Health check (free)`);
    console.log(`  GET  /circuits            — List circuits (free)`);
    console.log(`  GET  /pool                — Privacy pool info (free)`);
    console.log(`  POST /prove/1x2           — Generate 1x2 proof ($0.01 MPP)`);
    console.log(`  POST /prove/2x2           — Generate 2x2 proof ($0.02 MPP)`);
    console.log(`  POST /verify/1x2          — Verify 1x2 proof (free)`);
    console.log(`  POST /verify/2x2          — Verify 2x2 proof (free)`);
    console.log(`  POST /privacy/deposit     — Shielded deposit proof ($0.03 MPP)`);
    console.log(`  POST /privacy/transfer    — Private transfer proof ($0.03 MPP)`);
    console.log(`  POST /privacy/withdraw    — Withdrawal proof ($0.03 MPP)`);
  });
}

main().catch(console.error);
