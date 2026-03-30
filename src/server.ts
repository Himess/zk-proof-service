import { Hono } from "hono";
import { cors } from "hono/cors";
import { serve } from "@hono/node-server";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { registerMerkleRoutes } from "./merkle-routes.js";
import { registerAttestationRoutes } from "./attestation-routes.js";
import { registerBatchRoutes } from "./batch-routes.js";
import { registerHashRoutes } from "./hash-routes.js";
import { registerCompressionRoutes } from "./compression-routes.js";
import { registerStealthRoutes } from "./stealth-routes.js";
import { registerOnchainRoutes } from "./onchain-routes.js";
import { registerZkAttestationRoutes } from "./zk-attestation-routes.js";
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
<p><span class="badge">LIVE</span> <span class="badge">Groth16</span> <span class="badge">Privacy</span> <span class="badge">Stealth</span> <span class="badge">Attestation</span> <span class="badge">Merkle</span> <span class="badge">Hashing</span> <span class="badge">MPP</span></p>
<p>Full-stack zero-knowledge proving service via <a href="https://mpp.dev">Tempo MPP</a>. ZK proofs, privacy transactions, stealth addresses, attestations, Merkle trees, and ZK-friendly hashing. Real compute, not a proxy.</p>

<h2>Try it</h2>
<pre>tempo request -t https://himess-zk-proof-service.hf.space/circuits

tempo request -v -X POST \\
  -H "Content-Type: application/json" \\
  -d @input.json \\
  https://himess-zk-proof-service.hf.space/prove/1x2

tempo request -v -X POST \\
  -H "Content-Type: application/json" \\
  -d '{"amount":"1000000"}' \\
  https://himess-zk-proof-service.hf.space/privacy/deposit

tempo request -v -X POST \\
  -H "Content-Type: application/json" \\
  -d '{"inputs":["12345","67890"]}' \\
  https://himess-zk-proof-service.hf.space/hash/poseidon</pre>

<h2>Discovery</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>GET</td><td><a href="/health">/health</a></td><td>Free</td><td>Health check</td></tr>
<tr><td>GET</td><td><a href="/circuits">/circuits</a></td><td>Free</td><td>List circuits &amp; pricing</td></tr>
<tr><td>GET</td><td><a href="/pool">/pool</a></td><td>Free</td><td>Privacy pool info</td></tr>
<tr><td>GET</td><td><a href="/llms.txt">/llms.txt</a></td><td>Free</td><td>Agent discovery</td></tr>
<tr><td>GET</td><td><a href="/openapi.json">/openapi.json</a></td><td>Free</td><td>OpenAPI spec</td></tr>
<tr><td>GET</td><td><a href="/.well-known/x402">/.well-known/x402</a></td><td>Free</td><td>x402 resource list</td></tr>
</table>

<h2>ZK Proving</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>POST</td><td>/prove/1x2</td><td>$0.01</td><td>Generate Groth16 proof (1x2 JoinSplit)</td></tr>
<tr><td>POST</td><td>/prove/2x2</td><td>$0.02</td><td>Generate Groth16 proof (2x2 JoinSplit)</td></tr>
<tr><td>POST</td><td>/prove/batch</td><td>$0.008/proof</td><td>Batch proof generation (20% discount)</td></tr>
<tr><td>POST</td><td>/verify/:circuit</td><td>Free</td><td>Verify a proof</td></tr>
</table>

<h2>Privacy Proofs</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>POST</td><td>/privacy/deposit</td><td>$0.03</td><td>Shielded deposit proof</td></tr>
<tr><td>POST</td><td>/privacy/transfer</td><td>$0.03</td><td>Private transfer proof</td></tr>
<tr><td>POST</td><td>/privacy/withdraw</td><td>$0.03</td><td>Withdrawal proof</td></tr>
</table>

<h2>ZK Attestation</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>POST</td><td>/attest/zk/balance-gt</td><td>$0.01</td><td>ZK proof: balance &gt; threshold</td></tr>
<tr><td>POST</td><td>/attest/zk/verify</td><td>Free</td><td>Verify ZK attestation</td></tr>
</table>

<h2>Credential Attestation</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>POST</td><td>/attest/commitment</td><td>$0.001</td><td>Create Poseidon commitment</td></tr>
<tr><td>POST</td><td>/attest/balance-gt</td><td>$0.005</td><td>Attest balance &gt; threshold</td></tr>
<tr><td>POST</td><td>/attest/range</td><td>$0.005</td><td>Attest value in range</td></tr>
<tr><td>POST</td><td>/attest/membership</td><td>$0.005</td><td>Attest set membership</td></tr>
<tr><td>POST</td><td>/attest/verify</td><td>Free</td><td>Verify attestation</td></tr>
</table>

<h2>On-chain Attestation (Tempo)</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>POST</td><td>/attest/onchain/balance</td><td>$0.005</td><td>Verify token balance on Tempo</td></tr>
<tr><td>POST</td><td>/attest/onchain/nft</td><td>$0.005</td><td>Verify NFT ownership</td></tr>
<tr><td>POST</td><td>/attest/onchain/interaction</td><td>$0.005</td><td>Verify contract interaction</td></tr>
</table>

<h2>Stealth Addresses</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>POST</td><td>/stealth/generate-keys</td><td>$0.002</td><td>Generate stealth meta-address</td></tr>
<tr><td>POST</td><td>/stealth/derive-address</td><td>$0.002</td><td>Derive one-time stealth address</td></tr>
<tr><td>POST</td><td>/stealth/scan</td><td>$0.005</td><td>Scan for stealth payments</td></tr>
<tr><td>POST</td><td>/stealth/compute-key</td><td>$0.002</td><td>Recover stealth private key</td></tr>
</table>

<h2>Merkle Tree</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>POST</td><td>/merkle/build</td><td>$0.01</td><td>Build Poseidon Merkle tree</td></tr>
<tr><td>POST</td><td>/merkle/prove</td><td>$0.005</td><td>Generate inclusion proof</td></tr>
<tr><td>POST</td><td>/merkle/verify</td><td>Free</td><td>Verify inclusion proof</td></tr>
</table>

<h2>Hash Functions</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>POST</td><td>/hash/poseidon</td><td>$0.001</td><td>Poseidon hash</td></tr>
<tr><td>POST</td><td>/hash/mimc</td><td>$0.001</td><td>MiMC sponge hash</td></tr>
<tr><td>POST</td><td>/hash/pedersen</td><td>$0.001</td><td>Pedersen hash</td></tr>
<tr><td>POST</td><td>/hash/keccak256</td><td>$0.001</td><td>Keccak256 hash</td></tr>
</table>

<h2>Proof Tools</h2>
<table>
<tr><th>Method</th><th>Path</th><th>Cost</th><th>Description</th></tr>
<tr><td>POST</td><td>/proof/compress</td><td>$0.002</td><td>Compress proof + Solidity calldata</td></tr>
</table>

<h2>Performance</h2>
<p>~2-5s proof generation · ~50ms verification · 13,726 constraints · BN254 curve</p>

<h2>Links</h2>
<p><a href="https://github.com/Himess/zk-proof-service">GitHub</a> · <a href="/llms.txt">llms.txt</a> · <a href="/openapi.json">OpenAPI</a> · <a href="/circuits">Circuits</a> · <a href="/pool">Pool Info</a></p>
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
        version: "3.0.0",
        description: "Full-stack zero-knowledge proving service on Tempo MPP. ZK proof generation, privacy transactions, stealth addresses, ZK/credential/on-chain attestations, Merkle trees, ZK-friendly hashing, and proof compression.",
        "x-guidance": "ZKProver provides 30+ endpoints for zero-knowledge cryptography. ZK Proving: /prove/1x2 ($0.01), /prove/2x2 ($0.02), /prove/batch ($0.008/proof). Privacy: /privacy/deposit, /transfer, /withdraw ($0.03 each). ZK Attestation: /attest/zk/balance-gt ($0.01) for trustless proofs. Credential Attestation: /attest/commitment ($0.001), /attest/balance-gt, /attest/range, /attest/membership ($0.005 each). On-chain (Tempo): /attest/onchain/balance, /nft, /interaction ($0.005 each). Stealth Addresses: /stealth/generate-keys, /derive-address, /compute-key ($0.002 each), /stealth/scan ($0.005). Merkle: /merkle/build ($0.01), /merkle/prove ($0.005). Hashing: /hash/poseidon, /hash/mimc, /hash/pedersen, /hash/keccak256 ($0.001 each). Proof Tools: /proof/compress ($0.002). Verification endpoints are free. Payment is automatic via MPP 402 flow.",
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
        "/prove/batch": {
          post: {
            operationId: "proveBatch",
            summary: "Batch proof generation (20% discount)",
            tags: ["ZK Proving"],
            description: "Generate multiple Groth16 proofs in a single request at $0.008/proof (20% discount vs individual). Min 2, max 20.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.008000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      circuit: { type: "string", enum: ["1x2", "2x2"], description: "Circuit type" },
                      inputs: { type: "array", items: { type: "object" }, minItems: 2, maxItems: 20, description: "Array of circuit input objects" },
                    },
                    required: ["circuit", "inputs"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Batch proofs generated",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        circuit: { type: "string" },
                        results: { type: "array", items: { type: "object" } },
                        totalTimeMs: { type: "number" },
                        count: { type: "integer" },
                        pricing: { type: "object" },
                      },
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/attest/zk/balance-gt": {
          post: {
            operationId: "zkAttestBalanceGt",
            summary: "ZK proof: balance > threshold",
            tags: ["ZK Attestation"],
            description: "Generate a Groth16 ZK proof that a committed balance exceeds a threshold. Trustless — anyone can verify. $0.01.",
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
                      value: { type: "string", description: "Secret value (balance)" },
                      blinding: { type: "string", description: "Random blinding factor" },
                      threshold: { type: "string", description: "Public threshold to prove against" },
                    },
                    required: ["value", "blinding", "threshold"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "ZK attestation proof generated",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        proof: { type: "object" },
                        publicSignals: { type: "array", items: { type: "string" } },
                        commitment: { type: "string" },
                        threshold: { type: "string" },
                        verified: { type: "boolean" },
                        generationTimeMs: { type: "number" },
                        circuit: { type: "string" },
                        protocol: { type: "string" },
                        curve: { type: "string" },
                      },
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/attest/zk/verify": {
          post: {
            operationId: "zkAttestVerify",
            summary: "Verify ZK attestation",
            tags: ["ZK Attestation"],
            description: "Verify a Groth16 ZK attestation proof. Free.",
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      proof: { type: "object", description: "Groth16 proof object" },
                      publicSignals: { type: "array", items: { type: "string" }, description: "[commitment, threshold]" },
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
                        valid: { type: "boolean" },
                        verificationTimeMs: { type: "number" },
                        publicSignals: { type: "object" },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        "/attest/commitment": {
          post: {
            operationId: "attestCommitment",
            summary: "Create Poseidon commitment",
            tags: ["Credential Attestation"],
            description: "Create a Poseidon hash commitment from a value and blinding factor. $0.001.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.001000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      value: { type: "string", description: "Value to commit" },
                      blinding: { type: "string", description: "Random blinding factor" },
                    },
                    required: ["value", "blinding"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Commitment created",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        commitment: { type: "string" },
                        value: { type: "string" },
                        computeTimeMs: { type: "number" },
                      },
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/attest/balance-gt": {
          post: {
            operationId: "attestBalanceGt",
            summary: "Attest balance > threshold",
            tags: ["Credential Attestation"],
            description: "Server-signed attestation that a committed balance exceeds a threshold. $0.005.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.005000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      commitment: { type: "string" },
                      value: { type: "string" },
                      blinding: { type: "string" },
                      threshold: { type: "string" },
                    },
                    required: ["commitment", "value", "blinding", "threshold"],
                  },
                },
              },
            },
            responses: {
              "200": { description: "Attestation result", content: { "application/json": { schema: { type: "object" } } } },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/attest/range": {
          post: {
            operationId: "attestRange",
            summary: "Attest value in range",
            tags: ["Credential Attestation"],
            description: "Server-signed attestation that a committed value falls within [min, max]. $0.005.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.005000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      commitment: { type: "string" },
                      value: { type: "string" },
                      blinding: { type: "string" },
                      min: { type: "string" },
                      max: { type: "string" },
                    },
                    required: ["commitment", "value", "blinding", "min", "max"],
                  },
                },
              },
            },
            responses: {
              "200": { description: "Attestation result", content: { "application/json": { schema: { type: "object" } } } },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/attest/membership": {
          post: {
            operationId: "attestMembership",
            summary: "Attest set membership",
            tags: ["Credential Attestation"],
            description: "Server-signed attestation that a committed value is a member of a Merkle set. $0.005.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.005000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      commitment: { type: "string" },
                      value: { type: "string" },
                      blinding: { type: "string" },
                      leaves: { type: "array", items: { type: "string" }, description: "Set of leaf values" },
                    },
                    required: ["commitment", "value", "blinding", "leaves"],
                  },
                },
              },
            },
            responses: {
              "200": { description: "Attestation result", content: { "application/json": { schema: { type: "object" } } } },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/attest/verify": {
          post: {
            operationId: "attestVerify",
            summary: "Verify attestation",
            tags: ["Credential Attestation"],
            description: "Verify a server-signed attestation. Free.",
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      attestation: { type: "object", description: "Attestation object to verify" },
                    },
                    required: ["attestation"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Verification result",
                content: { "application/json": { schema: { type: "object", properties: { valid: { type: "boolean" } } } } },
              },
            },
          },
        },
        "/attest/onchain/balance": {
          post: {
            operationId: "attestOnchainBalance",
            summary: "Verify token balance on Tempo",
            tags: ["On-chain Attestation"],
            description: "Verify that an address holds a token balance above a threshold on Tempo chain. $0.005.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.005000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      address: { type: "string", description: "Wallet address" },
                      token: { type: "string", description: "Token contract address (optional, native if omitted)" },
                      threshold: { type: "string", description: "Minimum balance threshold" },
                    },
                    required: ["address", "threshold"],
                  },
                },
              },
            },
            responses: {
              "200": { description: "Attestation result", content: { "application/json": { schema: { type: "object" } } } },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/attest/onchain/nft": {
          post: {
            operationId: "attestOnchainNft",
            summary: "Verify NFT ownership",
            tags: ["On-chain Attestation"],
            description: "Verify that an address owns a specific NFT on Tempo chain. $0.005.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.005000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      address: { type: "string", description: "Wallet address" },
                      nftContract: { type: "string", description: "NFT contract address" },
                      tokenId: { type: "string", description: "Token ID" },
                    },
                    required: ["address", "nftContract", "tokenId"],
                  },
                },
              },
            },
            responses: {
              "200": { description: "Attestation result", content: { "application/json": { schema: { type: "object" } } } },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/attest/onchain/interaction": {
          post: {
            operationId: "attestOnchainInteraction",
            summary: "Verify contract interaction",
            tags: ["On-chain Attestation"],
            description: "Verify that an address has interacted with a specific contract on Tempo chain. $0.005.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.005000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      address: { type: "string", description: "Wallet address" },
                      contractAddress: { type: "string", description: "Contract address" },
                    },
                    required: ["address", "contractAddress"],
                  },
                },
              },
            },
            responses: {
              "200": { description: "Attestation result", content: { "application/json": { schema: { type: "object" } } } },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/stealth/generate-keys": {
          post: {
            operationId: "stealthGenerateKeys",
            summary: "Generate stealth meta-address",
            tags: ["Stealth Addresses"],
            description: "Generate an ERC-5564 stealth meta-address keypair. No input required — returns a fresh keypair. $0.002.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.002000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: false,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      label: { type: "string", description: "Optional label for the keypair" },
                    },
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Stealth keypair generated",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        metaAddress: { type: "string" },
                        spendingPubKey: { type: "string" },
                        viewingPubKey: { type: "string" },
                        spendingKey: { type: "string" },
                        viewingKey: { type: "string" },
                        computeTimeMs: { type: "number" },
                      },
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/stealth/derive-address": {
          post: {
            operationId: "stealthDeriveAddress",
            summary: "Derive one-time stealth address",
            tags: ["Stealth Addresses"],
            description: "Derive a one-time stealth address from a stealth meta-address. $0.002.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.002000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      metaAddress: { type: "string", description: "Stealth meta-address (e.g. 'st:eth:0x...')" },
                    },
                    required: ["metaAddress"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Stealth address derived",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        stealthAddress: { type: "string" },
                        ephemeralPubKey: { type: "string" },
                        computeTimeMs: { type: "number" },
                      },
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/stealth/scan": {
          post: {
            operationId: "stealthScan",
            summary: "Scan for stealth payments",
            tags: ["Stealth Addresses"],
            description: "Scan a list of ephemeral public keys to find stealth payments addressed to you. $0.005.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.005000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      viewingKey: { type: "string", description: "Viewing private key (hex)" },
                      spendingPubKey: { type: "string", description: "Spending public key (hex)" },
                      ephemeralPubKeys: { type: "array", items: { type: "string" }, description: "Ephemeral public keys to scan" },
                    },
                    required: ["viewingKey", "spendingPubKey", "ephemeralPubKeys"],
                  },
                },
              },
            },
            responses: {
              "200": { description: "Scan results", content: { "application/json": { schema: { type: "object" } } } },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/stealth/compute-key": {
          post: {
            operationId: "stealthComputeKey",
            summary: "Recover stealth private key",
            tags: ["Stealth Addresses"],
            description: "Compute the private key for a stealth address using spending key, viewing key, and ephemeral public key. $0.002.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.002000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      spendingKey: { type: "string", description: "Spending private key (hex)" },
                      viewingKey: { type: "string", description: "Viewing private key (hex)" },
                      ephemeralPubKey: { type: "string", description: "Ephemeral public key (hex)" },
                    },
                    required: ["spendingKey", "viewingKey", "ephemeralPubKey"],
                  },
                },
              },
            },
            responses: {
              "200": { description: "Stealth private key computed", content: { "application/json": { schema: { type: "object" } } } },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/merkle/build": {
          post: {
            operationId: "merkleBuild",
            summary: "Build Poseidon Merkle tree",
            tags: ["Merkle Tree"],
            description: "Build a Poseidon Merkle tree from an array of leaves. Returns root and tree data. $0.01.",
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
                      leaves: { type: "array", items: { type: "string" }, description: "Leaf values" },
                      depth: { type: "integer", description: "Tree depth (optional)" },
                    },
                    required: ["leaves"],
                  },
                },
              },
            },
            responses: {
              "200": { description: "Merkle tree built", content: { "application/json": { schema: { type: "object" } } } },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/merkle/prove": {
          post: {
            operationId: "merkleProve",
            summary: "Generate Merkle inclusion proof",
            tags: ["Merkle Tree"],
            description: "Generate a Merkle inclusion proof for a leaf at a given index. $0.005.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.005000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      leaves: { type: "array", items: { type: "string" }, description: "Leaf values" },
                      leafIndex: { type: "integer", description: "Index of the leaf to prove" },
                      depth: { type: "integer", description: "Tree depth (optional)" },
                    },
                    required: ["leaves", "leafIndex"],
                  },
                },
              },
            },
            responses: {
              "200": { description: "Merkle proof generated", content: { "application/json": { schema: { type: "object" } } } },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/merkle/verify": {
          post: {
            operationId: "merkleVerify",
            summary: "Verify Merkle inclusion proof",
            tags: ["Merkle Tree"],
            description: "Verify a Merkle inclusion proof. Free.",
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      root: { type: "string" },
                      leaf: { type: "string" },
                      pathElements: { type: "array", items: { type: "string" } },
                      pathIndices: { type: "array", items: { type: "integer" } },
                    },
                    required: ["root", "leaf", "pathElements", "pathIndices"],
                  },
                },
              },
            },
            responses: {
              "200": { description: "Verification result", content: { "application/json": { schema: { type: "object" } } } },
            },
          },
        },
        "/hash/poseidon": {
          post: {
            operationId: "hashPoseidon",
            summary: "Poseidon hash",
            tags: ["Hash Functions"],
            description: "Compute a ZK-friendly Poseidon hash. $0.001.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.001000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      inputs: { type: "array", items: { type: "string" }, description: "Field element strings to hash" },
                    },
                    required: ["inputs"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Hash result",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        success: { type: "boolean" },
                        hash: { type: "string" },
                        inputCount: { type: "integer" },
                        computeTimeMs: { type: "number" },
                      },
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/hash/mimc": {
          post: {
            operationId: "hashMimc",
            summary: "MiMC sponge hash",
            tags: ["Hash Functions"],
            description: "Compute a MiMC sponge hash (1 or 2 inputs). $0.001.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.001000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      inputs: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 2, description: "1 or 2 field element strings" },
                    },
                    required: ["inputs"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Hash result",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        hash: { type: "string" },
                        algorithm: { type: "string" },
                        inputCount: { type: "integer" },
                        computeTimeMs: { type: "number" },
                      },
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/hash/pedersen": {
          post: {
            operationId: "hashPedersen",
            summary: "Pedersen hash",
            tags: ["Hash Functions"],
            description: "Compute a Pedersen hash over BabyJubJub. $0.001.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.001000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      inputs: { type: "array", items: { type: "string" }, description: "Field element strings" },
                    },
                    required: ["inputs"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Hash result",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        hash: { type: "string" },
                        algorithm: { type: "string" },
                        inputCount: { type: "integer" },
                        computeTimeMs: { type: "number" },
                      },
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/hash/keccak256": {
          post: {
            operationId: "hashKeccak256",
            summary: "Keccak256 hash",
            tags: ["Hash Functions"],
            description: "Compute an Ethereum-compatible Keccak256 hash. Accepts hex (0x...) or plaintext. $0.001.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.001000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      data: { type: "string", description: "Hex string (0x...) or plaintext to hash" },
                    },
                    required: ["data"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Hash result",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        hash: { type: "string" },
                        algorithm: { type: "string" },
                        inputSize: { type: "integer" },
                        computeTimeMs: { type: "number" },
                      },
                    },
                  },
                },
              },
              "402": { description: "Payment Required" },
            },
          },
        },
        "/proof/compress": {
          post: {
            operationId: "proofCompress",
            summary: "Compress proof + Solidity calldata",
            tags: ["Proof Tools"],
            description: "Compress a Groth16 proof to minimal 256-byte format and generate Solidity calldata. $0.002.",
            "x-payment-info": {
              pricingMode: "fixed",
              price: "0.002000",
              protocols: ["x402", "mpp"],
            },
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      proof: { type: "object", description: "Groth16 proof with pi_a, pi_b, pi_c" },
                      publicSignals: { type: "array", items: { type: "string" } },
                    },
                    required: ["proof", "publicSignals"],
                  },
                },
              },
            },
            responses: {
              "200": {
                description: "Compressed proof",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        compressed: { type: "string" },
                        solidityCalldata: { type: "string" },
                        format: { type: "string" },
                        originalSize: { type: "integer" },
                        compressedSize: { type: "integer" },
                        compressionRatio: { type: "string" },
                        computeTimeMs: { type: "number" },
                      },
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
        "POST /prove/batch",
        "POST /privacy/deposit",
        "POST /privacy/transfer",
        "POST /privacy/withdraw",
        "POST /attest/zk/balance-gt",
        "POST /attest/commitment",
        "POST /attest/balance-gt",
        "POST /attest/range",
        "POST /attest/membership",
        "POST /attest/onchain/balance",
        "POST /attest/onchain/nft",
        "POST /attest/onchain/interaction",
        "POST /stealth/generate-keys",
        "POST /stealth/derive-address",
        "POST /stealth/scan",
        "POST /stealth/compute-key",
        "POST /merkle/build",
        "POST /merkle/prove",
        "POST /hash/poseidon",
        "POST /hash/mimc",
        "POST /hash/pedersen",
        "POST /hash/keccak256",
        "POST /proof/compress",
      ],
      description: "ZKProver: Full-stack ZK proving service via MPP. ZK Proving: /prove/1x2 ($0.01), /prove/2x2 ($0.02), /prove/batch ($0.008/proof). Privacy: /privacy/deposit, /transfer, /withdraw ($0.03 each). ZK Attestation: /attest/zk/balance-gt ($0.01). Credential Attestation: /attest/commitment ($0.001), /attest/balance-gt, /attest/range, /attest/membership ($0.005 each). On-chain Attestation: /attest/onchain/balance, /nft, /interaction ($0.005 each). Stealth Addresses: /stealth/generate-keys, /derive-address, /compute-key ($0.002 each), /stealth/scan ($0.005). Merkle: /merkle/build ($0.01), /merkle/prove ($0.005). Hashing: /hash/poseidon, /mimc, /pedersen, /keccak256 ($0.001 each). Proof Tools: /proof/compress ($0.002). Verification endpoints free.",
    })
  );

  // LLMs.txt (free)
  app.get("/llms.txt", (c) => {
    c.header("Content-Type", "text/plain");
    return c.body(`# ZKProver
> Full-stack zero-knowledge proving service via Tempo MPP. ZK proofs, privacy transactions, stealth addresses, attestations, Merkle trees, and ZK-friendly hashing.

## Live
https://himess-zk-proof-service.hf.space

## Discovery
- GET /health — Health check (free)
- GET /circuits — List circuits and pricing (free)
- GET /pool — Privacy pool info (free)
- GET /openapi.json — OpenAPI 3.1 spec (free)
- GET /.well-known/x402 — x402 resource list (free)

## ZK Proving
- POST /prove/1x2 — Generate Groth16 proof, 1x2 JoinSplit ($0.01)
- POST /prove/2x2 — Generate Groth16 proof, 2x2 JoinSplit ($0.02)
- POST /prove/batch — Batch proof generation, 20% discount ($0.008/proof)
- POST /verify/:circuit — Verify a proof (free)

## Privacy Proofs
- POST /privacy/deposit — Shielded deposit proof ($0.03)
- POST /privacy/transfer — Private transfer proof ($0.03)
- POST /privacy/withdraw — Withdrawal proof ($0.03)

## ZK Attestation
- POST /attest/zk/balance-gt — ZK proof: balance > threshold ($0.01)
- POST /attest/zk/verify — Verify ZK attestation (free)

## Credential Attestation
- POST /attest/commitment — Create Poseidon commitment ($0.001)
- POST /attest/balance-gt — Attest balance > threshold ($0.005)
- POST /attest/range — Attest value in range ($0.005)
- POST /attest/membership — Attest set membership ($0.005)
- POST /attest/verify — Verify attestation (free)

## On-chain Attestation (Tempo)
- POST /attest/onchain/balance — Verify token balance on Tempo ($0.005)
- POST /attest/onchain/nft — Verify NFT ownership ($0.005)
- POST /attest/onchain/interaction — Verify contract interaction ($0.005)

## Stealth Addresses
- POST /stealth/generate-keys — Generate stealth meta-address keypair ($0.002)
- POST /stealth/derive-address — Derive one-time stealth address ($0.002)
- POST /stealth/scan — Scan for stealth payments ($0.005)
- POST /stealth/compute-key — Recover stealth private key ($0.002)

## Merkle Tree
- POST /merkle/build — Build Poseidon Merkle tree ($0.01)
- POST /merkle/prove — Generate inclusion proof ($0.005)
- POST /merkle/verify — Verify inclusion proof (free)

## Hash Functions
- POST /hash/poseidon — Poseidon hash ($0.001)
- POST /hash/mimc — MiMC sponge hash ($0.001)
- POST /hash/pedersen — Pedersen hash ($0.001)
- POST /hash/keccak256 — Keccak256 hash ($0.001)

## Proof Tools
- POST /proof/compress — Compress proof + Solidity calldata ($0.002)

## Pricing
- ZK proving: $0.01-$0.02/proof, batch $0.008/proof
- Privacy proofs: $0.03/proof
- ZK attestation: $0.01/proof
- Credential attestation: $0.001-$0.005
- On-chain attestation: $0.005
- Stealth addresses: $0.002-$0.005
- Merkle operations: $0.005-$0.01
- Hash functions: $0.001
- Proof compression: $0.002
- Verification endpoints: free
- Payment: USDC via Tempo MPP (automatic 402 flow)

## What This Does
Full-stack ZK cryptography service with 30+ endpoints. Generates Groth16 proofs for JoinSplit circuits, privacy-preserving deposits/transfers/withdrawals, ZK balance attestations, credential attestations, on-chain state verification, ERC-5564 stealth addresses, Poseidon Merkle trees, and multiple ZK-friendly hash functions. Returns proofs, public signals, and Solidity-ready calldata. Proof generation: ~2-5s. Verification: ~50ms. BN254 curve.

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

    // Register all additional routes with MPP
    registerMerkleRoutes(app, mppx);
    registerAttestationRoutes(app, mppx);
    registerBatchRoutes(app, mppx);
    registerHashRoutes(app, mppx);
    registerCompressionRoutes(app, mppx);
    registerStealthRoutes(app, mppx);
    registerOnchainRoutes(app, mppx);
    registerZkAttestationRoutes(app, mppx);

    console.log("MPP payment gating enabled");
  } catch (e) {
    console.warn("mppx not available, running free:", (e as Error).message);
    app.post("/prove/1x2", handleProve);
    app.post("/prove/2x2", handleProve);
    app.post("/privacy/deposit", handleDeposit);
    app.post("/privacy/transfer", handleTransfer);
    app.post("/privacy/withdraw", handleWithdraw);

    // Register all additional routes without MPP
    registerMerkleRoutes(app);
    registerAttestationRoutes(app);
    registerBatchRoutes(app);
    registerHashRoutes(app);
    registerCompressionRoutes(app);
    registerStealthRoutes(app);
    registerOnchainRoutes(app);
    registerZkAttestationRoutes(app);
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
    console.log(`\n30+ Endpoints:`);
    console.log(`  Discovery:`);
    console.log(`    GET  /health                    — Health check (free)`);
    console.log(`    GET  /circuits                  — List circuits (free)`);
    console.log(`    GET  /pool                      — Privacy pool info (free)`);
    console.log(`    GET  /openapi.json              — OpenAPI spec (free)`);
    console.log(`    GET  /llms.txt                  — Agent discovery (free)`);
    console.log(`  ZK Proving:`);
    console.log(`    POST /prove/1x2                 — 1x2 proof ($0.01)`);
    console.log(`    POST /prove/2x2                 — 2x2 proof ($0.02)`);
    console.log(`    POST /prove/batch               — Batch proofs ($0.008/proof)`);
    console.log(`    POST /verify/:circuit           — Verify proof (free)`);
    console.log(`  Privacy:`);
    console.log(`    POST /privacy/deposit           — Shielded deposit ($0.03)`);
    console.log(`    POST /privacy/transfer          — Private transfer ($0.03)`);
    console.log(`    POST /privacy/withdraw          — Withdrawal ($0.03)`);
    console.log(`  ZK Attestation:`);
    console.log(`    POST /attest/zk/balance-gt      — ZK balance proof ($0.01)`);
    console.log(`    POST /attest/zk/verify          — Verify ZK attestation (free)`);
    console.log(`  Credential Attestation:`);
    console.log(`    POST /attest/commitment         — Poseidon commitment ($0.001)`);
    console.log(`    POST /attest/balance-gt         — Balance attestation ($0.005)`);
    console.log(`    POST /attest/range              — Range attestation ($0.005)`);
    console.log(`    POST /attest/membership         — Membership attestation ($0.005)`);
    console.log(`    POST /attest/verify             — Verify attestation (free)`);
    console.log(`  On-chain Attestation:`);
    console.log(`    POST /attest/onchain/balance    — Token balance ($0.005)`);
    console.log(`    POST /attest/onchain/nft        — NFT ownership ($0.005)`);
    console.log(`    POST /attest/onchain/interaction — Contract interaction ($0.005)`);
    console.log(`  Stealth Addresses:`);
    console.log(`    POST /stealth/generate-keys     — Generate keys ($0.002)`);
    console.log(`    POST /stealth/derive-address    — Derive address ($0.002)`);
    console.log(`    POST /stealth/scan              — Scan payments ($0.005)`);
    console.log(`    POST /stealth/compute-key       — Compute key ($0.002)`);
    console.log(`  Merkle Tree:`);
    console.log(`    POST /merkle/build              — Build tree ($0.01)`);
    console.log(`    POST /merkle/prove              — Inclusion proof ($0.005)`);
    console.log(`    POST /merkle/verify             — Verify proof (free)`);
    console.log(`  Hash Functions:`);
    console.log(`    POST /hash/poseidon             — Poseidon ($0.001)`);
    console.log(`    POST /hash/mimc                 — MiMC ($0.001)`);
    console.log(`    POST /hash/pedersen             — Pedersen ($0.001)`);
    console.log(`    POST /hash/keccak256            — Keccak256 ($0.001)`);
    console.log(`  Proof Tools:`);
    console.log(`    POST /proof/compress            — Compress proof ($0.002)`);
  });
}

main().catch(console.error);
