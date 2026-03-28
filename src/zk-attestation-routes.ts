/**
 * ZK Attestation HTTP routes — Real zero-knowledge proofs using Groth16.
 *
 * Unlike the HMAC-based attestation routes which require trusting the server,
 * these routes generate cryptographic ZK proofs that ANYONE can verify
 * independently — no trust required.
 *
 * Registers endpoints on an existing Hono app:
 *   POST /attest/zk/balance-gt — ZK proof that committed balance > threshold ($0.01)
 *   POST /attest/zk/verify     — Verify a ZK attestation proof             (free)
 *
 * Import and call `registerZkAttestationRoutes(app, mppx?)` from server.ts.
 */

import type { Hono } from "hono";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
// @ts-ignore - snarkjs has no types
import * as snarkjs from "snarkjs";
import { initPoseidon } from "./crypto.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ATTESTATION_CIRCUIT_DIR = path.resolve(
  __dirname,
  "../circuits/attestation",
);

// Artifact paths for the BalanceGT circuit
const BALANCE_GT_WASM = path.join(
  ATTESTATION_CIRCUIT_DIR,
  "balance_gt_js",
  "balance_gt.wasm",
);
const BALANCE_GT_ZKEY = path.join(
  ATTESTATION_CIRCUIT_DIR,
  "balance_gt_final.zkey",
);
const BALANCE_GT_VKEY_PATH = path.join(
  ATTESTATION_CIRCUIT_DIR,
  "verification_key.json",
);

// Cache the verification key in memory after first load
let cachedVKey: Record<string, unknown> | null = null;

function loadVerificationKey(): Record<string, unknown> {
  if (cachedVKey) return cachedVKey;
  if (!fs.existsSync(BALANCE_GT_VKEY_PATH)) {
    throw new Error(
      `Verification key not found: ${BALANCE_GT_VKEY_PATH}. ` +
        "Run the trusted setup first (see circuits/attestation/).",
    );
  }
  cachedVKey = JSON.parse(fs.readFileSync(BALANCE_GT_VKEY_PATH, "utf-8"));
  return cachedVKey!;
}

/**
 * Check that all required circuit artifacts exist.
 * Returns null if everything is OK, or an error message string.
 */
function checkArtifacts(): string | null {
  if (!fs.existsSync(BALANCE_GT_WASM)) {
    return `Circuit WASM not found: ${BALANCE_GT_WASM}. Compile the circuit first.`;
  }
  if (!fs.existsSync(BALANCE_GT_ZKEY)) {
    return `Circuit zkey not found: ${BALANCE_GT_ZKEY}. Run the trusted setup first.`;
  }
  if (!fs.existsSync(BALANCE_GT_VKEY_PATH)) {
    return `Verification key not found: ${BALANCE_GT_VKEY_PATH}. Export the verification key first.`;
  }
  return null;
}

export function registerZkAttestationRoutes(app: Hono, mppx?: any) {
  // ── Helper: optionally wrap handler with MPP charge ───────────────────
  const charge = (amount: string, description: string) =>
    mppx
      ? mppx.charge({ amount, description })
      : (_c: any, next: () => Promise<void>) => next();

  // ── POST /attest/zk/balance-gt ────────────────────────────────────────
  // Input:  { value: string, blinding: string, threshold: string }
  // Output: { proof, publicSignals, commitment, verified, generationTimeMs }
  //
  // The server computes the Poseidon commitment from (value, blinding),
  // generates a Groth16 ZK proof that value > threshold, and returns the
  // proof along with the public signals [commitment, threshold].
  //
  // The private inputs (value, blinding) are NEVER included in the output.
  // Anyone can verify the proof using only the public signals and the
  // verification key — no trust in this server is required.
  app.post(
    "/attest/zk/balance-gt",
    charge("0.01", "ZK proof: balance > threshold"),
    async (c) => {
      // Check artifacts are available
      const artifactError = checkArtifacts();
      if (artifactError) {
        return c.json({ error: artifactError }, 503);
      }

      let body: { value: string; blinding: string; threshold: string };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (!body.value || !body.blinding || !body.threshold) {
        return c.json(
          { error: "Missing required fields: value, blinding, threshold" },
          400,
        );
      }

      // Validate inputs are valid integers
      try {
        BigInt(body.value);
        BigInt(body.blinding);
        BigInt(body.threshold);
      } catch {
        return c.json(
          { error: "All fields must be valid integer strings" },
          400,
        );
      }

      // Quick sanity check: value must actually be > threshold
      if (BigInt(body.value) <= BigInt(body.threshold)) {
        return c.json(
          {
            error:
              "Cannot generate proof: value is not greater than threshold. " +
              "The ZK circuit will reject this witness.",
          },
          400,
        );
      }

      try {
        // 1. Compute commitment = Poseidon(value, blinding)
        const poseidon = await initPoseidon();
        const commitment = poseidon
          .hash2(BigInt(body.value), BigInt(body.blinding))
          .toString();

        // 2. Generate ZK proof
        const circuitInput = {
          commitment,
          threshold: body.threshold,
          value: body.value,
          blinding: body.blinding,
        };

        const start = Date.now();
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
          circuitInput,
          BALANCE_GT_WASM,
          BALANCE_GT_ZKEY,
        );
        const generationTimeMs = Date.now() - start;

        // 3. Verify proof server-side (sanity check before returning)
        const vkey = loadVerificationKey();
        const verified = await snarkjs.groth16.verify(
          vkey,
          publicSignals,
          proof,
        );

        return c.json({
          proof,
          publicSignals,
          commitment,
          threshold: body.threshold,
          verified,
          generationTimeMs,
          circuit: "BalanceGT(64)",
          protocol: "groth16",
          curve: "bn128",
        });
      } catch (e) {
        return c.json(
          {
            error: "ZK proof generation failed",
            details: (e as Error).message,
          },
          500,
        );
      }
    },
  );

  // ── POST /attest/zk/verify ────────────────────────────────────────────
  // Input:  { proof, publicSignals }
  // Output: { valid: boolean, verificationTimeMs: number }
  //
  // Verifies a Groth16 ZK proof against the BalanceGT verification key.
  // This is FREE — verification is fast and allows anyone to check proofs.
  app.post("/attest/zk/verify", async (c) => {
    const artifactError = checkArtifacts();
    if (artifactError) {
      return c.json({ error: artifactError }, 503);
    }

    let body: { proof: unknown; publicSignals: string[] };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }

    if (!body.proof || !Array.isArray(body.publicSignals)) {
      return c.json(
        {
          error:
            "Missing required fields: proof (object), publicSignals (array)",
        },
        400,
      );
    }

    if (body.publicSignals.length !== 2) {
      return c.json(
        {
          error:
            "publicSignals must have exactly 2 elements: [commitment, threshold]",
        },
        400,
      );
    }

    try {
      const vkey = loadVerificationKey();

      const start = Date.now();
      const valid = await snarkjs.groth16.verify(
        vkey,
        body.publicSignals,
        body.proof,
      );
      const verificationTimeMs = Date.now() - start;

      return c.json({
        valid,
        verificationTimeMs,
        publicSignals: {
          commitment: body.publicSignals[0],
          threshold: body.publicSignals[1],
        },
      });
    } catch (e) {
      return c.json(
        {
          error: "Verification failed",
          details: (e as Error).message,
        },
        500,
      );
    }
  });
}
