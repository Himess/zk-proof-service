/**
 * Proof compression HTTP routes for the ZK proof service.
 *
 * Registers endpoint on an existing Hono app:
 *   POST /proof/compress — Compress Groth16 proof to minimal format ($0.002)
 *
 * Import and call `registerCompressionRoutes(app, mppx?)` from server.ts to wire up.
 */

import type { Hono } from "hono";

interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol?: string;
  curve?: string;
}

/**
 * Compress a Groth16 proof by concatenating the 8 key field elements as
 * 32-byte big-endian hex values:
 *   pi_a[0], pi_a[1], pi_b[0][0], pi_b[0][1], pi_b[1][0], pi_b[1][1], pi_c[0], pi_c[1]
 */
function compressProof(proof: Groth16Proof): string {
  const elements = [
    proof.pi_a[0],
    proof.pi_a[1],
    proof.pi_b[0][0],
    proof.pi_b[0][1],
    proof.pi_b[1][0],
    proof.pi_b[1][1],
    proof.pi_c[0],
    proof.pi_c[1],
  ];

  // Each element is a decimal string; convert to 32-byte (256-bit) hex
  const hexParts = elements.map((el) => {
    const n = BigInt(el);
    return n.toString(16).padStart(64, "0");
  });

  return "0x" + hexParts.join("");
}

export function registerCompressionRoutes(app: Hono, mppx?: any) {
  // Helper: optionally wrap handler with MPP charge
  const charge = (amount: string, description: string) =>
    mppx
      ? mppx.charge({ amount, description })
      : (_c: any, next: () => Promise<void>) => next();

  // ── POST /proof/compress ──────────────────────────────────────────────────
  app.post(
    "/proof/compress",
    charge("0.002", "Compress Groth16 proof"),
    async (c) => {
      let body: { proof: Groth16Proof; publicSignals: string[] };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      // Validate proof structure
      if (!body.proof || typeof body.proof !== "object") {
        return c.json(
          { error: "Body must contain a 'proof' object with pi_a, pi_b, pi_c" },
          400,
        );
      }

      const { proof } = body;
      if (
        !Array.isArray(proof.pi_a) || proof.pi_a.length < 2 ||
        !Array.isArray(proof.pi_b) || proof.pi_b.length < 2 ||
        !Array.isArray(proof.pi_c) || proof.pi_c.length < 2
      ) {
        return c.json(
          { error: "Invalid proof structure: need pi_a[2], pi_b[2][2], pi_c[2]" },
          400,
        );
      }

      if (
        !Array.isArray(proof.pi_b[0]) || proof.pi_b[0].length < 2 ||
        !Array.isArray(proof.pi_b[1]) || proof.pi_b[1].length < 2
      ) {
        return c.json(
          { error: "Invalid proof structure: pi_b must be a 2x2 array" },
          400,
        );
      }

      if (!Array.isArray(body.publicSignals)) {
        return c.json(
          { error: "Body must contain a 'publicSignals' array of strings" },
          400,
        );
      }

      try {
        const start = Date.now();

        // Compute original size (JSON representation)
        const originalJson = JSON.stringify({ proof, publicSignals: body.publicSignals });
        const originalSize = Buffer.byteLength(originalJson, "utf-8");

        // Compressed proof: 8 x 32 bytes = 256 bytes
        const compressed = compressProof(proof);
        const compressedSize = (compressed.length - 2) / 2; // subtract "0x", each 2 hex chars = 1 byte

        // Solidity calldata via snarkjs
        let solidityCalldata: string;
        try {
          // @ts-ignore - snarkjs has no types
          const snarkjs = await import("snarkjs");
          const calldataStr = await snarkjs.groth16.exportSolidityCallData(
            proof,
            body.publicSignals,
          );
          // exportSolidityCallData returns a string like:
          // ["0x..","0x.."],  [["0x..","0x.."],["0x..","0x.."]],  ["0x..","0x.."],  ["0x..","0x.."]
          // We wrap it for direct use as calldata
          solidityCalldata = "0x" + Buffer.from(calldataStr, "utf-8").toString("hex");
        } catch (e) {
          // Fall back: return the compressed form as calldata
          solidityCalldata = compressed;
        }

        const elapsed = Date.now() - start;

        return c.json({
          compressed,
          solidityCalldata,
          format: "groth16-bn254-compressed",
          originalSize,
          compressedSize,
          compressionRatio: `${((1 - compressedSize / originalSize) * 100).toFixed(1)}%`,
          computeTimeMs: elapsed,
        });
      } catch (e) {
        return c.json(
          { error: "Proof compression failed", details: (e as Error).message },
          500,
        );
      }
    },
  );
}
