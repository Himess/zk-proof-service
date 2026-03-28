/**
 * Batch proving HTTP routes for the ZK proof service.
 *
 * Registers endpoint on an existing Hono app:
 *   POST /prove/batch — Batch proof generation (20% discount: $0.008/proof)
 *
 * Import and call `registerBatchRoutes(app, mppx?)` from server.ts to wire up.
 */

import type { Hono } from "hono";
import { generateProof, formatProofForContract } from "./prover.js";
import type { CircuitType } from "./prover.js";

export function registerBatchRoutes(app: Hono, mppx?: any) {
  // Helper: optionally wrap handler with MPP charge
  const charge = (amount: string, description: string) =>
    mppx
      ? mppx.charge({ amount, description })
      : (_c: any, next: () => Promise<void>) => next();

  // ── POST /prove/batch ─────────────────────────────────────────────────────
  app.post(
    "/prove/batch",
    charge("0.008", "Batch ZK proof (per-proof, applied after count validation)"),
    async (c) => {
      let body: { circuit: string; inputs: Record<string, unknown>[] };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      // Validate circuit type
      const circuit = body.circuit as CircuitType;
      if (circuit !== "1x2" && circuit !== "2x2") {
        return c.json(
          { error: "Invalid circuit type. Use '1x2' or '2x2'" },
          400,
        );
      }

      // Validate inputs array
      if (!Array.isArray(body.inputs)) {
        return c.json(
          { error: "Body must contain an 'inputs' array of circuit input objects" },
          400,
        );
      }

      const count = body.inputs.length;
      if (count < 2) {
        return c.json(
          { error: "Batch requires at least 2 inputs (use /prove/:circuit for single proofs)" },
          400,
        );
      }
      if (count > 20) {
        return c.json(
          { error: "Batch is limited to 20 proofs maximum" },
          400,
        );
      }

      // Generate proofs sequentially (parallel would OOM on free tier)
      const batchStart = Date.now();
      const results: {
        proof: any;
        publicSignals: string[];
        contractProof: string[];
        generationTimeMs: number;
      }[] = [];

      try {
        for (let i = 0; i < count; i++) {
          const input = body.inputs[i];
          if (!input || typeof input !== "object") {
            return c.json(
              { error: `Input at index ${i} must be a JSON object` },
              400,
            );
          }

          console.log(`Batch proof ${i + 1}/${count} (${circuit})...`);
          const result = await generateProof(circuit, input);
          const contractProof = formatProofForContract(result.proof);
          results.push({
            proof: result.proof,
            publicSignals: result.publicSignals,
            contractProof,
            generationTimeMs: result.generationTimeMs,
          });
        }
      } catch (e) {
        return c.json(
          {
            error: "Batch proof generation failed",
            details: (e as Error).message,
            completedCount: results.length,
          },
          500,
        );
      }

      const totalTimeMs = Date.now() - batchStart;
      const pricePerProof = 0.008;
      const regularPricePerProof = 0.01;
      const totalPrice = count * pricePerProof;
      const regularPrice = count * regularPricePerProof;

      console.log(
        `Batch complete: ${count} proofs in ${totalTimeMs}ms ($${totalPrice.toFixed(3)} vs $${regularPrice.toFixed(2)} individual)`,
      );

      return c.json({
        success: true,
        circuit,
        results,
        totalTimeMs,
        count,
        pricing: {
          perProof: `$${pricePerProof}`,
          total: `$${totalPrice.toFixed(3)}`,
          regularTotal: `$${regularPrice.toFixed(2)}`,
          savings: "20% discount",
        },
      });
    },
  );
}
