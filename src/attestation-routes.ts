/**
 * ZK Credential Attestation HTTP routes.
 *
 * Registers endpoints on an existing Hono app:
 *   POST /attest/commitment   — Create a Poseidon commitment       ($0.001)
 *   POST /attest/balance-gt   — Prove balance > threshold           ($0.005)
 *   POST /attest/range        — Prove value in [min, max]           ($0.005)
 *   POST /attest/membership   — Prove membership in a Merkle set    ($0.005)
 *   POST /attest/verify       — Verify an attestation signature     (free)
 *
 * Import and call `registerAttestationRoutes(app)` from server.ts.
 */

import type { Hono } from "hono";
import {
  createCommitment,
  verifyCommitment,
  attestBalanceGT,
  attestRange,
  attestMembership,
  verifyAttestationSignature,
} from "./attestation.js";

export function registerAttestationRoutes(app: Hono, mppx?: any) {
  // ── Helper: optionally wrap handler with MPP charge ───────────────────────
  const charge = (amount: string, description: string) =>
    mppx
      ? mppx.charge({ amount, description })
      : (_c: any, next: () => Promise<void>) => next();

  // ── POST /attest/commitment ───────────────────────────────────────────────
  app.post(
    "/attest/commitment",
    charge("0.001", "Create Poseidon commitment"),
    async (c) => {
      let body: { value: string; blinding: string };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (!body.value || !body.blinding) {
        return c.json(
          { error: "Missing required fields: value, blinding" },
          400,
        );
      }

      try {
        const start = Date.now();
        const commitment = await createCommitment(body.value, body.blinding);
        const elapsed = Date.now() - start;
        return c.json({
          commitment,
          value: body.value,
          computeTimeMs: elapsed,
        });
      } catch (e) {
        return c.json(
          {
            error: "Failed to create commitment",
            details: (e as Error).message,
          },
          500,
        );
      }
    },
  );

  // ── POST /attest/balance-gt ───────────────────────────────────────────────
  app.post(
    "/attest/balance-gt",
    charge("0.005", "Attest balance > threshold"),
    async (c) => {
      let body: {
        commitment: string;
        value: string;
        blinding: string;
        threshold: string;
      };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (!body.commitment || !body.value || !body.blinding || !body.threshold) {
        return c.json(
          {
            error:
              "Missing required fields: commitment, value, blinding, threshold",
          },
          400,
        );
      }

      try {
        const start = Date.now();
        const result = await attestBalanceGT(
          body.commitment,
          body.value,
          body.blinding,
          body.threshold,
        );
        const elapsed = Date.now() - start;
        return c.json({ ...result, computeTimeMs: elapsed });
      } catch (e) {
        return c.json(
          {
            error: "Attestation failed",
            details: (e as Error).message,
          },
          400,
        );
      }
    },
  );

  // ── POST /attest/range ────────────────────────────────────────────────────
  app.post(
    "/attest/range",
    charge("0.005", "Attest value in range"),
    async (c) => {
      let body: {
        commitment: string;
        value: string;
        blinding: string;
        min: string;
        max: string;
      };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (
        !body.commitment ||
        body.value === undefined ||
        !body.blinding ||
        body.min === undefined ||
        body.max === undefined
      ) {
        return c.json(
          {
            error:
              "Missing required fields: commitment, value, blinding, min, max",
          },
          400,
        );
      }

      try {
        const start = Date.now();
        const result = await attestRange(
          body.commitment,
          body.value,
          body.blinding,
          body.min,
          body.max,
        );
        const elapsed = Date.now() - start;
        return c.json({ ...result, computeTimeMs: elapsed });
      } catch (e) {
        return c.json(
          {
            error: "Attestation failed",
            details: (e as Error).message,
          },
          400,
        );
      }
    },
  );

  // ── POST /attest/membership ───────────────────────────────────────────────
  app.post(
    "/attest/membership",
    charge("0.005", "Attest set membership"),
    async (c) => {
      let body: {
        commitment: string;
        value: string;
        blinding: string;
        leaves: string[];
      };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (
        !body.commitment ||
        !body.value ||
        !body.blinding ||
        !Array.isArray(body.leaves) ||
        body.leaves.length === 0
      ) {
        return c.json(
          {
            error:
              "Missing required fields: commitment, value, blinding, leaves (non-empty array)",
          },
          400,
        );
      }

      try {
        const start = Date.now();
        const result = await attestMembership(
          body.commitment,
          body.value,
          body.blinding,
          body.leaves,
        );
        const elapsed = Date.now() - start;
        return c.json({ ...result, computeTimeMs: elapsed });
      } catch (e) {
        return c.json(
          {
            error: "Attestation failed",
            details: (e as Error).message,
          },
          400,
        );
      }
    },
  );

  // ── POST /attest/verify ───────────────────────────────────────────────────
  app.post("/attest/verify", async (c) => {
    let body: { attestation: Record<string, unknown> };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }

    if (!body.attestation || typeof body.attestation !== "object") {
      return c.json(
        { error: "Missing required field: attestation (object)" },
        400,
      );
    }

    try {
      const valid = verifyAttestationSignature(body.attestation);
      return c.json({ valid });
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
