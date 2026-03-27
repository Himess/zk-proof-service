/**
 * Merkle tree HTTP routes for the ZK proof service.
 *
 * Registers endpoints on an existing Hono app:
 *   POST /merkle/build   — Build a Merkle tree from leaves         ($0.01)
 *   POST /merkle/prove   — Generate a Merkle inclusion proof       ($0.005)
 *   POST /merkle/verify  — Verify a Merkle inclusion proof         (free)
 *   POST /hash/poseidon  — Compute a Poseidon hash                 ($0.001)
 *
 * Import and call `registerMerkleRoutes(app)` from server.ts to wire them up.
 */

import type { Hono } from "hono";
import {
  buildMerkleTree,
  generateMerkleProof,
  verifyMerkleProof,
  poseidonHash,
} from "./merkle.js";

export function registerMerkleRoutes(app: Hono, mppx?: any) {
  // ── Helper: optionally wrap handler with MPP charge ───────────────────────
  const charge = (amount: string, description: string) =>
    mppx
      ? mppx.charge({ amount, description })
      : (_c: any, next: () => Promise<void>) => next();

  // ── POST /merkle/build ────────────────────────────────────────────────────
  app.post(
    "/merkle/build",
    charge("0.01", "Build Merkle tree"),
    async (c) => {
      let body: { leaves: string[]; depth?: number };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (!Array.isArray(body.leaves) || body.leaves.length === 0) {
        return c.json(
          { error: "Body must contain a non-empty 'leaves' array of strings" },
          400,
        );
      }

      try {
        const start = Date.now();
        const result = await buildMerkleTree(body.leaves, body.depth);
        const elapsed = Date.now() - start;
        return c.json({ success: true, ...result, computeTimeMs: elapsed });
      } catch (e) {
        return c.json(
          { error: "Failed to build Merkle tree", details: (e as Error).message },
          500,
        );
      }
    },
  );

  // ── POST /merkle/prove ────────────────────────────────────────────────────
  app.post(
    "/merkle/prove",
    charge("0.005", "Generate Merkle inclusion proof"),
    async (c) => {
      let body: { leaves: string[]; leafIndex: number; depth?: number };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (!Array.isArray(body.leaves) || body.leaves.length === 0) {
        return c.json(
          { error: "Body must contain a non-empty 'leaves' array" },
          400,
        );
      }
      if (typeof body.leafIndex !== "number") {
        return c.json(
          { error: "Body must contain a numeric 'leafIndex'" },
          400,
        );
      }

      try {
        const start = Date.now();
        const result = await generateMerkleProof(
          body.leaves,
          body.leafIndex,
          body.depth,
        );
        const elapsed = Date.now() - start;
        return c.json({ success: true, ...result, computeTimeMs: elapsed });
      } catch (e) {
        return c.json(
          {
            error: "Failed to generate proof",
            details: (e as Error).message,
          },
          500,
        );
      }
    },
  );

  // ── POST /merkle/verify ───────────────────────────────────────────────────
  app.post("/merkle/verify", async (c) => {
    let body: {
      root: string;
      leaf: string;
      pathElements: string[];
      pathIndices: number[];
    };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }

    if (!body.root || !body.leaf || !body.pathElements || !body.pathIndices) {
      return c.json(
        {
          error:
            "Body must contain 'root', 'leaf', 'pathElements', and 'pathIndices'",
        },
        400,
      );
    }

    try {
      const start = Date.now();
      const result = await verifyMerkleProof(
        body.root,
        body.leaf,
        body.pathElements,
        body.pathIndices,
      );
      const elapsed = Date.now() - start;
      return c.json({ success: true, ...result, computeTimeMs: elapsed });
    } catch (e) {
      return c.json(
        { error: "Verification failed", details: (e as Error).message },
        500,
      );
    }
  });

  // ── POST /hash/poseidon ───────────────────────────────────────────────────
  app.post(
    "/hash/poseidon",
    charge("0.001", "Poseidon hash"),
    async (c) => {
      let body: { inputs: string[] };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (!Array.isArray(body.inputs) || body.inputs.length === 0) {
        return c.json(
          { error: "Body must contain a non-empty 'inputs' array of strings" },
          400,
        );
      }

      try {
        const start = Date.now();
        const hash = await poseidonHash(body.inputs);
        const elapsed = Date.now() - start;
        return c.json({
          success: true,
          hash,
          inputCount: body.inputs.length,
          computeTimeMs: elapsed,
        });
      } catch (e) {
        return c.json(
          { error: "Hash computation failed", details: (e as Error).message },
          500,
        );
      }
    },
  );
}
