/**
 * Additional hash function HTTP routes for the ZK proof service.
 *
 * Registers endpoints on an existing Hono app:
 *   POST /hash/mimc     — MiMC sponge hash   ($0.001)
 *   POST /hash/pedersen — Pedersen hash       ($0.001)
 *   POST /hash/keccak256 — Keccak256 hash     ($0.001)
 *
 * Import and call `registerHashRoutes(app, mppx?)` from server.ts to wire up.
 */

import type { Hono } from "hono";

// Lazy-loaded circomlibjs instances
let mimcSpongeInstance: any = null;
let pedersenInstance: any = null;
let babyJubInstance: any = null;

async function getMimc() {
  if (mimcSpongeInstance) return mimcSpongeInstance;
  const { buildMimcSponge } = await import("circomlibjs");
  mimcSpongeInstance = await buildMimcSponge();
  return mimcSpongeInstance;
}

async function getPedersen() {
  if (pedersenInstance && babyJubInstance) {
    return { pedersen: pedersenInstance, babyJub: babyJubInstance };
  }
  const { buildPedersenHash, buildBabyjub } = await import("circomlibjs");
  pedersenInstance = await buildPedersenHash();
  babyJubInstance = await buildBabyjub();
  return { pedersen: pedersenInstance, babyJub: babyJubInstance };
}

export function registerHashRoutes(app: Hono, mppx?: any) {
  // Helper: optionally wrap handler with MPP charge
  const charge = (amount: string, description: string) =>
    mppx
      ? mppx.charge({ amount, description })
      : (_c: any, next: () => Promise<void>) => next();

  // ── POST /hash/mimc ─────────────────────────────────────────────────────
  app.post(
    "/hash/mimc",
    charge("0.001", "MiMC sponge hash"),
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

      if (body.inputs.length > 2) {
        return c.json(
          { error: "MiMC sponge accepts 1 or 2 inputs" },
          400,
        );
      }

      try {
        const start = Date.now();
        const mimc = await getMimc();

        // MiMC sponge: multiHash takes an array of field elements and a key (0)
        // For 2 inputs we use them directly; for 1 input we hash with a single element
        const fieldInputs = body.inputs.map((v) => BigInt(v));
        const result = mimc.multiHash(fieldInputs, BigInt(0), 1);
        const hash = mimc.F.toObject(result).toString();

        const elapsed = Date.now() - start;
        return c.json({
          hash,
          algorithm: "mimc",
          inputCount: body.inputs.length,
          computeTimeMs: elapsed,
        });
      } catch (e) {
        return c.json(
          { error: "MiMC hash failed", details: (e as Error).message },
          500,
        );
      }
    },
  );

  // ── POST /hash/pedersen ─────────────────────────────────────────────────
  app.post(
    "/hash/pedersen",
    charge("0.001", "Pedersen hash"),
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
        const { pedersen, babyJub } = await getPedersen();

        // Pedersen hash operates on a buffer of bytes.
        // Convert each input to a 32-byte big-endian buffer and concatenate.
        const buffers: Buffer[] = body.inputs.map((v) => {
          const n = BigInt(v);
          const hex = n.toString(16).padStart(64, "0");
          return Buffer.from(hex, "hex");
        });
        const combined = Buffer.concat(buffers);

        // pedersen.hash returns a babyJub point; we take the x-coordinate (unpack)
        const hashed = pedersen.hash(combined);
        const unpackedPoint = babyJub.unpackPoint(hashed);
        const hash = babyJub.F.toObject(unpackedPoint[0]).toString();

        const elapsed = Date.now() - start;
        return c.json({
          hash,
          algorithm: "pedersen",
          inputCount: body.inputs.length,
          computeTimeMs: elapsed,
        });
      } catch (e) {
        return c.json(
          { error: "Pedersen hash failed", details: (e as Error).message },
          500,
        );
      }
    },
  );

  // ── POST /hash/keccak256 ───────────────────────────────────────────────
  app.post(
    "/hash/keccak256",
    charge("0.001", "Keccak256 hash"),
    async (c) => {
      let body: { data: string };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (!body.data || typeof body.data !== "string") {
        return c.json(
          { error: "Body must contain a 'data' string (hex '0x...' or plaintext)" },
          400,
        );
      }

      try {
        const start = Date.now();

        // Determine if input is hex-encoded or plaintext
        let hexData: `0x${string}`;
        let inputSize: number;
        if (body.data.startsWith("0x") || body.data.startsWith("0X")) {
          const hexStr = body.data.slice(2);
          if (!/^[0-9a-fA-F]*$/.test(hexStr)) {
            return c.json({ error: "Invalid hex string" }, 400);
          }
          hexData = `0x${hexStr}` as `0x${string}`;
          inputSize = hexStr.length / 2;
        } else {
          // Convert plaintext to hex for viem
          const buf = Buffer.from(body.data, "utf-8");
          hexData = `0x${buf.toString("hex")}` as `0x${string}`;
          inputSize = buf.length;
        }

        // Use viem's keccak256 for Ethereum-compatible output
        const { keccak256 } = await import("viem");
        const hash = keccak256(hexData);

        const elapsed = Date.now() - start;
        return c.json({
          hash,
          algorithm: "keccak256",
          inputSize,
          computeTimeMs: elapsed,
        });
      } catch (e) {
        return c.json(
          { error: "Keccak256 hash failed", details: (e as Error).message },
          500,
        );
      }
    },
  );
}
