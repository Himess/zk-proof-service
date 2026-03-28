/**
 * PLONK proving routes for the ZK proof service.
 *
 * Registers endpoints on an existing Hono app:
 *   POST /prove/plonk/1x2    — Generate a PLONK proof (1x2 JoinSplit)  ($0.015)
 *   POST /prove/plonk/2x2    — Generate a PLONK proof (2x2 JoinSplit)  ($0.025)
 *   POST /verify/plonk/:circuit — Verify a PLONK proof                 (free)
 *
 * Uses the same circuits as Groth16 but with PLONK-specific .zkey files.
 * Input format is identical to the Groth16 endpoints.
 *
 * Import and call `registerPlonkRoutes(app, mppx?)` from server.ts to wire them up.
 */

import type { Hono } from "hono";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
// @ts-ignore - snarkjs has no types
import * as snarkjs from "snarkjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = path.resolve(__dirname, "../circuits");

type PlonkCircuitType = "1x2" | "2x2";

interface PlonkArtifactPaths {
  wasm: string;
  zkey: string;
  vkey: string;
}

function getPlonkArtifactPaths(circuit: PlonkCircuitType): PlonkArtifactPaths {
  const dir = path.join(CIRCUITS_DIR, circuit);
  const prefix = `joinSplit_${circuit}`;
  return {
    wasm: path.join(dir, `${prefix}.wasm`),
    zkey: path.join(dir, `${prefix}_plonk.zkey`),
    vkey: path.join(dir, "verification_key_plonk.json"),
  };
}

function checkPlonkAvailability(circuit: PlonkCircuitType): {
  available: boolean;
  missing: string[];
} {
  const paths = getPlonkArtifactPaths(circuit);
  const missing: string[] = [];
  if (!fs.existsSync(paths.wasm)) missing.push("wasm");
  if (!fs.existsSync(paths.zkey)) missing.push("plonk zkey");
  if (!fs.existsSync(paths.vkey)) missing.push("plonk verification key");
  return { available: missing.length === 0, missing };
}

export function registerPlonkRoutes(app: Hono, mppx?: any) {
  // Helper: optionally wrap handler with MPP charge
  const charge = (amount: string, description: string) =>
    mppx
      ? mppx.charge({ amount, description })
      : (_c: any, next: () => Promise<void>) => next();

  // POST /prove/plonk/1x2 — PLONK proof for 1-input, 2-output JoinSplit
  app.post(
    "/prove/plonk/1x2",
    charge("0.015", "Generate PLONK proof (1x2 JoinSplit circuit)"),
    async (c) => {
      return handlePlonkProve(c, "1x2");
    },
  );

  // POST /prove/plonk/2x2 — PLONK proof for 2-input, 2-output JoinSplit
  app.post(
    "/prove/plonk/2x2",
    charge("0.025", "Generate PLONK proof (2x2 JoinSplit circuit)"),
    async (c) => {
      return handlePlonkProve(c, "2x2");
    },
  );

  // POST /verify/plonk/:circuit — Verify a PLONK proof (free)
  app.post("/verify/plonk/:circuit", async (c) => {
    const circuit = c.req.param("circuit") as PlonkCircuitType;

    if (circuit !== "1x2" && circuit !== "2x2") {
      return c.json(
        { error: "Invalid circuit. Use '1x2' or '2x2'" },
        400,
      );
    }

    const availability = checkPlonkAvailability(circuit);
    if (!availability.available) {
      return c.json(
        {
          error: "PLONK verification not available for this circuit",
          missing: availability.missing,
          hint: "PLONK setup has not been completed for this circuit",
        },
        503,
      );
    }

    let body: { proof: unknown; publicSignals: string[] };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }

    if (!body.proof || !Array.isArray(body.publicSignals)) {
      return c.json(
        { error: "Body must contain 'proof' (object) and 'publicSignals' (string[])" },
        400,
      );
    }

    try {
      const paths = getPlonkArtifactPaths(circuit);
      const vkey = JSON.parse(fs.readFileSync(paths.vkey, "utf8"));

      const start = Date.now();
      const valid = await snarkjs.plonk.verify(vkey, body.publicSignals, body.proof);
      const verificationTimeMs = Date.now() - start;

      return c.json({
        success: true,
        protocol: "plonk",
        circuit,
        valid,
        verificationTimeMs,
      });
    } catch (e) {
      console.error("PLONK verification failed:", e);
      return c.json(
        { error: "PLONK verification failed", details: (e as Error).message },
        500,
      );
    }
  });
}

async function handlePlonkProve(c: any, circuit: PlonkCircuitType) {
  const availability = checkPlonkAvailability(circuit);
  if (!availability.available) {
    return c.json(
      {
        error: "PLONK proving not available for this circuit",
        missing: availability.missing,
        hint: "PLONK setup has not been completed for this circuit",
      },
      503,
    );
  }

  let circuitInput: Record<string, unknown>;
  try {
    circuitInput = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  if (!circuitInput || typeof circuitInput !== "object") {
    return c.json(
      { error: "Body must be a JSON object with circuit inputs" },
      400,
    );
  }

  try {
    const paths = getPlonkArtifactPaths(circuit);

    console.log(`Generating PLONK ${circuit} proof...`);
    const start = Date.now();
    const { proof, publicSignals } = await snarkjs.plonk.fullProve(
      circuitInput,
      paths.wasm,
      paths.zkey,
    );
    const generationTimeMs = Date.now() - start;
    console.log(`PLONK proof generated in ${generationTimeMs}ms`);

    return c.json({
      success: true,
      protocol: "plonk",
      circuit,
      proof,
      publicSignals,
      generationTimeMs,
    });
  } catch (e) {
    console.error("PLONK proof generation failed:", e);
    return c.json(
      { error: "PLONK proof generation failed", details: (e as Error).message },
      500,
    );
  }
}
