import path from "path";
import { fileURLToPath } from "url";
// @ts-ignore - snarkjs has no types
import * as snarkjs from "snarkjs";
import fs from "fs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = path.resolve(__dirname, "../circuits");

export type CircuitType = "1x2" | "2x2";

export interface ProofResult {
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  publicSignals: string[];
  generationTimeMs: number;
}

export interface VerifyResult {
  valid: boolean;
  verificationTimeMs: number;
}

function getArtifactPaths(circuit: CircuitType) {
  const dir = path.join(CIRCUITS_DIR, circuit);
  const prefix = `joinSplit_${circuit}`;
  return {
    wasm: path.join(dir, `${prefix}.wasm`),
    zkey: path.join(dir, `${prefix}_final.zkey`),
    vkey: path.join(dir, "verification_key.json"),
  };
}

export function listCircuits(): {
  id: CircuitType;
  description: string;
  constraintCount: number;
  publicSignals: number;
}[] {
  return [
    {
      id: "1x2",
      description: "JoinSplit(1,2,20) — 1 input, 2 outputs, Merkle depth 20",
      constraintCount: 13726,
      publicSignals: 7,
    },
    {
      id: "2x2",
      description: "JoinSplit(2,2,20) — 2 inputs, 2 outputs, Merkle depth 20",
      constraintCount: 25877,
      publicSignals: 8,
    },
  ];
}

export async function generateProof(
  circuit: CircuitType,
  circuitInput: Record<string, unknown>
): Promise<ProofResult> {
  const paths = getArtifactPaths(circuit);

  if (!fs.existsSync(paths.wasm)) {
    throw new Error(`Circuit WASM not found: ${paths.wasm}`);
  }
  if (!fs.existsSync(paths.zkey)) {
    throw new Error(`Circuit zkey not found: ${paths.zkey}`);
  }

  const start = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    paths.wasm,
    paths.zkey
  );
  const generationTimeMs = Date.now() - start;

  return { proof, publicSignals, generationTimeMs };
}

export async function verifyProof(
  circuit: CircuitType,
  proof: unknown,
  publicSignals: string[]
): Promise<VerifyResult> {
  const paths = getArtifactPaths(circuit);

  if (!fs.existsSync(paths.vkey)) {
    throw new Error(`Verification key not found: ${paths.vkey}`);
  }

  const vkey = JSON.parse(fs.readFileSync(paths.vkey, "utf8"));

  const start = Date.now();
  const valid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  const verificationTimeMs = Date.now() - start;

  return { valid, verificationTimeMs };
}

/**
 * Format proof for on-chain Solidity verifier.
 * Returns uint256[8] array: [pA0, pA1, pB00, pB01, pB10, pB11, pC0, pC1]
 */
export function formatProofForContract(proof: ProofResult["proof"]): string[] {
  return [
    proof.pi_a[0],
    proof.pi_a[1],
    proof.pi_b[0][1],
    proof.pi_b[0][0],
    proof.pi_b[1][1],
    proof.pi_b[1][0],
    proof.pi_c[0],
    proof.pi_c[1],
  ];
}
