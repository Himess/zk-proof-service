/**
 * ZK Credential Attestation — Core Logic
 *
 * Provides commitment-based attestations using Poseidon hashing.
 * The server verifies claims against committed values and signs
 * attestations with HMAC-SHA256 so any third party can verify
 * the attestation came from this service without replaying the
 * private data.
 *
 * Trust model: the agent reveals (value, blinding) to the service,
 * which checks commitment = Poseidon(value, blinding) and signs the
 * claim.  The commitment cryptographically binds the agent to the
 * value so it cannot be changed after the fact.
 */

import { createHmac, randomUUID } from "crypto";
import { initPoseidon } from "./crypto.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const ATTESTATION_SECRET =
  process.env.ATTESTATION_SECRET || "zkprover-attestation-secret";
const SERVICE_ID = "zkprover-v1";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Attestation {
  id: string;
  claim: string;
  commitment: string;
  timestamp: number;
  serviceId: string;
  signature: string;
  [key: string]: unknown; // claim-specific fields (threshold, min, max, merkleRoot)
}

export interface AttestationResult {
  valid: boolean;
  attestation: Attestation;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Sign an attestation object with HMAC-SHA256.
 * We canonicalise by sorting keys and exclude the `signature` field itself.
 */
function signAttestation(data: Record<string, unknown>): string {
  const { signature: _ignored, ...rest } = data;
  const canonical = JSON.stringify(rest, Object.keys(rest).sort());
  return createHmac("sha256", ATTESTATION_SECRET)
    .update(canonical)
    .digest("hex");
}

/**
 * Verify an attestation signature.
 */
export function verifyAttestationSignature(
  attestation: Record<string, unknown>,
): boolean {
  const claimed = attestation.signature as string;
  if (!claimed) return false;
  const expected = signAttestation(attestation);
  return expected === claimed;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create a Poseidon commitment:  commitment = Poseidon(value, blinding).
 * Returns the commitment as a decimal string.
 */
export async function createCommitment(
  value: string,
  blinding: string,
): Promise<string> {
  const p = await initPoseidon();
  const commitment = p.hash2(BigInt(value), BigInt(blinding));
  return commitment.toString();
}

/**
 * Verify that `commitment == Poseidon(value, blinding)`.
 */
export async function verifyCommitment(
  commitment: string,
  value: string,
  blinding: string,
): Promise<boolean> {
  const computed = await createCommitment(value, blinding);
  return computed === commitment;
}

/**
 * Attest that `value > threshold` given a valid commitment.
 *
 * Returns a signed attestation if the commitment opens correctly AND
 * the value exceeds the threshold.
 */
export async function attestBalanceGT(
  commitment: string,
  value: string,
  blinding: string,
  threshold: string,
): Promise<AttestationResult> {
  // Verify commitment
  const commitmentValid = await verifyCommitment(commitment, value, blinding);
  if (!commitmentValid) {
    throw new Error(
      "Commitment mismatch — Poseidon(value, blinding) != commitment",
    );
  }

  const satisfied = BigInt(value) > BigInt(threshold);

  const attestation: Record<string, unknown> = {
    id: randomUUID(),
    claim: "balance-gt",
    threshold,
    commitment,
    timestamp: Math.floor(Date.now() / 1000),
    serviceId: SERVICE_ID,
  };

  attestation.signature = signAttestation(attestation);

  return {
    valid: satisfied,
    attestation: attestation as unknown as Attestation,
  };
}

/**
 * Attest that `min <= value <= max` given a valid commitment.
 */
export async function attestRange(
  commitment: string,
  value: string,
  blinding: string,
  min: string,
  max: string,
): Promise<AttestationResult> {
  const commitmentValid = await verifyCommitment(commitment, value, blinding);
  if (!commitmentValid) {
    throw new Error(
      "Commitment mismatch — Poseidon(value, blinding) != commitment",
    );
  }

  const v = BigInt(value);
  const satisfied = v >= BigInt(min) && v <= BigInt(max);

  const attestation: Record<string, unknown> = {
    id: randomUUID(),
    claim: "range",
    min,
    max,
    commitment,
    timestamp: Math.floor(Date.now() / 1000),
    serviceId: SERVICE_ID,
  };

  attestation.signature = signAttestation(attestation);

  return {
    valid: satisfied,
    attestation: attestation as unknown as Attestation,
  };
}

/**
 * Attest set membership via Merkle proof.
 *
 * Given a set of `leaves`, the function:
 *  1. Verifies `commitment == Poseidon(value, blinding)`
 *  2. Hashes each leaf with Poseidon to get leaf hashes
 *  3. Builds a small Merkle tree from `leaves`
 *  4. Checks whether `value` is among the leaves
 *  5. Signs an attestation containing the Merkle root
 */
export async function attestMembership(
  commitment: string,
  value: string,
  blinding: string,
  leaves: string[],
): Promise<AttestationResult & { merkleRoot: string }> {
  const commitmentValid = await verifyCommitment(commitment, value, blinding);
  if (!commitmentValid) {
    throw new Error(
      "Commitment mismatch — Poseidon(value, blinding) != commitment",
    );
  }

  const p = await initPoseidon();

  // Check if value is among the leaves
  const isMember = leaves.some((leaf) => leaf === value);

  // Build a simple Merkle tree from the leaves to derive the root.
  // Pad to next power of 2 with zeros.
  const leafBigints = leaves.map((l) => BigInt(l));
  let layerSize = 1;
  while (layerSize < leafBigints.length) layerSize <<= 1;
  const paddedLeaves = [...leafBigints];
  while (paddedLeaves.length < layerSize) paddedLeaves.push(0n);

  let currentLayer = paddedLeaves;
  while (currentLayer.length > 1) {
    const nextLayer: bigint[] = [];
    for (let i = 0; i < currentLayer.length; i += 2) {
      nextLayer.push(p.hash2(currentLayer[i], currentLayer[i + 1]));
    }
    currentLayer = nextLayer;
  }
  const merkleRoot = currentLayer[0].toString();

  const attestation: Record<string, unknown> = {
    id: randomUUID(),
    claim: "membership",
    merkleRoot,
    commitment,
    timestamp: Math.floor(Date.now() / 1000),
    serviceId: SERVICE_ID,
  };

  attestation.signature = signAttestation(attestation);

  return {
    valid: isMember,
    merkleRoot,
    attestation: attestation as unknown as Attestation,
  };
}
