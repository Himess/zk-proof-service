/**
 * Poseidon-based Merkle tree implementation for ZK proof service.
 *
 * Uses circomlibjs Poseidon (BN254-compatible) — same hash used by
 * the JoinSplit circuits, so proofs generated from this tree are
 * directly consumable by /prove/1x2 and /prove/2x2.
 */

import { initPoseidon, type PoseidonHash } from "./crypto.js";
import { randomUUID } from "crypto";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const DEFAULT_DEPTH = 20;

/** Cached zero-hashes per depth (lazy). */
let zeroCache: bigint[] | null = null;

async function getZeroHashes(depth: number): Promise<bigint[]> {
  if (zeroCache && zeroCache.length >= depth + 1) return zeroCache;
  const p = await initPoseidon();
  const zeros: bigint[] = new Array(depth + 1);
  zeros[0] = 0n;
  for (let i = 1; i <= depth; i++) {
    zeros[i] = p.hash2(zeros[i - 1], zeros[i - 1]);
  }
  zeroCache = zeros;
  return zeros;
}

/**
 * Build a full binary Merkle tree from `leaves` (as bigints).
 * Returns every layer bottom-up: layers[0] = leaves, layers[depth] = [root].
 */
async function buildLayers(
  leaves: bigint[],
  depth: number,
): Promise<bigint[][]> {
  const p = await initPoseidon();
  const zeros = await getZeroHashes(depth);
  const numLeaves = 1 << depth; // 2^depth

  // Pad leaves with zero to fill the layer
  const layer0 = new Array<bigint>(numLeaves);
  for (let i = 0; i < numLeaves; i++) {
    layer0[i] = i < leaves.length ? leaves[i] : zeros[0];
  }

  const layers: bigint[][] = [layer0];

  let current = layer0;
  for (let level = 1; level <= depth; level++) {
    const next: bigint[] = new Array(current.length >> 1);
    for (let i = 0; i < next.length; i++) {
      next[i] = p.hash2(current[2 * i], current[2 * i + 1]);
    }
    layers.push(next);
    current = next;
  }

  return layers;
}

/**
 * Parse a leaf string into a bigint.  Accepts decimal or hex (0x-prefixed).
 */
function parseBigInt(s: string): bigint {
  const trimmed = s.trim();
  if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
    return BigInt(trimmed);
  }
  return BigInt(trimmed);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Poseidon hash utility.
 *
 * Hashes 1-N field elements (strings, decimal or hex) through circomlibjs
 * Poseidon and returns the digest as a decimal string.
 */
export async function poseidonHash(inputs: string[]): Promise<string> {
  if (inputs.length === 0) {
    throw new Error("poseidonHash requires at least one input");
  }
  const p = await initPoseidon();
  const vals = inputs.map(parseBigInt);

  // circomlibjs supports up to ~16 inputs; use cascaded hash2 for >2
  if (vals.length === 1) {
    return p.hash1(vals[0]).toString();
  }
  if (vals.length === 2) {
    return p.hash2(vals[0], vals[1]).toString();
  }
  if (vals.length === 3) {
    return p.hash3(vals[0], vals[1], vals[2]).toString();
  }

  // For 4+ inputs, use the raw circomlibjs poseidon which supports up to 16
  const { buildPoseidon } = await import("circomlibjs");
  const poseidon = await buildPoseidon();
  const result = poseidon.F.toObject(poseidon(vals));
  return result.toString();
}

/**
 * Build a Merkle tree from a list of leaf values (decimal or hex strings).
 *
 * Returns the root, depth, leaf count, and a unique tree ID.
 */
export async function buildMerkleTree(
  leaves: string[],
  depth: number = DEFAULT_DEPTH,
): Promise<{ root: string; depth: number; leafCount: number; treeId: string }> {
  if (leaves.length === 0) {
    throw new Error("At least one leaf is required");
  }
  if (leaves.length > 1 << depth) {
    throw new Error(
      `Too many leaves (${leaves.length}) for depth ${depth} (max ${1 << depth})`,
    );
  }

  const bigLeaves = leaves.map(parseBigInt);
  const layers = await buildLayers(bigLeaves, depth);
  const root = layers[depth][0];

  return {
    root: root.toString(),
    depth,
    leafCount: leaves.length,
    treeId: randomUUID(),
  };
}

/**
 * Generate a Merkle inclusion proof for the leaf at `leafIndex`.
 *
 * Returns the root, the leaf value, the sibling path elements (bottom-up),
 * the path indices (0 = left, 1 = right), and whether the proof is valid.
 */
export async function generateMerkleProof(
  leaves: string[],
  leafIndex: number,
  depth: number = DEFAULT_DEPTH,
): Promise<{
  root: string;
  leaf: string;
  pathElements: string[];
  pathIndices: number[];
  valid: boolean;
}> {
  if (leafIndex < 0 || leafIndex >= leaves.length) {
    throw new Error(
      `leafIndex ${leafIndex} out of range [0, ${leaves.length})`,
    );
  }

  const bigLeaves = leaves.map(parseBigInt);
  const layers = await buildLayers(bigLeaves, depth);

  const pathElements: string[] = [];
  const pathIndices: number[] = [];
  let idx = leafIndex;

  for (let level = 0; level < depth; level++) {
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    pathElements.push(layers[level][siblingIdx].toString());
    pathIndices.push(idx % 2); // 0 if current node is left child, 1 if right
    idx = idx >> 1;
  }

  const root = layers[depth][0].toString();
  const leaf = bigLeaves[leafIndex].toString();

  // Self-verify before returning
  const verification = await verifyMerkleProof(
    root,
    leaf,
    pathElements,
    pathIndices,
  );

  return {
    root,
    leaf,
    pathElements,
    pathIndices,
    valid: verification.valid,
  };
}

/**
 * Verify a Merkle inclusion proof.
 *
 * Recomputes the root from the leaf + path and compares with the expected root.
 */
export async function verifyMerkleProof(
  root: string,
  leaf: string,
  pathElements: string[],
  pathIndices: number[],
): Promise<{ valid: boolean; computedRoot: string }> {
  if (pathElements.length !== pathIndices.length) {
    throw new Error("pathElements and pathIndices must have the same length");
  }

  const p = await initPoseidon();
  let current = parseBigInt(leaf);

  for (let i = 0; i < pathElements.length; i++) {
    const sibling = parseBigInt(pathElements[i]);
    if (pathIndices[i] === 0) {
      // current node is left child
      current = p.hash2(current, sibling);
    } else {
      // current node is right child
      current = p.hash2(sibling, current);
    }
  }

  const computedRoot = current.toString();
  const expectedRoot = parseBigInt(root).toString();

  return {
    valid: computedRoot === expectedRoot,
    computedRoot,
  };
}
