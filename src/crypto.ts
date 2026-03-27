// Poseidon hashing utilities for PrivAgent UTXO system
// Uses circomlibjs for BN254-compatible Poseidon

let poseidonInstance: any = null;

export interface PoseidonHash {
  hash1(input: bigint): bigint;
  hash2(a: bigint, b: bigint): bigint;
  hash3(a: bigint, b: bigint, c: bigint): bigint;
}

export async function initPoseidon(): Promise<PoseidonHash> {
  if (poseidonInstance) return poseidonInstance;

  const { buildPoseidon } = await import("circomlibjs");
  const poseidon = await buildPoseidon();

  const toFieldElement = (buf: Uint8Array): bigint => {
    return poseidon.F.toObject(buf);
  };

  poseidonInstance = {
    hash1(input: bigint): bigint {
      return toFieldElement(poseidon([input]));
    },
    hash2(a: bigint, b: bigint): bigint {
      return toFieldElement(poseidon([a, b]));
    },
    hash3(a: bigint, b: bigint, c: bigint): bigint {
      return toFieldElement(poseidon([a, b, c]));
    },
  };

  return poseidonInstance;
}

// Compute UTXO commitment: Poseidon(amount, pubkey, blinding)
export async function computeCommitment(
  amount: bigint,
  pubkey: bigint,
  blinding: bigint,
): Promise<bigint> {
  const p = await initPoseidon();
  return p.hash3(amount, pubkey, blinding);
}

// Compute nullifier: Poseidon(commitment, leafIndex, privateKey)
export async function computeNullifier(
  commitment: bigint,
  leafIndex: bigint,
  privateKey: bigint,
): Promise<bigint> {
  const p = await initPoseidon();
  return p.hash3(commitment, leafIndex, privateKey);
}

// Derive public key from private key: Poseidon(privateKey)
export async function derivePublicKey(privateKey: bigint): Promise<bigint> {
  const p = await initPoseidon();
  return p.hash1(privateKey);
}

// Generate random blinding factor (120-bit for safety within BN254 field)
export function randomBlinding(): bigint {
  const bytes = new Uint8Array(15); // 120 bits
  crypto.getRandomValues(bytes);
  let result = BigInt(0);
  for (const byte of bytes) {
    result = (result << BigInt(8)) | BigInt(byte);
  }
  return result;
}

// BN254 field prime
export const FIELD_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);
