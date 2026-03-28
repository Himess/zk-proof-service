/**
 * ERC-5564 Stealth Address implementation using secp256k1.
 *
 * Provides generation of stealth meta-addresses, derivation of one-time
 * stealth addresses, scanning for payments, and private key recovery.
 *
 * Crypto stack:
 *   - secp256k1 point operations via @noble/curves (bundled with viem)
 *   - keccak256 from viem for Ethereum address derivation
 *   - sha256 from @noble/hashes for shared-secret hashing
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { keccak256, toHex, toBytes } from "viem";

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Return the uncompressed public key (65 bytes, 0x04 prefix) for a private key. */
function pubFromPriv(privHex: string): Uint8Array {
  const privBytes = hexToBytes(privHex);
  return secp256k1.ProjectivePoint.fromPrivateKey(privBytes).toRawBytes(false);
}

/** Strip optional 0x prefix and decode hex string to Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Encode Uint8Array to 0x-prefixed hex string. */
function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("")}` as `0x${string}`;
}

/** Derive an Ethereum address from an uncompressed public key (65 bytes). */
function pubKeyToAddress(uncompressedPub: Uint8Array): `0x${string}` {
  // Drop the 0x04 prefix byte, keccak256 the remaining 64 bytes, take last 20.
  const hash = keccak256(bytesToHex(uncompressedPub.slice(1)));
  return `0x${hash.slice(-40)}` as `0x${string}`;
}

/** Generate 32 cryptographically random bytes as a hex string. */
function randomPrivateKey(): `0x${string}` {
  const bytes = secp256k1.utils.randomPrivateKey();
  return bytesToHex(bytes);
}

/**
 * Hash a shared secret (uncompressed point bytes) into a scalar mod n.
 * Uses SHA-256 and reduces mod curve order to ensure a valid scalar.
 */
function hashSharedSecret(sharedSecretBytes: Uint8Array): bigint {
  const digest = sha256(sharedSecretBytes);
  let num = BigInt(0);
  for (const byte of digest) {
    num = (num << BigInt(8)) | BigInt(byte);
  }
  // Reduce mod curve order to get a valid scalar
  return num % secp256k1.CURVE.n;
}

// ── Public API ───────────────────────────────────────────────────────────────

export interface StealthKeys {
  spendingKey: `0x${string}`;
  viewingKey: `0x${string}`;
  spendingPubKey: `0x${string}`;
  viewingPubKey: `0x${string}`;
  metaAddress: string;
}

/**
 * Generate a stealth meta-address keypair.
 *
 * Returns spending and viewing private keys, their public keys (uncompressed),
 * and the ERC-5564 meta-address string `st:eth:0x<spendingPubKey><viewingPubKey>`.
 */
export async function generateStealthKeys(): Promise<StealthKeys> {
  const spendingKey = randomPrivateKey();
  const viewingKey = randomPrivateKey();

  const spendingPubKey = bytesToHex(pubFromPriv(spendingKey));
  const viewingPubKey = bytesToHex(pubFromPriv(viewingKey));

  // Meta-address concatenates the two uncompressed public keys (no 0x prefix)
  const metaAddress = `st:eth:0x${spendingPubKey.slice(2)}${viewingPubKey.slice(2)}`;

  return { spendingKey, viewingKey, spendingPubKey, viewingPubKey, metaAddress };
}

export interface DerivedStealthAddress {
  stealthAddress: `0x${string}`;
  ephemeralPubKey: `0x${string}`;
  viewKeyHash: `0x${string}`;
}

/**
 * Derive a one-time stealth address from an ERC-5564 meta-address.
 *
 * 1. Parse spending and viewing public keys from the meta-address.
 * 2. Generate an ephemeral keypair.
 * 3. ECDH: sharedSecret = ephemeralPrivKey * viewingPubKey
 * 4. stealthScalar = hash(sharedSecret)
 * 5. stealthPubKey = spendingPubKey + stealthScalar * G
 * 6. Derive Ethereum address from stealthPubKey.
 */
export async function deriveStealthAddress(metaAddress: string): Promise<DerivedStealthAddress> {
  // Parse meta-address: "st:eth:0x<130 hex chars spending><130 hex chars viewing>"
  const prefix = "st:eth:0x";
  if (!metaAddress.startsWith(prefix)) {
    throw new Error(`Invalid meta-address format, expected prefix "${prefix}"`);
  }
  const payload = metaAddress.slice(prefix.length);
  // Each uncompressed public key = 65 bytes = 130 hex chars
  if (payload.length !== 260) {
    throw new Error(`Invalid meta-address length: expected 260 hex chars, got ${payload.length}`);
  }

  const spendingPubHex = payload.slice(0, 130);
  const viewingPubHex = payload.slice(130, 260);

  const spendingPubBytes = hexToBytes(spendingPubHex);
  const viewingPubBytes = hexToBytes(viewingPubHex);

  // Generate ephemeral keypair
  const ephemeralPrivKey = randomPrivateKey();
  const ephemeralPubBytes = pubFromPriv(ephemeralPrivKey);

  // ECDH: shared secret = ephemeralPrivKey * viewingPubKey
  const viewingPoint = secp256k1.ProjectivePoint.fromHex(viewingPubBytes);
  const sharedPoint = viewingPoint.multiply(BigInt(`0x${ephemeralPrivKey.slice(2)}`));
  const sharedSecretBytes = sharedPoint.toRawBytes(false);

  // Hash the shared secret to get a scalar
  const stealthScalar = hashSharedSecret(sharedSecretBytes);

  // Stealth public key = spendingPubKey + stealthScalar * G
  const spendingPoint = secp256k1.ProjectivePoint.fromHex(spendingPubBytes);
  const stealthOffset = secp256k1.ProjectivePoint.BASE.multiply(stealthScalar);
  const stealthPubPoint = spendingPoint.add(stealthOffset);
  const stealthPubBytes = stealthPubPoint.toRawBytes(false);

  const stealthAddress = pubKeyToAddress(stealthPubBytes);
  const ephemeralPubKey = bytesToHex(ephemeralPubBytes);

  // viewKeyHash: keccak256 of the shared secret for announcement logs
  const viewKeyHash = keccak256(bytesToHex(sharedSecretBytes)) as `0x${string}`;

  return { stealthAddress, ephemeralPubKey, viewKeyHash };
}

export interface ScanMatch {
  index: number;
  stealthAddress: `0x${string}`;
}

export interface ScanResult {
  matches: ScanMatch[];
}

/**
 * Scan a list of ephemeral public keys to find stealth payments addressed to us.
 *
 * For each ephemeralPubKey:
 *   sharedSecret = viewingKey * ephemeralPubKey
 *   stealthScalar = hash(sharedSecret)
 *   expectedPub = spendingPubKey + stealthScalar * G
 *   expectedAddress = address(expectedPub)
 */
export async function scanStealthPayments(
  viewingKey: string,
  spendingPubKey: string,
  ephemeralPubKeys: string[],
): Promise<ScanResult> {
  const viewingKeyScalar = BigInt(viewingKey.startsWith("0x") ? viewingKey : `0x${viewingKey}`);
  const spendingPoint = secp256k1.ProjectivePoint.fromHex(hexToBytes(spendingPubKey));

  const matches: ScanMatch[] = [];

  for (let i = 0; i < ephemeralPubKeys.length; i++) {
    const ephPubBytes = hexToBytes(ephemeralPubKeys[i]);
    const ephPoint = secp256k1.ProjectivePoint.fromHex(ephPubBytes);

    // ECDH: sharedSecret = viewingKey * ephemeralPubKey
    const sharedPoint = ephPoint.multiply(viewingKeyScalar);
    const sharedSecretBytes = sharedPoint.toRawBytes(false);

    const stealthScalar = hashSharedSecret(sharedSecretBytes);
    const stealthOffset = secp256k1.ProjectivePoint.BASE.multiply(stealthScalar);
    const expectedPub = spendingPoint.add(stealthOffset);
    const expectedAddress = pubKeyToAddress(expectedPub.toRawBytes(false));

    matches.push({ index: i, stealthAddress: expectedAddress });
  }

  return { matches };
}

export interface ComputedStealthKey {
  stealthPrivateKey: `0x${string}`;
  stealthAddress: `0x${string}`;
}

/**
 * Compute the private key for a stealth address.
 * Only the recipient (who holds spendingKey + viewingKey) can do this.
 *
 *   sharedSecret = viewingKey * ephemeralPubKey
 *   stealthPrivKey = (spendingKey + hash(sharedSecret)) mod n
 */
export async function computeStealthPrivateKey(
  spendingKey: string,
  viewingKey: string,
  ephemeralPubKey: string,
): Promise<ComputedStealthKey> {
  const spendingScalar = BigInt(spendingKey.startsWith("0x") ? spendingKey : `0x${spendingKey}`);
  const viewingScalar = BigInt(viewingKey.startsWith("0x") ? viewingKey : `0x${viewingKey}`);

  const ephPubBytes = hexToBytes(ephemeralPubKey);
  const ephPoint = secp256k1.ProjectivePoint.fromHex(ephPubBytes);

  // ECDH: sharedSecret = viewingKey * ephemeralPubKey
  const sharedPoint = ephPoint.multiply(viewingScalar);
  const sharedSecretBytes = sharedPoint.toRawBytes(false);

  const stealthScalar = hashSharedSecret(sharedSecretBytes);

  // stealthPrivKey = (spendingKey + stealthScalar) mod n
  const stealthPrivKey = (spendingScalar + stealthScalar) % secp256k1.CURVE.n;

  // Encode as 32-byte 0x-prefixed hex
  const privHex = stealthPrivKey.toString(16).padStart(64, "0");
  const stealthPrivateKey = `0x${privHex}` as `0x${string}`;

  // Derive the stealth address from the private key to confirm
  const stealthPubBytes = pubFromPriv(stealthPrivateKey);
  const stealthAddress = pubKeyToAddress(stealthPubBytes);

  return { stealthPrivateKey, stealthAddress };
}
