/**
 * On-chain data reading and attestation utilities for Tempo blockchain.
 *
 * Reads token balances, NFT ownership, and contract interactions from
 * Tempo mainnet (chainId 4217) and produces privacy-preserving signed
 * attestations — the actual balance/ownership data never leaves this module.
 */

import { createPublicClient, http, parseAbi, formatUnits, type PublicClient } from "viem";
import { createHmac, randomUUID } from "crypto";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const TEMPO_RPC = "https://rpc.tempo.xyz";
const TEMPO_CHAIN_ID = 4217;
const PATHUSD = "0x20c000000000000000000000b9537d11c60e8b50";

const ATTESTATION_SECRET =
  process.env.ATTESTATION_SECRET || "zkprover-attestation-secret";
const SERVICE_ID = "zkprover-v1";

// ---------------------------------------------------------------------------
// Viem client
// ---------------------------------------------------------------------------

const client: PublicClient = createPublicClient({
  transport: http(TEMPO_RPC),
}) as PublicClient;

// ---------------------------------------------------------------------------
// ABI fragments
// ---------------------------------------------------------------------------

const ERC20_ABI = parseAbi([
  "function balanceOf(address owner) view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
]);

const ERC721_ABI = parseAbi([
  "function ownerOf(uint256 tokenId) view returns (address)",
]);

// ---------------------------------------------------------------------------
// Signing helpers (same HMAC-SHA256 scheme as attestation.ts)
// ---------------------------------------------------------------------------

function signAttestation(data: Record<string, unknown>): string {
  const { signature: _ignored, ...rest } = data;
  const canonical = JSON.stringify(rest, Object.keys(rest).sort());
  return createHmac("sha256", ATTESTATION_SECRET)
    .update(canonical)
    .digest("hex");
}

/**
 * Hash an address for privacy: we include a hashed version in attestations
 * so the raw address is not leaked.
 */
function hashAddress(address: string): string {
  return createHmac("sha256", ATTESTATION_SECRET)
    .update(address.toLowerCase())
    .digest("hex");
}

// ---------------------------------------------------------------------------
// On-chain reading functions
// ---------------------------------------------------------------------------

/**
 * Get token balance for an address on Tempo.
 *
 * - If `token` is provided, calls ERC20 balanceOf / decimals / symbol.
 * - If `token` is omitted, defaults to PathUSD.
 *
 * Returns `{ balance, decimals, symbol }` where balance is the raw
 * integer string (no formatting).
 */
export async function getTokenBalance(
  address: string,
  token?: string,
): Promise<{ balance: string; decimals: number; symbol: string }> {
  const tokenAddress = token ?? PATHUSD;

  try {
    const [balance, decimals, symbol] = await Promise.all([
      client.readContract({
        address: tokenAddress as `0x${string}`,
        abi: ERC20_ABI,
        functionName: "balanceOf",
        args: [address as `0x${string}`],
      }),
      client.readContract({
        address: tokenAddress as `0x${string}`,
        abi: ERC20_ABI,
        functionName: "decimals",
      }),
      client.readContract({
        address: tokenAddress as `0x${string}`,
        abi: ERC20_ABI,
        functionName: "symbol",
      }),
    ]);

    return {
      balance: (balance as bigint).toString(),
      decimals: Number(decimals),
      symbol: symbol as string,
    };
  } catch (e) {
    throw new Error(`Chain RPC unavailable: ${(e as Error).message}`);
  }
}

/**
 * Check NFT ownership on Tempo.
 *
 * Calls ERC721 ownerOf(tokenId) and compares against `address`.
 */
export async function getNFTOwnership(
  address: string,
  nftContract: string,
  tokenId: string,
): Promise<{ owned: boolean; owner: string }> {
  try {
    const owner = (await client.readContract({
      address: nftContract as `0x${string}`,
      abi: ERC721_ABI,
      functionName: "ownerOf",
      args: [BigInt(tokenId)],
    })) as string;

    return {
      owned: owner.toLowerCase() === address.toLowerCase(),
      owner,
    };
  } catch (e) {
    throw new Error(`Chain RPC unavailable: ${(e as Error).message}`);
  }
}

/**
 * Check if an address has made any transactions on Tempo.
 *
 * Note: checking specific contract interaction requires an indexer;
 * for now we check whether the address nonce > 0.
 */
export async function getContractInteraction(
  address: string,
  _contractAddress: string,
): Promise<{ hasInteracted: boolean; txCount: number }> {
  try {
    const txCount = await client.getTransactionCount({
      address: address as `0x${string}`,
    });

    return {
      hasInteracted: txCount > 0,
      txCount,
    };
  } catch (e) {
    throw new Error(`Chain RPC unavailable: ${(e as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// Attestation functions
// ---------------------------------------------------------------------------

export interface OnchainAttestation {
  id: string;
  claim: string;
  chain: string;
  thresholdMet?: boolean;
  owned?: boolean;
  hasInteracted?: boolean;
  addressHash: string;
  timestamp: number;
  serviceId: string;
  signature: string;
  [key: string]: unknown;
}

/**
 * Attest that an address holds at least `threshold` of a token on Tempo.
 *
 * The actual balance is NOT included in the attestation — only whether
 * the threshold was met.
 */
export async function attestOnchainBalance(
  address: string,
  token: string | undefined,
  threshold: string,
): Promise<{ verified: boolean; attestation: OnchainAttestation }> {
  const { balance } = await getTokenBalance(address, token);

  const thresholdMet = BigInt(balance) >= BigInt(threshold);

  const attestation: Record<string, unknown> = {
    id: randomUUID(),
    claim: "onchain-balance-gte",
    chain: "tempo",
    thresholdMet,
    addressHash: hashAddress(address),
    timestamp: Math.floor(Date.now() / 1000),
    serviceId: SERVICE_ID,
  };

  attestation.signature = signAttestation(attestation);

  return {
    verified: thresholdMet,
    attestation: attestation as unknown as OnchainAttestation,
  };
}

/**
 * Attest NFT ownership on Tempo.
 */
export async function attestNFTOwnership(
  address: string,
  nftContract: string,
  tokenId: string,
): Promise<{ verified: boolean; attestation: OnchainAttestation }> {
  const { owned } = await getNFTOwnership(address, nftContract, tokenId);

  const attestation: Record<string, unknown> = {
    id: randomUUID(),
    claim: "onchain-nft-ownership",
    chain: "tempo",
    owned,
    addressHash: hashAddress(address),
    nftContract: nftContract.toLowerCase(),
    tokenId,
    timestamp: Math.floor(Date.now() / 1000),
    serviceId: SERVICE_ID,
  };

  attestation.signature = signAttestation(attestation);

  return {
    verified: owned,
    attestation: attestation as unknown as OnchainAttestation,
  };
}

/**
 * Attest that an address has interacted with the Tempo chain.
 */
export async function attestContractInteraction(
  address: string,
  contractAddress: string,
): Promise<{ verified: boolean; attestation: OnchainAttestation }> {
  const { hasInteracted, txCount } = await getContractInteraction(
    address,
    contractAddress,
  );

  const attestation: Record<string, unknown> = {
    id: randomUUID(),
    claim: "onchain-interaction",
    chain: "tempo",
    hasInteracted,
    addressHash: hashAddress(address),
    timestamp: Math.floor(Date.now() / 1000),
    serviceId: SERVICE_ID,
  };

  attestation.signature = signAttestation(attestation);

  return {
    verified: hasInteracted,
    attestation: attestation as unknown as OnchainAttestation,
  };
}
