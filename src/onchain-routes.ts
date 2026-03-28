/**
 * On-chain attestation HTTP routes for Tempo blockchain.
 *
 * Registers endpoints on an existing Hono app:
 *   POST /attest/onchain/balance      — Verify token balance meets threshold   ($0.005)
 *   POST /attest/onchain/nft          — Verify NFT ownership                  ($0.005)
 *   POST /attest/onchain/interaction   — Verify contract interaction           ($0.005)
 *
 * Import and call `registerOnchainRoutes(app, mppx?)` from server.ts.
 */

import type { Hono } from "hono";
import {
  attestOnchainBalance,
  attestNFTOwnership,
  attestContractInteraction,
} from "./onchain.js";

export function registerOnchainRoutes(app: Hono, mppx?: any) {
  // ── Helper: optionally wrap handler with MPP charge ───────────────────────
  const charge = (amount: string, description: string) =>
    mppx
      ? mppx.charge({ amount, description })
      : (_c: any, next: () => Promise<void>) => next();

  // ── POST /attest/onchain/balance ──────────────────────────────────────────
  app.post(
    "/attest/onchain/balance",
    charge("0.005", "Attest on-chain token balance on Tempo"),
    async (c) => {
      let body: { address: string; token?: string; threshold: string };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (!body.address || body.threshold === undefined) {
        return c.json(
          { error: "Missing required fields: address, threshold" },
          400,
        );
      }

      try {
        const start = Date.now();
        const result = await attestOnchainBalance(
          body.address,
          body.token,
          body.threshold,
        );
        const elapsed = Date.now() - start;
        return c.json({ ...result, computeTimeMs: elapsed });
      } catch (e) {
        const msg = (e as Error).message;
        if (msg.startsWith("Chain RPC unavailable")) {
          return c.json({ error: "Chain RPC unavailable" }, 502);
        }
        return c.json(
          { error: "Attestation failed", details: msg },
          500,
        );
      }
    },
  );

  // ── POST /attest/onchain/nft ──────────────────────────────────────────────
  app.post(
    "/attest/onchain/nft",
    charge("0.005", "Attest on-chain NFT ownership on Tempo"),
    async (c) => {
      let body: { address: string; nftContract: string; tokenId: string };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (!body.address || !body.nftContract || body.tokenId === undefined) {
        return c.json(
          { error: "Missing required fields: address, nftContract, tokenId" },
          400,
        );
      }

      try {
        const start = Date.now();
        const result = await attestNFTOwnership(
          body.address,
          body.nftContract,
          body.tokenId,
        );
        const elapsed = Date.now() - start;
        return c.json({ ...result, computeTimeMs: elapsed });
      } catch (e) {
        const msg = (e as Error).message;
        if (msg.startsWith("Chain RPC unavailable")) {
          return c.json({ error: "Chain RPC unavailable" }, 502);
        }
        return c.json(
          { error: "Attestation failed", details: msg },
          500,
        );
      }
    },
  );

  // ── POST /attest/onchain/interaction ──────────────────────────────────────
  app.post(
    "/attest/onchain/interaction",
    charge("0.005", "Attest on-chain contract interaction on Tempo"),
    async (c) => {
      let body: { address: string; contractAddress: string };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (!body.address || !body.contractAddress) {
        return c.json(
          { error: "Missing required fields: address, contractAddress" },
          400,
        );
      }

      try {
        const start = Date.now();
        const result = await attestContractInteraction(
          body.address,
          body.contractAddress,
        );
        const elapsed = Date.now() - start;
        return c.json({ ...result, computeTimeMs: elapsed });
      } catch (e) {
        const msg = (e as Error).message;
        if (msg.startsWith("Chain RPC unavailable")) {
          return c.json({ error: "Chain RPC unavailable" }, 502);
        }
        return c.json(
          { error: "Attestation failed", details: msg },
          500,
        );
      }
    },
  );
}
