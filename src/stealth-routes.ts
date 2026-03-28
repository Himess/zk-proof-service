/**
 * Stealth address HTTP routes for the ZK proof service.
 *
 * Registers ERC-5564-style stealth address endpoints on an existing Hono app:
 *   POST /stealth/generate-keys   — Generate stealth meta-address keypair   ($0.002)
 *   POST /stealth/derive-address  — Derive one-time stealth address         ($0.002)
 *   POST /stealth/scan            — Scan for stealth payments               ($0.005)
 *   POST /stealth/compute-key     — Compute stealth address private key     ($0.002)
 *
 * Import and call `registerStealthRoutes(app)` from server.ts to wire them up.
 */

import type { Hono } from "hono";
import {
  generateStealthKeys,
  deriveStealthAddress,
  scanStealthPayments,
  computeStealthPrivateKey,
} from "./stealth.js";

export function registerStealthRoutes(app: Hono, mppx?: any) {
  // ── Helper: optionally wrap handler with MPP charge ───────────────────────
  const charge = (amount: string, description: string) =>
    mppx
      ? mppx.charge({ amount, description })
      : (_c: any, next: () => Promise<void>) => next();

  // ── POST /stealth/generate-keys ─────────────────────────────────────────
  app.post(
    "/stealth/generate-keys",
    charge("0.002", "Generate stealth meta-address keypair"),
    async (c) => {
      try {
        const start = Date.now();
        const result = await generateStealthKeys();
        const elapsed = Date.now() - start;
        return c.json({ success: true, ...result, computeTimeMs: elapsed });
      } catch (e) {
        return c.json(
          { error: "Failed to generate stealth keys", details: (e as Error).message },
          500,
        );
      }
    },
  );

  // ── POST /stealth/derive-address ────────────────────────────────────────
  app.post(
    "/stealth/derive-address",
    charge("0.002", "Derive one-time stealth address"),
    async (c) => {
      let body: { metaAddress: string };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (!body.metaAddress || typeof body.metaAddress !== "string") {
        return c.json(
          { error: "Body must contain a 'metaAddress' string (e.g. 'st:eth:0x...')" },
          400,
        );
      }

      try {
        const start = Date.now();
        const result = await deriveStealthAddress(body.metaAddress);
        const elapsed = Date.now() - start;
        return c.json({ success: true, ...result, computeTimeMs: elapsed });
      } catch (e) {
        return c.json(
          { error: "Failed to derive stealth address", details: (e as Error).message },
          500,
        );
      }
    },
  );

  // ── POST /stealth/scan ──────────────────────────────────────────────────
  app.post(
    "/stealth/scan",
    charge("0.005", "Scan for stealth payments"),
    async (c) => {
      let body: { viewingKey: string; spendingPubKey: string; ephemeralPubKeys: string[] };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (!body.viewingKey || typeof body.viewingKey !== "string") {
        return c.json({ error: "Body must contain a 'viewingKey' hex string" }, 400);
      }
      if (!body.spendingPubKey || typeof body.spendingPubKey !== "string") {
        return c.json({ error: "Body must contain a 'spendingPubKey' hex string" }, 400);
      }
      if (!Array.isArray(body.ephemeralPubKeys) || body.ephemeralPubKeys.length === 0) {
        return c.json(
          { error: "Body must contain a non-empty 'ephemeralPubKeys' array" },
          400,
        );
      }

      try {
        const start = Date.now();
        const result = await scanStealthPayments(
          body.viewingKey,
          body.spendingPubKey,
          body.ephemeralPubKeys,
        );
        const elapsed = Date.now() - start;
        return c.json({ success: true, ...result, computeTimeMs: elapsed });
      } catch (e) {
        return c.json(
          { error: "Failed to scan stealth payments", details: (e as Error).message },
          500,
        );
      }
    },
  );

  // ── POST /stealth/compute-key ───────────────────────────────────────────
  app.post(
    "/stealth/compute-key",
    charge("0.002", "Compute stealth address private key"),
    async (c) => {
      let body: { spendingKey: string; viewingKey: string; ephemeralPubKey: string };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body" }, 400);
      }

      if (!body.spendingKey || typeof body.spendingKey !== "string") {
        return c.json({ error: "Body must contain a 'spendingKey' hex string" }, 400);
      }
      if (!body.viewingKey || typeof body.viewingKey !== "string") {
        return c.json({ error: "Body must contain a 'viewingKey' hex string" }, 400);
      }
      if (!body.ephemeralPubKey || typeof body.ephemeralPubKey !== "string") {
        return c.json({ error: "Body must contain an 'ephemeralPubKey' hex string" }, 400);
      }

      try {
        const start = Date.now();
        const result = await computeStealthPrivateKey(
          body.spendingKey,
          body.viewingKey,
          body.ephemeralPubKey,
        );
        const elapsed = Date.now() - start;
        return c.json({ success: true, ...result, computeTimeMs: elapsed });
      } catch (e) {
        return c.json(
          { error: "Failed to compute stealth private key", details: (e as Error).message },
          500,
        );
      }
    },
  );
}
