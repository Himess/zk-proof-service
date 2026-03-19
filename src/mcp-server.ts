/**
 * MCP Server — ZK Proof Generation as a tool for AI agents.
 *
 * AI agents (Claude Code, Cursor, etc.) can discover and call this server
 * to generate Groth16 ZK proofs.
 *
 * Usage:
 *   npx tsx src/mcp-server.ts
 *
 * Claude Code config (~/.claude/settings.json):
 *   {
 *     "mcpServers": {
 *       "zk-proof": {
 *         "command": "npx",
 *         "args": ["tsx", "src/mcp-server.ts"],
 *         "cwd": "/path/to/zk-proof-service"
 *       }
 *     }
 *   }
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  generateProof,
  verifyProof,
  listCircuits,
  formatProofForContract,
} from "./prover.js";
import type { CircuitType } from "./prover.js";

const server = new McpServer({
  name: "zk-proof-service",
  version: "1.0.0",
});

// Tool: list available circuits
server.tool(
  "list_circuits",
  "List available ZK circuits with descriptions, constraint counts, and pricing",
  {},
  async () => {
    const circuits = listCircuits();
    const pricing: Record<string, string> = { "1x2": "$0.01", "2x2": "$0.02" };

    const text = circuits
      .map(
        (c) =>
          `${c.id}: ${c.description}\n  Constraints: ${c.constraintCount.toLocaleString()}, Public signals: ${c.publicSignals}, Price: ${pricing[c.id]}`
      )
      .join("\n\n");

    return { content: [{ type: "text", text }] };
  }
);

// Tool: generate a ZK proof
server.tool(
  "generate_proof",
  "Generate a Groth16 ZK proof for a JoinSplit circuit. Returns proof, public signals, and contract-ready uint256[8] format.",
  {
    circuit: z.enum(["1x2", "2x2"]).describe("Circuit type: '1x2' (1 input, 2 outputs) or '2x2' (2 inputs, 2 outputs)"),
    root: z.string().describe("Merkle tree root"),
    publicAmount: z.string().describe("Public amount (deposit/withdraw)"),
    extDataHash: z.string().describe("External data hash"),
    protocolFee: z.string().describe("Protocol fee (usually '0')"),
    inputNullifiers: z.array(z.string()).describe("Input nullifier hashes"),
    outputCommitments: z.array(z.string()).describe("Output commitment hashes"),
    inAmount: z.array(z.string()).describe("Input amounts"),
    inPrivateKey: z.array(z.string()).describe("Input private keys"),
    inBlinding: z.array(z.string()).describe("Input blinding factors"),
    inPathIndices: z.array(z.string()).describe("Merkle path indices"),
    inPathElements: z.array(z.array(z.string())).describe("Merkle path elements (depth 20)"),
    outAmount: z.array(z.string()).describe("Output amounts"),
    outPubkey: z.array(z.string()).describe("Output public keys"),
    outBlinding: z.array(z.string()).describe("Output blinding factors"),
  },
  async ({ circuit, ...circuitInput }) => {
    try {
      const result = await generateProof(circuit as CircuitType, circuitInput);
      const contractProof = formatProofForContract(result.proof);

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              success: true,
              circuit,
              generationTimeMs: result.generationTimeMs,
              publicSignals: result.publicSignals,
              contractProof,
              proof: result.proof,
            }, null, 2),
          },
        ],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Proof generation failed: ${(e as Error).message}` }],
        isError: true,
      };
    }
  }
);

// Tool: verify a ZK proof
server.tool(
  "verify_proof",
  "Verify a Groth16 ZK proof. Free — no payment required.",
  {
    circuit: z.enum(["1x2", "2x2"]).describe("Circuit type"),
    proof: z.object({
      pi_a: z.array(z.string()),
      pi_b: z.array(z.array(z.string())),
      pi_c: z.array(z.string()),
      protocol: z.string(),
      curve: z.string(),
    }).describe("Proof object from generate_proof"),
    publicSignals: z.array(z.string()).describe("Public signals from generate_proof"),
  },
  async ({ circuit, proof, publicSignals }) => {
    try {
      const result = await verifyProof(circuit as CircuitType, proof, publicSignals);

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              valid: result.valid,
              verificationTimeMs: result.verificationTimeMs,
              circuit,
            }, null, 2),
          },
        ],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Verification failed: ${(e as Error).message}` }],
        isError: true,
      };
    }
  }
);

// Start
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("ZK Proof MCP Server running on stdio");
}

main().catch(console.error);
