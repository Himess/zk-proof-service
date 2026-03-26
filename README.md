---
title: ZKProver
emoji: 🔐
colorFrom: green
colorTo: indigo
sdk: docker
app_port: 7860
---

# ZKProver

**Pay-per-proof ZK proving service via MPP**

> Real compute, not just an API proxy. Groth16 proof generation as a service — agents pay $0.01 per proof via [Tempo MPP](https://mpp.dev).

**Live:** https://himess-zk-proof-service.hf.space

## Try It Now

```bash
# Check the service
tempo request -t https://himess-zk-proof-service.hf.space/health

# See available circuits & pricing
tempo request -t https://himess-zk-proof-service.hf.space/circuits

# Generate a ZK proof ($0.01 — payment handled automatically)
tempo request -X POST \
  -H "Content-Type: application/json" \
  --json '{"root":"0","publicAmount":"1000000","extDataHash":"0","protocolFee":"0","inputNullifiers":["0"],"outputCommitments":["0","0"],"inAmount":["0"],"inPrivateKey":["1"],"inBlinding":["0"],"inPathIndices":["0"],"inPathElements":[["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]],"outAmount":["1000000","0"],"outPubkey":["0","0"],"outBlinding":["0","0"]}' \
  https://himess-zk-proof-service.hf.space/prove/1x2
```

## How It Works

```
Client                          ZK Proof Service
  |                                    |
  |-- POST /prove/1x2 --------------->|
  |<------------ 402 Payment Required -|
  |                                    |
  |-- MPP Payment (0.01 USDC) ------->|
  |<------------ 200 OK --------------|
  |    { proof, publicSignals,         |
  |      contractProof, timeMs }       |
  |                                    |
  |-- POST /verify/1x2 (free) ------->|
  |<------------ { valid: true } ------|
```

The server uses [mppx](https://www.npmjs.com/package/mppx) to gate proof generation behind a 402 paywall. Clients pay via Tempo MPP — no API keys, no accounts, just a wallet. Verification is free.

## Performance

| Metric | Time |
|---|---|
| Proof generation (warm) | ~3-5s |
| Proof generation (cold) | ~8-13s |
| Verification | ~50ms |

## Endpoints

| Method | Path | Cost | Description |
|---|---|---|---|
| `GET` | `/health` | Free | Health check, server wallet, chain info |
| `GET` | `/circuits` | Free | List available circuits and pricing |
| `POST` | `/prove/1x2` | $0.01 | Generate Groth16 proof (1-in, 2-out JoinSplit) |
| `POST` | `/prove/2x2` | $0.02 | Generate Groth16 proof (2-in, 2-out JoinSplit) |
| `POST` | `/verify/:circuit` | Free | Verify a proof |

## Circuits

| Circuit | Description | Constraints | Public Signals |
|---|---|---|---|
| `1x2` | JoinSplit(1,2,20) — 1 input, 2 outputs, Merkle depth 20 | 13,726 | 7 |
| `2x2` | JoinSplit(2,2,20) — 2 inputs, 2 outputs, Merkle depth 20 | 25,877 | 8 |

## Run Locally

```bash
# Install
npm install

# Circuit artifacts (not in repo — ~20MB)
# Place wasm/zkey/vkey files in circuits/1x2/ and circuits/2x2/

# Login to Tempo
tempo wallet login

# Start server
npx tsx src/server.ts

# Test (expects 402 → payment → proof)
npx tsx src/test-prove.ts

# Programmatic MPP client
npx tsx src/client-mpp.ts 1x2

# Agent demo (3 autonomous tasks, real payments)
npx tsx src/agent-consumer.ts

# Benchmark (run with NO_MPP=1 server)
npx tsx src/batch-benchmark.ts
```

## Agent Consumer Demo

An autonomous agent that discovers circuits, reasons about tasks, pays for proofs, and verifies results:

```
Task 1/3: Private Deposit — Shield 5 USDC
  > Agent: 1x2 circuit sufficient. Cost: $0.01. Worth it for privacy.
  [OK] Proof generated in 4346ms
  [OK] Proof VALID (275ms)
  $ Spent: $0.01

Task 2/3: Private Transfer — 25 USDC privately
  > Agent: Standard private transfer. Cost-effective at $0.01.
  [OK] Proof generated in 10061ms
  [OK] Proof VALID (47ms)
  $ Spent: $0.02

Task 3/3: Large Withdrawal — 100 USDC from privacy pool
  > Agent: Trivial cost for 100 USDC privacy.
  [OK] Proof generated in 3119ms
  [OK] Proof VALID (66ms)
  $ Total: $0.03 | 3/3 proofs verified
```

## Response Format

```json
{
  "success": true,
  "circuit": "1x2",
  "proof": { "pi_a": [...], "pi_b": [...], "pi_c": [...] },
  "publicSignals": ["...", "..."],
  "contractProof": ["uint256[8] for Solidity verifiers"],
  "generationTimeMs": 4795
}
```

## Built With

- [snarkjs](https://github.com/iden3/snarkjs) — Groth16 proof generation & verification
- [Hono](https://hono.dev) — Web framework
- [mppx](https://www.npmjs.com/package/mppx) — MPP 402 payment gating
- [Tempo](https://tempo.xyz) — Micropayment protocol
- [circomlibjs](https://github.com/iden3/circomlibjs) — Poseidon hashing
- [viem](https://viem.sh) — Wallet utilities

## License

MIT
