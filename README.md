# zk-proof-service

**Pay-per-proof ZK proving service via MPP**

Groth16 ZK proof generation as a service. Agents and clients pay $0.01--$0.02 per proof using [Tempo's MPP (Micropayment Protocol)](https://tempo.xyz). Supports JoinSplit circuits for private UTXO transactions.

## How It Works

```
Client                          ZK Proof Service
  |                                    |
  |-- POST /prove/1x2 --------------->|
  |<------------ 402 Payment Required -|
  |                                    |
  |-- MPP Payment (Tempo pathUSD) ---->|
  |<------------ 200 OK --------------|
  |    { proof, publicSignals,         |
  |      contractProof, timeMs }       |
  |                                    |
  |-- POST /verify/1x2 (free) ------->|
  |<------------ { valid: true } ------|
```

The server uses [mppx](https://www.npmjs.com/package/mppx) to gate proof generation behind a 402 paywall. Clients pay in pathUSD on Tempo Moderato (chain 42431). Verification is free.

## Performance

| Metric | Time |
|---|---|
| Proof generation (warm) | ~1.4s |
| Proof generation (first run) | ~12s |
| Verification | ~16ms |

## Endpoints

| Method | Path | Cost | Description |
|---|---|---|---|
| `GET` | `/health` | Free | Health check, server wallet, chain info |
| `GET` | `/circuits` | Free | List available circuits and pricing |
| `POST` | `/prove/1x2` | $0.01 | Generate Groth16 proof (1-in, 2-out JoinSplit) |
| `POST` | `/prove/2x2` | $0.02 | Generate Groth16 proof (2-in, 2-out JoinSplit) |
| `POST` | `/verify/:circuit` | Free | Verify a proof (1x2 or 2x2) |

## Circuits

| Circuit | Description | Constraints | Public Signals |
|---|---|---|---|
| `1x2` | JoinSplit(1,2,20) -- 1 input, 2 outputs, Merkle depth 20 | 13,726 | 7 |
| `2x2` | JoinSplit(2,2,20) -- 2 inputs, 2 outputs, Merkle depth 20 | 25,877 | 8 |

## Quick Start

### 1. Install dependencies

```bash
npm install
```

### 2. Set up circuit artifacts

Circuit WASM and zkey files are not included in the repo (~20MB). Download or generate them:

```bash
mkdir -p circuits/1x2 circuits/2x2

# Place the following files:
#   circuits/1x2/joinSplit_1x2.wasm
#   circuits/1x2/joinSplit_1x2_final.zkey
#   circuits/1x2/verification_key.json
#   circuits/2x2/joinSplit_2x2.wasm
#   circuits/2x2/joinSplit_2x2_final.zkey
#   circuits/2x2/verification_key.json
```

You can compile these from the JoinSplit circom circuits using [snarkjs](https://github.com/iden3/snarkjs) and a Powers of Tau ceremony, or ask a team member for the artifacts.

### 3. Login to Tempo (for MPP payments)

```bash
npm i -g @aspect-build/tempo
tempo wallet login
```

### 4. Start the server

```bash
npx tsx src/server.ts
```

The server starts on `http://localhost:3402` and auto-funds itself on Tempo Moderato testnet.

## Client Usage

### Using `tempo request` CLI

```bash
# 1x2 proof ($0.01)
tempo request POST http://localhost:3402/prove/1x2 \
  --body '{"root":"0", "publicAmount":"1000", ...}'

# 2x2 proof ($0.02)
tempo request POST http://localhost:3402/prove/2x2 \
  --body '{"root":"0", "publicAmount":"1000", ...}'
```

### Using the MPP client (TypeScript)

```bash
TEMPO_KEY=0x... npx tsx src/client-mpp.ts 1x2
```

The client auto-handles the 402 challenge, signs a Tempo payment, and retries -- all in one call via `mppx.fetch()`.

### Direct test (no payment, if MPP disabled)

```bash
npx tsx src/test-prove.ts
```

## Response Format

```json
{
  "success": true,
  "circuit": "1x2",
  "proof": { "pi_a": [...], "pi_b": [...], "pi_c": [...] },
  "publicSignals": ["...", "..."],
  "contractProof": ["0x...", "0x...", "0x...", "0x...", "0x...", "0x...", "0x...", "0x..."],
  "generationTimeMs": 1423
}
```

The `contractProof` field is a `uint256[8]` array formatted for on-chain Solidity verifiers.

## Built With

- [snarkjs](https://github.com/iden3/snarkjs) -- Groth16 proof generation and verification
- [Hono](https://hono.dev) -- Lightweight web framework
- [mppx](https://www.npmjs.com/package/mppx) -- MPP middleware for 402 payment gating
- [Tempo](https://tempo.xyz) -- Micropayment protocol and chain
- [circomlibjs](https://github.com/iden3/circomlibjs) -- Poseidon hashing for circuit inputs
- [viem](https://viem.sh) -- Ethereum/Tempo wallet utilities

## License

MIT
