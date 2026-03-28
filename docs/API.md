# ZKProver API Documentation

## Overview

ZKProver is a pay-per-proof zero-knowledge proving service. It generates and verifies Groth16 ZK proofs for JoinSplit circuits (private UTXO transactions), provides privacy-preserving shielded deposits/transfers/withdrawals, builds Merkle trees, computes ZK-friendly hashes, and issues credential attestations.

All paid endpoints use the **Tempo MPP (Micropayment Protocol)** for payment. When you call a paid endpoint without payment, the server returns HTTP 402 with payment instructions. The `tempo` CLI handles this automatically -- it detects the 402, pays the required amount in USDC on Tempo's network, and retries the request.

**Base URL:** `https://himess-zk-proof-service.hf.space`

**Payment chain:** Tempo Moderato (EIP-155 chain 42431)
**Payment asset:** USDC (pathUSD)
**Payment recipient:** `0x4013AE1C1473f6CB37AA44eedf58BDF7Fa4068F7`

---

## Quick Start

### 1. Install the Tempo CLI

```bash
npm install -g @anthropic-ai/agentcash
# or
npx tempo --help
```

### 2. Fund your wallet

```bash
tempo fund
```

### 3. Make your first request

```bash
# Free -- check service health
tempo request -t https://himess-zk-proof-service.hf.space/health

# Free -- list circuits and pricing
tempo request -t https://himess-zk-proof-service.hf.space/circuits

# Paid ($0.03) -- generate a shielded deposit proof
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"amount":"1000000"}' \
  https://himess-zk-proof-service.hf.space/privacy/deposit
```

---

## Authentication

ZKProver uses the **MPP 402 flow** for payment. There are no API keys or tokens.

### How it works

1. You send a request to a paid endpoint (e.g., `POST /prove/1x2`).
2. The server returns **HTTP 402 Payment Required** with a `PAYMENT-REQUIRED` header containing the price, recipient wallet, and accepted payment methods.
3. Your client (the `tempo` CLI or any MPP-compatible agent) reads the 402 response, constructs a USDC payment transaction on the Tempo Moderato chain, and resends the request with the payment proof in the `X-PAYMENT` header.
4. The server verifies payment and returns the result.

**Free endpoints** (health, circuits, pool, verify, merkle/verify, attest/verify) skip this flow entirely.

When using `tempo request`, steps 2-4 happen automatically. You just see the final result.

---

## Endpoints

### Free Endpoints

---

#### `GET /health`

Health check. Returns service status, wallet, and chain info.

**Price:** Free

**Response:**

```json
{
  "status": "ok",
  "wallet": "0x4013AE1C1473f6CB37AA44eedf58BDF7Fa4068F7",
  "chain": "tempo-moderato",
  "chainId": 42431,
  "privacyPool": "0x8F1ae8209156C22dFD972352A415880040fB0b0c",
  "poolChain": "base-sepolia"
}
```

**Example:**

```bash
tempo request -t https://himess-zk-proof-service.hf.space/health
```

---

#### `GET /circuits`

List available ZK circuits with constraint counts and pricing.

**Price:** Free

**Response:**

```json
{
  "circuits": [
    {
      "id": "1x2",
      "description": "1-input, 2-output JoinSplit",
      "constraintCount": 13726,
      "publicSignals": 5
    },
    {
      "id": "2x2",
      "description": "2-input, 2-output JoinSplit",
      "constraintCount": 27000,
      "publicSignals": 6
    }
  ],
  "pricing": {
    "1x2": { "amount": "0.01", "currency": "USDC", "description": "$0.01" },
    "2x2": { "amount": "0.02", "currency": "USDC", "description": "$0.02" }
  }
}
```

**Example:**

```bash
tempo request -t https://himess-zk-proof-service.hf.space/circuits
```

---

#### `GET /pool`

Privacy pool info. Returns contract addresses, chain info, and available circuits.

**Price:** Free

**Response:**

```json
{
  "pool": "0x8F1ae8209156C22dFD972352A415880040fB0b0c",
  "chain": "base-sepolia",
  "chainId": 84532,
  "usdc": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  "deployBlock": 38347380,
  "circuits": ["1x2", "2x2"],
  "merkleDepth": 20,
  "maxLeaves": 1048576
}
```

**Example:**

```bash
tempo request -t https://himess-zk-proof-service.hf.space/pool
```

---

#### `GET /llms.txt`

Agent discovery file. Plain text description of all endpoints for LLM-based agents.

**Price:** Free

**Example:**

```bash
tempo request -t https://himess-zk-proof-service.hf.space/llms.txt
```

---

#### `GET /openapi.json`

OpenAPI 3.1 specification for the service. Used by MPPscan and agent frameworks for discovery.

**Price:** Free

---

### Proving Endpoints

---

#### `POST /prove/1x2`

Generate a Groth16 ZK proof for a 1-input, 2-output JoinSplit circuit.

**Price:** $0.01

**Request body:**

```json
{
  "root": "12345678901234567890",
  "publicAmount": "1000000",
  "extDataHash": "0",
  "protocolFee": "0",
  "inputNullifiers": ["111222333"],
  "outputCommitments": ["444555666", "777888999"],
  "inAmount": ["1000000"],
  "inPrivateKey": ["1"],
  "inBlinding": ["0"],
  "inPathIndices": ["0"],
  "inPathElements": [["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]],
  "outAmount": ["1000000", "0"],
  "outPubkey": ["12345", "67890"],
  "outBlinding": ["42", "0"]
}
```

**Response:**

```json
{
  "success": true,
  "circuit": "1x2",
  "proof": {
    "pi_a": ["123...", "456...", "1"],
    "pi_b": [["789...", "012..."], ["345...", "678..."], ["1", "0"]],
    "pi_c": ["901...", "234...", "1"],
    "protocol": "groth16",
    "curve": "bn128"
  },
  "publicSignals": ["...", "...", "...", "...", "..."],
  "contractProof": ["0x...", "0x...", "0x...", "0x...", "0x...", "0x...", "0x...", "0x..."],
  "generationTimeMs": 3200
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d @input_1x2.json \
  https://himess-zk-proof-service.hf.space/prove/1x2
```

---

#### `POST /prove/2x2`

Generate a Groth16 ZK proof for a 2-input, 2-output JoinSplit circuit.

**Price:** $0.02

**Request body:** Same schema as `/prove/1x2` but with 2 entries in each `in*` array (two input UTXOs).

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d @input_2x2.json \
  https://himess-zk-proof-service.hf.space/prove/2x2
```

---

#### `POST /prove/batch`

Batch proof generation. Generates multiple proofs of the same circuit type in one request at a 20% discount.

**Price:** $0.008 per proof (vs $0.01 individual)
**Minimum:** 2 proofs
**Maximum:** 20 proofs

**Request body:**

```json
{
  "circuit": "1x2",
  "inputs": [
    { "root": "...", "publicAmount": "...", ... },
    { "root": "...", "publicAmount": "...", ... }
  ]
}
```

**Response:**

```json
{
  "success": true,
  "circuit": "1x2",
  "results": [
    {
      "proof": { ... },
      "publicSignals": ["..."],
      "contractProof": ["0x..."],
      "generationTimeMs": 3100
    },
    {
      "proof": { ... },
      "publicSignals": ["..."],
      "contractProof": ["0x..."],
      "generationTimeMs": 2900
    }
  ],
  "totalTimeMs": 6200,
  "count": 2,
  "pricing": {
    "perProof": "$0.008",
    "total": "$0.016",
    "regularTotal": "$0.02",
    "savings": "20% discount"
  }
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"circuit":"1x2","inputs":[...]}' \
  https://himess-zk-proof-service.hf.space/prove/batch
```

---

#### `POST /verify/:circuit`

Verify a previously generated Groth16 proof. Circuit must be `1x2` or `2x2`.

**Price:** Free

**Request body:**

```json
{
  "proof": {
    "pi_a": ["...", "...", "1"],
    "pi_b": [["...", "..."], ["...", "..."], ["1", "0"]],
    "pi_c": ["...", "...", "1"],
    "protocol": "groth16",
    "curve": "bn128"
  },
  "publicSignals": ["...", "...", "...", "...", "..."]
}
```

**Response:**

```json
{
  "success": true,
  "valid": true,
  "verificationTimeMs": 48
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"proof":{...},"publicSignals":[...]}' \
  https://himess-zk-proof-service.hf.space/verify/1x2
```

---

### Privacy Endpoints

These endpoints generate proofs for privacy-preserving financial operations using a Poseidon-based commitment scheme on a depth-20 Merkle tree. Amounts are in USDC micro-units (6 decimals: `"1000000"` = 1 USDC).

---

#### `POST /privacy/deposit`

Generate a shielded deposit proof (public to private). Moves funds from a public balance into the privacy pool.

**Price:** $0.03

**Request body:**

```json
{
  "amount": "10000000"
}
```

`amount` is in micro-USDC. `"10000000"` = 10 USDC.

**Response:**

```json
{
  "success": true,
  "operation": "deposit",
  "amount": "10000000",
  "proof": { ... },
  "publicSignals": ["..."],
  "commitment": "1234567890...",
  "valid": true,
  "generationTimeMs": 4200
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"amount":"10000000"}' \
  https://himess-zk-proof-service.hf.space/privacy/deposit
```

---

#### `POST /privacy/transfer`

Generate a private transfer proof (private to private). Transfers shielded funds to another recipient without revealing the amount or sender.

**Price:** $0.03

**Request body:**

```json
{
  "amount": "5000000",
  "recipientPubkey": "12345678901234567890"
}
```

`recipientPubkey` is the recipient's Poseidon public key (a field element as a decimal string).

**Response:**

```json
{
  "success": true,
  "operation": "transfer",
  "amount": "5000000",
  "recipientPubkey": "12345678901234567890",
  "proof": { ... },
  "publicSignals": ["..."],
  "paymentCommitment": "...",
  "changeCommitment": "...",
  "valid": true,
  "generationTimeMs": 4100
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"amount":"5000000","recipientPubkey":"12345678901234567890"}' \
  https://himess-zk-proof-service.hf.space/privacy/transfer
```

---

#### `POST /privacy/withdraw`

Generate a withdrawal proof (private to public). Moves shielded funds back to a public Ethereum address.

**Price:** $0.03

**Request body:**

```json
{
  "amount": "5000000",
  "recipient": "0xYourEthereumAddress"
}
```

**Response:**

```json
{
  "success": true,
  "operation": "withdraw",
  "amount": "5000000",
  "recipient": "0xYourEthereumAddress",
  "proof": { ... },
  "publicSignals": ["..."],
  "valid": true,
  "generationTimeMs": 3900
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"amount":"5000000","recipient":"0xYourEthereumAddress"}' \
  https://himess-zk-proof-service.hf.space/privacy/withdraw
```

---

### Merkle Tree Endpoints

---

#### `POST /merkle/build`

Build a Merkle tree from an array of leaf values. Returns the root and all intermediate layers.

**Price:** $0.01

**Request body:**

```json
{
  "leaves": ["alice", "bob", "charlie", "dave"],
  "depth": 4
}
```

`leaves` is required (non-empty array of strings). `depth` is optional.

**Response:**

```json
{
  "success": true,
  "root": "0x1a2b3c...",
  "depth": 4,
  "leafCount": 4,
  "layers": [
    ["0xaaa...", "0xbbb...", "0xccc...", "0xddd..."],
    ["0xeee...", "0xfff..."],
    ["0x111..."]
  ],
  "computeTimeMs": 12
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"leaves":["alice","bob","charlie","dave"]}' \
  https://himess-zk-proof-service.hf.space/merkle/build
```

---

#### `POST /merkle/prove`

Generate a Merkle inclusion proof for a specific leaf in a tree.

**Price:** $0.005

**Request body:**

```json
{
  "leaves": ["alice", "bob", "charlie", "dave"],
  "leafIndex": 1,
  "depth": 4
}
```

`leafIndex` is the zero-based index of the leaf to prove. `depth` is optional.

**Response:**

```json
{
  "success": true,
  "root": "0x1a2b3c...",
  "leaf": "0xbbb...",
  "leafIndex": 1,
  "pathElements": ["0xaaa...", "0xfff..."],
  "pathIndices": [1, 0],
  "computeTimeMs": 8
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"leaves":["alice","bob","charlie","dave"],"leafIndex":1}' \
  https://himess-zk-proof-service.hf.space/merkle/prove
```

---

#### `POST /merkle/verify`

Verify a Merkle inclusion proof against a known root.

**Price:** Free

**Request body:**

```json
{
  "root": "0x1a2b3c...",
  "leaf": "0xbbb...",
  "pathElements": ["0xaaa...", "0xfff..."],
  "pathIndices": [1, 0]
}
```

**Response:**

```json
{
  "success": true,
  "valid": true,
  "computeTimeMs": 2
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"root":"0x...","leaf":"0x...","pathElements":["0x..."],"pathIndices":[1,0]}' \
  https://himess-zk-proof-service.hf.space/merkle/verify
```

---

### Attestation Endpoints

These endpoints create Poseidon commitments and generate signed attestations proving properties about committed values without revealing the values themselves.

---

#### `POST /attest/commitment`

Create a Poseidon commitment to a value with a blinding factor.

**Price:** $0.001

**Request body:**

```json
{
  "value": "50000",
  "blinding": "98765432109876543210"
}
```

`value` is the secret value to commit to (decimal string). `blinding` is a random blinding factor for hiding.

**Response:**

```json
{
  "commitment": "1234567890123456789012345678901234567890",
  "value": "50000",
  "computeTimeMs": 5
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"value":"50000","blinding":"98765432109876543210"}' \
  https://himess-zk-proof-service.hf.space/attest/commitment
```

---

#### `POST /attest/balance-gt`

Prove that a committed value is greater than a threshold, without revealing the actual value.

**Price:** $0.005

**Request body:**

```json
{
  "commitment": "1234567890123456789012345678901234567890",
  "value": "50000",
  "blinding": "98765432109876543210",
  "threshold": "10000"
}
```

**Response:**

```json
{
  "valid": true,
  "attestation": {
    "type": "balance-gt",
    "commitment": "1234567890...",
    "threshold": "10000",
    "result": true,
    "signature": "..."
  },
  "computeTimeMs": 8
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"commitment":"...","value":"50000","blinding":"98765432109876543210","threshold":"10000"}' \
  https://himess-zk-proof-service.hf.space/attest/balance-gt
```

---

#### `POST /attest/range`

Prove that a committed value falls within a range `[min, max]`, without revealing the value.

**Price:** $0.005

**Request body:**

```json
{
  "commitment": "1234567890123456789012345678901234567890",
  "value": "50000",
  "blinding": "98765432109876543210",
  "min": "10000",
  "max": "100000"
}
```

**Response:**

```json
{
  "valid": true,
  "attestation": {
    "type": "range",
    "commitment": "...",
    "min": "10000",
    "max": "100000",
    "result": true,
    "signature": "..."
  },
  "computeTimeMs": 7
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"commitment":"...","value":"50000","blinding":"98765432109876543210","min":"10000","max":"100000"}' \
  https://himess-zk-proof-service.hf.space/attest/range
```

---

#### `POST /attest/membership`

Prove that a committed value is a member of a set (Merkle tree of allowed values), without revealing which member.

**Price:** $0.005

**Request body:**

```json
{
  "commitment": "1234567890123456789012345678901234567890",
  "value": "50000",
  "blinding": "98765432109876543210",
  "leaves": ["10000", "25000", "50000", "75000", "100000"]
}
```

**Response:**

```json
{
  "valid": true,
  "attestation": {
    "type": "membership",
    "commitment": "...",
    "setSize": 5,
    "result": true,
    "signature": "..."
  },
  "computeTimeMs": 15
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"commitment":"...","value":"50000","blinding":"98765432109876543210","leaves":["10000","25000","50000","75000","100000"]}' \
  https://himess-zk-proof-service.hf.space/attest/membership
```

---

#### `POST /attest/verify`

Verify an attestation signature returned by any of the attest endpoints.

**Price:** Free

**Request body:**

```json
{
  "attestation": {
    "type": "balance-gt",
    "commitment": "...",
    "threshold": "10000",
    "result": true,
    "signature": "..."
  }
}
```

**Response:**

```json
{
  "valid": true
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"attestation":{...}}' \
  https://himess-zk-proof-service.hf.space/attest/verify
```

---

### Hash Endpoints

ZK-friendly hash functions used in circuits and commitment schemes.

---

#### `POST /hash/poseidon`

Compute a Poseidon hash. Poseidon is the primary ZK-friendly hash used in the JoinSplit circuits and Merkle trees.

**Price:** $0.001

**Request body:**

```json
{
  "inputs": ["12345", "67890"]
}
```

`inputs` is a non-empty array of decimal string field elements.

**Response:**

```json
{
  "success": true,
  "hash": "9876543210987654321098765432109876543210",
  "inputCount": 2,
  "computeTimeMs": 3
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"inputs":["12345","67890"]}' \
  https://himess-zk-proof-service.hf.space/hash/poseidon
```

---

#### `POST /hash/mimc`

Compute a MiMC sponge hash. Accepts 1 or 2 inputs.

**Price:** $0.001

**Request body:**

```json
{
  "inputs": ["12345", "67890"]
}
```

Maximum 2 inputs.

**Response:**

```json
{
  "hash": "1111222233334444555566667777888899990000",
  "algorithm": "mimc",
  "inputCount": 2,
  "computeTimeMs": 45
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"inputs":["12345","67890"]}' \
  https://himess-zk-proof-service.hf.space/hash/mimc
```

---

#### `POST /hash/pedersen`

Compute a Pedersen hash over BabyJubJub. Inputs are converted to 32-byte big-endian buffers and concatenated before hashing.

**Price:** $0.001

**Request body:**

```json
{
  "inputs": ["12345", "67890"]
}
```

**Response:**

```json
{
  "hash": "2222333344445555666677778888999900001111",
  "algorithm": "pedersen",
  "inputCount": 2,
  "computeTimeMs": 120
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"inputs":["12345","67890"]}' \
  https://himess-zk-proof-service.hf.space/hash/pedersen
```

---

#### `POST /hash/keccak256`

Compute a Keccak-256 hash (Ethereum-compatible). Accepts hex (`0x...`) or plaintext string input.

**Price:** $0.001

**Request body (hex):**

```json
{
  "data": "0xdeadbeef"
}
```

**Request body (plaintext):**

```json
{
  "data": "hello world"
}
```

**Response:**

```json
{
  "hash": "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad",
  "algorithm": "keccak256",
  "inputSize": 11,
  "computeTimeMs": 1
}
```

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"data":"hello world"}' \
  https://himess-zk-proof-service.hf.space/hash/keccak256
```

---

### Compression Endpoint

---

#### `POST /proof/compress`

Compress a Groth16 proof into a minimal 256-byte format and generate Solidity-ready calldata. Useful for on-chain submission where gas costs matter.

**Price:** $0.002

**Request body:**

```json
{
  "proof": {
    "pi_a": ["123...", "456...", "1"],
    "pi_b": [["789...", "012..."], ["345...", "678..."], ["1", "0"]],
    "pi_c": ["901...", "234...", "1"],
    "protocol": "groth16",
    "curve": "bn128"
  },
  "publicSignals": ["...", "...", "...", "...", "..."]
}
```

**Response:**

```json
{
  "compressed": "0x007b...(512 hex chars)...",
  "solidityCalldata": "0x...",
  "format": "groth16-bn254-compressed",
  "originalSize": 1842,
  "compressedSize": 256,
  "compressionRatio": "86.1%",
  "computeTimeMs": 15
}
```

The `compressed` field contains the 8 key field elements (pi_a[0..1], pi_b[0][0..1], pi_b[1][0..1], pi_c[0..1]) as concatenated 32-byte hex values. The `solidityCalldata` field is formatted for direct use with a Solidity Groth16 verifier contract.

**Example:**

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"proof":{...},"publicSignals":[...]}' \
  https://himess-zk-proof-service.hf.space/proof/compress
```

---

## Use Cases

### "I want to prove my balance is above 10K without revealing it"

Use the attestation endpoints. First commit to your balance, then request a balance-greater-than attestation.

```bash
# Step 1: Create a commitment to your balance (value=50000, random blinding)
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"value":"50000","blinding":"7777777777"}' \
  https://himess-zk-proof-service.hf.space/attest/commitment

# Step 2: Prove balance > 10000 (you provide the value and blinding to the prover,
#          but only the commitment and threshold are public)
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"commitment":"<commitment_from_step1>","value":"50000","blinding":"7777777777","threshold":"10000"}' \
  https://himess-zk-proof-service.hf.space/attest/balance-gt

# Step 3: Anyone can verify the attestation (free)
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"attestation":<attestation_from_step2>}' \
  https://himess-zk-proof-service.hf.space/attest/verify
```

**Total cost:** $0.001 + $0.005 = $0.006

---

### "I want to generate a Merkle proof for a whitelist"

Build a Merkle tree from your list of allowed addresses/values, then generate an inclusion proof for a specific entry.

```bash
# Step 1: Build the tree from your whitelist
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"leaves":["0xAlice","0xBob","0xCharlie","0xDave"]}' \
  https://himess-zk-proof-service.hf.space/merkle/build

# Step 2: Generate proof that "0xBob" (index 1) is in the tree
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"leaves":["0xAlice","0xBob","0xCharlie","0xDave"],"leafIndex":1}' \
  https://himess-zk-proof-service.hf.space/merkle/prove

# Step 3: Verify the proof (free)
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"root":"<root>","leaf":"<leaf>","pathElements":["..."],"pathIndices":[...]}' \
  https://himess-zk-proof-service.hf.space/merkle/verify
```

**Total cost:** $0.01 + $0.005 = $0.015

---

### "I want a ZK proof for a JoinSplit transaction"

Use the proving endpoints to generate a Groth16 proof for your circuit inputs. Use the privacy endpoints if you want a simpler interface for deposit/transfer/withdraw operations.

**Simple way (privacy endpoints):**

```bash
# Deposit 10 USDC into the privacy pool
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"amount":"10000000"}' \
  https://himess-zk-proof-service.hf.space/privacy/deposit

# Transfer 5 USDC privately
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"amount":"5000000","recipientPubkey":"12345678901234567890"}' \
  https://himess-zk-proof-service.hf.space/privacy/transfer

# Withdraw 5 USDC back to public
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"amount":"5000000","recipient":"0xYourAddress"}' \
  https://himess-zk-proof-service.hf.space/privacy/withdraw
```

**Advanced way (raw circuit inputs):**

```bash
# Provide full circuit inputs for a 1x2 JoinSplit
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d @my_circuit_inputs.json \
  https://himess-zk-proof-service.hf.space/prove/1x2
```

---

### "I want to hash data with a ZK-friendly hash function"

Choose from four hash algorithms depending on your use case:

| Hash | Best for | Inputs |
|------|----------|--------|
| Poseidon | ZK circuits, Merkle trees, commitments | Array of field elements |
| MiMC | Alternative ZK hash, Tornado-style mixers | 1 or 2 field elements |
| Pedersen | Commitments on BabyJubJub curve | Array of field elements |
| Keccak256 | Ethereum compatibility, EVM verification | Hex or plaintext string |

```bash
# Poseidon (most common for ZK)
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"inputs":["12345","67890"]}' \
  https://himess-zk-proof-service.hf.space/hash/poseidon

# Keccak256 (Ethereum-compatible)
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"data":"hello world"}' \
  https://himess-zk-proof-service.hf.space/hash/keccak256
```

**Cost:** $0.001 per hash

---

### "I want to compress a proof for on-chain submission"

After generating a proof, compress it to reduce calldata size and get Solidity-ready format.

```bash
# Step 1: Generate the proof
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"amount":"1000000"}' \
  https://himess-zk-proof-service.hf.space/privacy/deposit

# Step 2: Compress it (pass the proof and publicSignals from step 1)
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"proof":<proof_from_step1>,"publicSignals":<signals_from_step1>}' \
  https://himess-zk-proof-service.hf.space/proof/compress
```

The compressed format reduces the proof from ~1.8KB JSON to 256 bytes. Typical compression ratio: ~86%.

**Cost:** $0.03 (proof) + $0.002 (compress) = $0.032

---

## Error Handling

### HTTP Status Codes

| Status | Meaning |
|--------|---------|
| 200 | Success |
| 400 | Bad request -- invalid JSON, missing fields, or invalid input |
| 402 | Payment required -- send payment via MPP and retry |
| 500 | Server error -- proof generation or computation failed |

### Common Errors

**Invalid JSON body**
```json
{ "error": "Invalid JSON body" }
```
Your request body is not valid JSON. Check for syntax errors.

**Missing required fields**
```json
{ "error": "Missing required fields: commitment, value, blinding, threshold" }
```
One or more required fields are missing from your request body.

**Invalid circuit type**
```json
{ "error": "Invalid circuit. Use '1x2' or '2x2'" }
```
The circuit parameter must be either `1x2` or `2x2`.

**Batch size out of range**
```json
{ "error": "Batch requires at least 2 inputs (use /prove/:circuit for single proofs)" }
```
Batch endpoint requires 2-20 inputs. Use the single proof endpoint for one proof.

**Proof generation failed**
```json
{ "error": "Proof generation failed", "details": "witness generation error..." }
```
The circuit inputs are invalid or inconsistent. Verify that all field elements, Merkle paths, nullifiers, and commitments are computed correctly.

**MiMC input limit**
```json
{ "error": "MiMC sponge accepts 1 or 2 inputs" }
```
The MiMC hash endpoint accepts at most 2 inputs.

**Invalid hex string**
```json
{ "error": "Invalid hex string" }
```
When using keccak256 with a `0x` prefix, the remaining characters must be valid hexadecimal.

---

## Pricing Table

| Endpoint | Method | Price |
|----------|--------|-------|
| `/health` | GET | Free |
| `/circuits` | GET | Free |
| `/pool` | GET | Free |
| `/llms.txt` | GET | Free |
| `/openapi.json` | GET | Free |
| `/.well-known/x402` | GET | Free |
| `/prove/1x2` | POST | $0.01 |
| `/prove/2x2` | POST | $0.02 |
| `/prove/batch` | POST | $0.008/proof |
| `/verify/:circuit` | POST | Free |
| `/privacy/deposit` | POST | $0.03 |
| `/privacy/transfer` | POST | $0.03 |
| `/privacy/withdraw` | POST | $0.03 |
| `/merkle/build` | POST | $0.01 |
| `/merkle/prove` | POST | $0.005 |
| `/merkle/verify` | POST | Free |
| `/attest/commitment` | POST | $0.001 |
| `/attest/balance-gt` | POST | $0.005 |
| `/attest/range` | POST | $0.005 |
| `/attest/membership` | POST | $0.005 |
| `/attest/verify` | POST | Free |
| `/hash/poseidon` | POST | $0.001 |
| `/hash/mimc` | POST | $0.001 |
| `/hash/pedersen` | POST | $0.001 |
| `/hash/keccak256` | POST | $0.001 |
| `/proof/compress` | POST | $0.002 |

**Payment method:** USDC via Tempo MPP (automatic 402 flow)
**Performance:** ~3-5s proof generation, ~50ms verification
**Circuits:** Groth16 on BN254 curve, 13,726 constraints (1x2), depth-20 Merkle tree
