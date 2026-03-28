# ZKProver Demo Script

A step-by-step walkthrough of the ZKProver service. Each step uses `tempo request` to call the live API with automatic MPP payment.

**Base URL:** `https://himess-zk-proof-service.hf.space`

**Prerequisites:**
```bash
# Install tempo CLI
npm install -g @anthropic-ai/agentcash

# Fund your wallet for paid requests
tempo fund
```

---

## Step 1: Check Service Health

Verify the service is running and see chain configuration.

```bash
tempo request -t https://himess-zk-proof-service.hf.space/health
```

**Expected output:**
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

**Cost:** Free

---

## Step 2: Generate a ZK Proof (Shielded Deposit)

Generate a Groth16 proof for depositing 1 USDC into the privacy pool.

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"amount":"1000000"}' \
  https://himess-zk-proof-service.hf.space/privacy/deposit
```

**What happens:** The server constructs a 1x2 JoinSplit circuit with your deposit amount, generates a Groth16 proof using snarkjs, and self-verifies before returning.

**Expected output (key fields):**
```json
{
  "success": true,
  "operation": "deposit",
  "amount": "1000000",
  "proof": { "pi_a": ["..."], "pi_b": [["..."], ["..."]], "pi_c": ["..."] },
  "publicSignals": ["...", "...", "...", "...", "..."],
  "commitment": "...",
  "valid": true,
  "generationTimeMs": 4200
}
```

Save the `proof` and `publicSignals` from this output for the next step.

**Cost:** $0.03

---

## Step 3: Verify the Proof

Verify the proof generated in Step 2. Paste the `proof` and `publicSignals` from the previous response.

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "proof": <paste proof object from step 2>,
    "publicSignals": <paste publicSignals array from step 2>
  }' \
  https://himess-zk-proof-service.hf.space/verify/1x2
```

**Expected output:**
```json
{
  "success": true,
  "valid": true,
  "verificationTimeMs": 48
}
```

**Cost:** Free

---

## Step 4: Create a Commitment

Create a Poseidon commitment to a secret value. This binds you to the value without revealing it.

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"value":"50000","blinding":"98765432109876543210"}' \
  https://himess-zk-proof-service.hf.space/attest/commitment
```

**Expected output:**
```json
{
  "commitment": "1234567890123456789012345678901234567890",
  "value": "50000",
  "computeTimeMs": 5
}
```

Save the `commitment` value for Steps 5 and beyond.

**Cost:** $0.001

---

## Step 5: Attest Balance > Threshold

Prove that your committed value (50,000) is greater than 10,000 without revealing the actual value.

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "commitment": "<commitment from step 4>",
    "value": "50000",
    "blinding": "98765432109876543210",
    "threshold": "10000"
  }' \
  https://himess-zk-proof-service.hf.space/attest/balance-gt
```

**Expected output:**
```json
{
  "valid": true,
  "attestation": {
    "type": "balance-gt",
    "commitment": "...",
    "threshold": "10000",
    "result": true,
    "signature": "..."
  },
  "computeTimeMs": 8
}
```

The `attestation` object is a signed statement that anyone can verify (Step 5b, free):

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"attestation": <paste attestation object from above>}' \
  https://himess-zk-proof-service.hf.space/attest/verify
```

**Cost:** $0.005 (verification is free)

---

## Step 6: Build a Merkle Tree

Build a Merkle tree from a set of values (e.g., a whitelist of allowed addresses).

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"leaves":["alice","bob","charlie","dave","eve","frank","grace","heidi"]}' \
  https://himess-zk-proof-service.hf.space/merkle/build
```

**Expected output:**
```json
{
  "success": true,
  "root": "0x...",
  "depth": 3,
  "leafCount": 8,
  "layers": [
    ["0x...", "0x...", "0x...", "0x...", "0x...", "0x...", "0x...", "0x..."],
    ["0x...", "0x...", "0x...", "0x..."],
    ["0x...", "0x..."],
    ["0x..."]
  ],
  "computeTimeMs": 12
}
```

**Cost:** $0.01

---

## Step 7: Generate a Merkle Inclusion Proof

Prove that "charlie" (index 2) is included in the Merkle tree.

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"leaves":["alice","bob","charlie","dave","eve","frank","grace","heidi"],"leafIndex":2}' \
  https://himess-zk-proof-service.hf.space/merkle/prove
```

**Expected output:**
```json
{
  "success": true,
  "root": "0x...",
  "leaf": "0x...",
  "leafIndex": 2,
  "pathElements": ["0x...", "0x...", "0x..."],
  "pathIndices": [0, 1, 0],
  "computeTimeMs": 8
}
```

Verify the proof (free):

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "root": "<root from above>",
    "leaf": "<leaf from above>",
    "pathElements": <pathElements from above>,
    "pathIndices": <pathIndices from above>
  }' \
  https://himess-zk-proof-service.hf.space/merkle/verify
```

**Cost:** $0.005 (verification is free)

---

## Step 8: Hash with Poseidon

Compute a Poseidon hash -- the same hash function used inside the JoinSplit circuits.

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"inputs":["12345","67890"]}' \
  https://himess-zk-proof-service.hf.space/hash/poseidon
```

**Expected output:**
```json
{
  "success": true,
  "hash": "...",
  "inputCount": 2,
  "computeTimeMs": 3
}
```

Try other hash functions too:

```bash
# MiMC sponge hash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"inputs":["12345","67890"]}' \
  https://himess-zk-proof-service.hf.space/hash/mimc

# Pedersen hash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"inputs":["12345","67890"]}' \
  https://himess-zk-proof-service.hf.space/hash/pedersen

# Keccak256 (Ethereum-compatible)
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"data":"hello world"}' \
  https://himess-zk-proof-service.hf.space/hash/keccak256
```

**Cost:** $0.001 per hash

---

## Step 9: Compress a Proof

Take a Groth16 proof from Step 2 and compress it for on-chain submission.

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "proof": <paste proof object from step 2>,
    "publicSignals": <paste publicSignals array from step 2>
  }' \
  https://himess-zk-proof-service.hf.space/proof/compress
```

**Expected output:**
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

The `compressed` field is the 256-byte proof (8 x 32-byte field elements). The `solidityCalldata` is ready for a Solidity Groth16 verifier contract.

**Cost:** $0.002

---

## Full Demo Cost Summary

| Step | Endpoint | Cost |
|------|----------|------|
| 1. Health check | GET /health | Free |
| 2. Generate proof | POST /privacy/deposit | $0.03 |
| 3. Verify proof | POST /verify/1x2 | Free |
| 4. Create commitment | POST /attest/commitment | $0.001 |
| 5. Balance attestation | POST /attest/balance-gt | $0.005 |
| 5b. Verify attestation | POST /attest/verify | Free |
| 6. Build Merkle tree | POST /merkle/build | $0.01 |
| 7. Merkle inclusion proof | POST /merkle/prove | $0.005 |
| 7b. Verify Merkle proof | POST /merkle/verify | Free |
| 8. Poseidon hash | POST /hash/poseidon | $0.001 |
| 9. Compress proof | POST /proof/compress | $0.002 |
| **Total** | | **$0.054** |

---

## Bonus: Advanced Flows

### Private Transfer

Send 5 USDC privately to another user:

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"amount":"5000000","recipientPubkey":"12345678901234567890"}' \
  https://himess-zk-proof-service.hf.space/privacy/transfer
```

### Private Withdrawal

Withdraw 5 USDC from the privacy pool back to a public address:

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"amount":"5000000","recipient":"0x4013AE1C1473f6CB37AA44eedf58BDF7Fa4068F7"}' \
  https://himess-zk-proof-service.hf.space/privacy/withdraw
```

### Range Attestation

Prove a value is between 10,000 and 100,000:

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "commitment": "<your commitment>",
    "value": "50000",
    "blinding": "98765432109876543210",
    "min": "10000",
    "max": "100000"
  }' \
  https://himess-zk-proof-service.hf.space/attest/range
```

### Set Membership Attestation

Prove your value is in an allowed set without revealing which one:

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "commitment": "<your commitment>",
    "value": "50000",
    "blinding": "98765432109876543210",
    "leaves": ["10000","25000","50000","75000","100000"]
  }' \
  https://himess-zk-proof-service.hf.space/attest/membership
```

### Batch Proving (20% Discount)

Generate multiple proofs in one request:

```bash
tempo request -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"circuit":"1x2","inputs":[<input1>,<input2>,<input3>]}' \
  https://himess-zk-proof-service.hf.space/prove/batch
```

### List Circuits and Pricing

```bash
tempo request -t https://himess-zk-proof-service.hf.space/circuits
```

### Pool Configuration

```bash
tempo request -t https://himess-zk-proof-service.hf.space/pool
```
