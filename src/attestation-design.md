# ZK Attestation Design for ZKProver Service

## Status: Design Document
## Date: 2026-03-27
## Service: https://himess-zk-proof-service.hf.space

---

## 1. Executive Summary

This document designs three attestation types for the ZKProver service:

| Attestation | What it proves | Can use existing circuits? | Implementation tier |
|---|---|---|---|
| **balance-gt** | "My balance > X" | NO - needs new circuit | Tier 2 (new circuit) |
| **range-proof** | "Value in [min, max]" | NO - needs new circuit | Tier 2 (new circuit) |
| **membership** | "I'm in this Merkle set" | PARTIALLY - existing circuits do Merkle proofs but are coupled to JoinSplit logic | Tier 2 (new circuit) |
| **commitment-verify** | "I know the preimage of this commitment" | YES - uses existing Poseidon + service signing | **Tier 1 (NOW)** |

**Key finding:** The existing 1x2/2x2 JoinSplit circuits cannot be cleanly repurposed for attestations. They enforce UTXO conservation laws (sum of inputs = sum of outputs + publicAmount + fee) and nullifier constraints that are irrelevant to attestation use cases. Trying to "trick" them with dummy values would be fragile and semantically wrong.

**Recommended approach:** Ship Tier 1 (commitment-based attestations) immediately using existing Poseidon hashing infrastructure, then build dedicated attestation circuits for Tier 2.

---

## 2. Analysis: Why Existing Circuits Cannot Be Reused

### What the JoinSplit circuits enforce

The 1x2 circuit (13,726 constraints) enforces ALL of the following simultaneously:

```
1. Merkle membership: each input UTXO exists in the tree at `root`
2. Nullifier correctness: nullifier = Poseidon(commitment, leafIndex, privateKey)
3. Commitment correctness: commitment = Poseidon(amount, pubkey, blinding)
4. Ownership: pubkey = Poseidon(privateKey) for each input
5. Conservation: sum(inAmount) + publicAmount = sum(outAmount) + protocolFee
6. Output binding: output commitments match declared amounts/keys/blindings
7. Non-negativity: all amounts are in valid range
```

For a "balance > threshold" attestation, we only need constraints 1, 3, 4, and a comparison. Constraints 2, 5, 6 are unnecessary overhead and force the caller to fabricate dummy nullifiers, output commitments, and a balanced equation. This is:
- **Wasteful**: ~13K constraints when we need ~2K
- **Fragile**: dummy values must satisfy conservation law perfectly
- **Misleading**: the proof "proves" a JoinSplit transaction that never happened

**Verdict: New circuits are the correct path for real ZK attestations.**

---

## 3. Tier 1 — Commitment-Based Attestations (Implementable NOW)

These use the existing Poseidon hashing from `crypto.ts` and service-level signing. They are NOT zero-knowledge proofs — they are server-verified attestations backed by cryptographic commitments.

### 3.1 Architecture

```
Agent                          ZKProver Service
  |                                   |
  |-- POST /attest/commitment ------->|
  |   { commitment, value, blinding } |
  |                                   |-- Verify: Poseidon(value, blinding) == commitment
  |                                   |-- Check: value > threshold (or range, etc.)
  |                                   |-- Sign attestation
  |<--- { attestation, signature } ---|
```

**Trust model:** The agent trusts ZKProver not to leak the revealed value. The commitment proves the agent cannot change the value after the fact. The service signature proves ZKProver verified the claim. This is useful when the verifier trusts ZKProver but the agent wants commitment-binding (cannot lie about the value later).

### 3.2 API Endpoints

#### POST /attest/balance-gt — "My balance exceeds threshold"

```typescript
// Request
{
  "commitment": "1234...",     // Poseidon(balance, blinding) — public
  "balance": "5000000",        // actual balance — private, sent to service
  "blinding": "98765...",      // blinding factor — private, sent to service
  "threshold": "1000000"       // threshold to prove against — public
}

// Response (200 OK)
{
  "success": true,
  "attestation": {
    "type": "balance-gt",
    "commitment": "1234...",
    "threshold": "1000000",
    "satisfied": true,
    "timestamp": 1711540800,
    "serviceId": "zkprover-v1"
  },
  "signature": "0xabcdef...",  // service signs the attestation JSON
  "verificationTimeMs": 12
}
```

#### POST /attest/range — "My value is in [min, max]"

```typescript
// Request
{
  "commitment": "5678...",     // Poseidon(value, blinding)
  "value": "42000",            // actual value — private
  "blinding": "11111...",      // blinding factor — private
  "min": "10000",              // range lower bound — public
  "max": "100000"              // range upper bound — public
}

// Response (200 OK)
{
  "success": true,
  "attestation": {
    "type": "range",
    "commitment": "5678...",
    "min": "10000",
    "max": "100000",
    "satisfied": true,
    "timestamp": 1711540800,
    "serviceId": "zkprover-v1"
  },
  "signature": "0x...",
  "verificationTimeMs": 8
}
```

#### POST /attest/membership — "I'm in this set"

```typescript
// Request
{
  "root": "9999...",              // Merkle root of the set — public
  "leaf": "3333...",              // my leaf value — private
  "pathElements": ["a1", "b2", ...],  // Merkle path — private
  "pathIndices": [0, 1, 0, ...]       // left/right path — private
}

// Response (200 OK)
{
  "success": true,
  "attestation": {
    "type": "membership",
    "root": "9999...",
    "depth": 20,
    "satisfied": true,
    "timestamp": 1711540800,
    "serviceId": "zkprover-v1"
  },
  "signature": "0x...",
  "verificationTimeMs": 15
}
```

#### POST /attest/verify — Verify any attestation signature

```typescript
// Request
{
  "attestation": { ... },   // the attestation object from any /attest/* response
  "signature": "0x..."       // the signature from the response
}

// Response
{
  "valid": true,
  "signer": "0x4013AE1C1473f6CB37AA44eedf58BDF7Fa4068F7"
}
```

### 3.3 Implementation Code

This can be added directly to the existing `server.ts`:

```typescript
// --- Attestation Imports (add to top of server.ts) ---
import { initPoseidon } from "./crypto.js";
import { createHash, sign } from "crypto";

// --- Attestation Signing ---
// In production, use a dedicated attestation key. For now, reuse the server wallet.
async function signAttestation(attestation: Record<string, unknown>): Promise<string> {
  const canonical = JSON.stringify(attestation, Object.keys(attestation).sort());
  // Sign with the server's private key using EIP-191 personal_sign style
  const msgHash = createHash("sha256").update(canonical).digest();
  const signature = await account.signMessage({ message: { raw: msgHash } });
  return signature;
}

// --- Merkle verification using Poseidon ---
async function verifyMerklePath(
  leaf: bigint,
  pathElements: bigint[],
  pathIndices: number[],
  root: bigint,
): Promise<boolean> {
  const p = await initPoseidon();
  let current = leaf;
  for (let i = 0; i < pathElements.length; i++) {
    if (pathIndices[i] === 0) {
      current = p.hash2(current, pathElements[i]);
    } else {
      current = p.hash2(pathElements[i], current);
    }
  }
  return current === root;
}

// --- POST /attest/balance-gt ---
app.post("/attest/balance-gt", async (c) => {
  const body = await c.req.json();
  const { commitment, balance, blinding, threshold } = body;

  if (!commitment || !balance || !blinding || !threshold) {
    return c.json({ error: "Missing required fields: commitment, balance, blinding, threshold" }, 400);
  }

  const p = await initPoseidon();
  const computed = p.hash2(BigInt(balance), BigInt(blinding));

  if (computed.toString() !== commitment) {
    return c.json({ error: "Commitment mismatch — Poseidon(balance, blinding) != commitment" }, 400);
  }

  const satisfied = BigInt(balance) > BigInt(threshold);

  const attestation = {
    type: "balance-gt",
    commitment,
    threshold,
    satisfied,
    timestamp: Math.floor(Date.now() / 1000),
    serviceId: "zkprover-v1",
  };

  const signature = await signAttestation(attestation);

  return c.json({ success: true, attestation, signature, verificationTimeMs: 0 });
});

// --- POST /attest/range ---
app.post("/attest/range", async (c) => {
  const body = await c.req.json();
  const { commitment, value, blinding, min, max } = body;

  if (!commitment || value === undefined || !blinding || min === undefined || max === undefined) {
    return c.json({ error: "Missing required fields: commitment, value, blinding, min, max" }, 400);
  }

  const p = await initPoseidon();
  const computed = p.hash2(BigInt(value), BigInt(blinding));

  if (computed.toString() !== commitment) {
    return c.json({ error: "Commitment mismatch — Poseidon(value, blinding) != commitment" }, 400);
  }

  const v = BigInt(value);
  const satisfied = v >= BigInt(min) && v <= BigInt(max);

  const attestation = {
    type: "range",
    commitment,
    min,
    max,
    satisfied,
    timestamp: Math.floor(Date.now() / 1000),
    serviceId: "zkprover-v1",
  };

  const signature = await signAttestation(attestation);

  return c.json({ success: true, attestation, signature, verificationTimeMs: 0 });
});

// --- POST /attest/membership ---
app.post("/attest/membership", async (c) => {
  const body = await c.req.json();
  const { root, leaf, pathElements, pathIndices } = body;

  if (!root || !leaf || !pathElements || !pathIndices) {
    return c.json({ error: "Missing required fields: root, leaf, pathElements, pathIndices" }, 400);
  }

  const valid = await verifyMerklePath(
    BigInt(leaf),
    pathElements.map((e: string) => BigInt(e)),
    pathIndices.map((i: string | number) => Number(i)),
    BigInt(root),
  );

  const attestation = {
    type: "membership",
    root,
    depth: pathElements.length,
    satisfied: valid,
    timestamp: Math.floor(Date.now() / 1000),
    serviceId: "zkprover-v1",
  };

  const signature = await signAttestation(attestation);

  return c.json({ success: true, attestation, signature, verificationTimeMs: 0 });
});

// --- POST /attest/verify ---
app.post("/attest/verify", async (c) => {
  const body = await c.req.json();
  const { attestation, signature } = body;

  if (!attestation || !signature) {
    return c.json({ error: "Missing required fields: attestation, signature" }, 400);
  }

  const canonical = JSON.stringify(attestation, Object.keys(attestation).sort());
  const msgHash = createHash("sha256").update(canonical).digest();

  // Recover signer from signature
  const { verifyMessage } = await import("viem");
  const valid = await verifyMessage({
    address: account.address,
    message: { raw: msgHash },
    signature: signature as `0x${string}`,
  });

  return c.json({ valid, signer: account.address });
});
```

### 3.4 Pricing for Tier 1

| Endpoint | Cost | Rationale |
|---|---|---|
| POST /attest/balance-gt | $0.005 | 1 Poseidon hash + comparison |
| POST /attest/range | $0.005 | 1 Poseidon hash + 2 comparisons |
| POST /attest/membership | $0.005 | ~20 Poseidon hashes (Merkle path) |
| POST /attest/verify | Free | Just signature verification |

---

## 4. Tier 2 — True ZK Attestation Circuits (Requires Trusted Setup)

These are proper Groth16 circuits where the verifier learns NOTHING about the private inputs. The proof is verifiable by anyone without trusting ZKProver.

### 4.1 Circuit: balance-gt (BalanceGreaterThan)

Proves: "I know a balance and blinding such that Poseidon(balance, blinding) = commitment AND balance > threshold"

```circom
pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Proves: balance > threshold, given commitment = Poseidon(balance, blinding)
// Public: commitment, threshold
// Private: balance, blinding
template BalanceGreaterThan(N_BITS) {
    // Public inputs
    signal input commitment;     // Poseidon(balance, blinding) — known to verifier
    signal input threshold;      // minimum balance to prove — known to verifier

    // Private inputs
    signal input balance;        // actual balance — hidden from verifier
    signal input blinding;       // randomness — hidden from verifier

    // 1. Verify commitment
    component hasher = Poseidon(2);
    hasher.inputs[0] <== balance;
    hasher.inputs[1] <== blinding;
    hasher.out === commitment;

    // 2. Range-check balance (prevent overflow attacks)
    //    Ensure balance fits in N_BITS bits (e.g., 64 bits for token amounts)
    component balanceBits = Num2Bits(N_BITS);
    balanceBits.in <== balance;

    // 3. Range-check threshold
    component thresholdBits = Num2Bits(N_BITS);
    thresholdBits.in <== threshold;

    // 4. Prove balance > threshold
    //    Compute diff = balance - threshold. If balance > threshold, diff is in [1, 2^N_BITS).
    //    We check diff - 1 fits in N_BITS bits (ensures diff >= 1, i.e., balance > threshold).
    signal diff;
    diff <== balance - threshold;

    component diffMinusOneBits = Num2Bits(N_BITS);
    diffMinusOneBits.in <== diff - 1;
    // If balance <= threshold, diff - 1 would underflow and not fit in N_BITS bits.
    // The Num2Bits constraint would fail.
}

component main {public [commitment, threshold]} = BalanceGreaterThan(64);
```

**Constraint estimate:** ~800 constraints
- Poseidon(2): ~250 constraints
- 3x Num2Bits(64): ~192 constraints each = ~576
- Subtraction + wiring: ~10

### 4.2 Circuit: range-proof (ValueInRange)

Proves: "I know a value and blinding such that Poseidon(value, blinding) = commitment AND min <= value <= max"

```circom
pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Proves: min <= value <= max, given commitment = Poseidon(value, blinding)
// Public: commitment, min, max
// Private: value, blinding
template ValueInRange(N_BITS) {
    // Public inputs
    signal input commitment;
    signal input rangeMin;
    signal input rangeMax;

    // Private inputs
    signal input value;
    signal input blinding;

    // 1. Verify commitment
    component hasher = Poseidon(2);
    hasher.inputs[0] <== value;
    hasher.inputs[1] <== blinding;
    hasher.out === commitment;

    // 2. Range-check all values fit in N_BITS
    component valueBits = Num2Bits(N_BITS);
    valueBits.in <== value;

    component minBits = Num2Bits(N_BITS);
    minBits.in <== rangeMin;

    component maxBits = Num2Bits(N_BITS);
    maxBits.in <== rangeMax;

    // 3. Prove value >= min
    //    diff_low = value - min >= 0, checked by fitting in N_BITS
    signal diffLow;
    diffLow <== value - rangeMin;
    component diffLowBits = Num2Bits(N_BITS);
    diffLowBits.in <== diffLow;

    // 4. Prove value <= max
    //    diff_high = max - value >= 0, checked by fitting in N_BITS
    signal diffHigh;
    diffHigh <== rangeMax - value;
    component diffHighBits = Num2Bits(N_BITS);
    diffHighBits.in <== diffHigh;
}

component main {public [commitment, rangeMin, rangeMax]} = ValueInRange(64);
```

**Constraint estimate:** ~1,100 constraints
- Poseidon(2): ~250
- 5x Num2Bits(64): ~960
- Subtraction + wiring: ~10

### 4.3 Circuit: membership (MerkleMembership)

Proves: "I know a leaf value and Merkle path such that the path leads to root"

```circom
pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

// Proves Merkle membership: I know a leaf and path leading to root
// Public: root
// Private: leaf, pathElements[], pathIndices[]
template MerkleMembership(DEPTH) {
    // Public
    signal input root;

    // Private
    signal input leaf;
    signal input pathElements[DEPTH];
    signal input pathIndices[DEPTH];   // 0 or 1

    // Constrain pathIndices to be binary
    for (var i = 0; i < DEPTH; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;
    }

    // Walk up the tree
    component hashers[DEPTH];
    component mux[DEPTH];

    signal hashes[DEPTH + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < DEPTH; i++) {
        mux[i] = MultiMux1(2);

        // If pathIndices[i] == 0: hash(current, sibling)
        // If pathIndices[i] == 1: hash(sibling, current)
        mux[i].c[0][0] <== hashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== hashes[i];
        mux[i].s <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];

        hashes[i + 1] <== hashers[i].out;
    }

    // Final hash must equal root
    hashes[DEPTH] === root;
}

component main {public [root]} = MerkleMembership(20);
```

**Constraint estimate:** ~5,300 constraints
- 20x Poseidon(2): ~5,000
- 20x Mux + binary constraints: ~300

### 4.4 Constraint Summary and Setup Requirements

| Circuit | Constraints | Public Signals | Powers of Tau needed | Setup time (est.) |
|---|---|---|---|---|
| BalanceGreaterThan(64) | ~800 | 2 (commitment, threshold) | pot12 (4096) | ~5s |
| ValueInRange(64) | ~1,100 | 3 (commitment, min, max) | pot12 (4096) | ~5s |
| MerkleMembership(20) | ~5,300 | 1 (root) | pot14 (16384) | ~15s |
| JoinSplit 1x2 (existing) | 13,726 | 7 | already done | already done |
| JoinSplit 2x2 (existing) | 25,877 | 8 | already done | already done |

### 4.5 Trusted Setup Process (for future implementation)

Each new circuit requires its own Groth16 trusted setup:

```bash
# 1. Compile the circuit
circom circuits/balance_gt.circom --r1cs --wasm --sym -o circuits/balance_gt/

# 2. Download powers of tau (one-time, reusable across circuits)
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_14.ptau

# 3. Phase 2 setup (circuit-specific)
snarkjs groth16 setup circuits/balance_gt/balance_gt.r1cs powersOfTau28_hez_final_14.ptau circuits/balance_gt/balance_gt_0000.zkey

# 4. Contribute randomness (at least 1 contribution required)
snarkjs zkey contribute circuits/balance_gt/balance_gt_0000.zkey circuits/balance_gt/balance_gt_final.zkey --name="ZKProver contribution" -v

# 5. Export verification key
snarkjs zkey export verificationkey circuits/balance_gt/balance_gt_final.zkey circuits/balance_gt/verification_key.json

# 6. Test with a witness
node circuits/balance_gt/balance_gt_js/generate_witness.js circuits/balance_gt/balance_gt_js/balance_gt.wasm input.json witness.wtns
snarkjs groth16 prove circuits/balance_gt/balance_gt_final.zkey witness.wtns proof.json public.json
snarkjs groth16 verify circuits/balance_gt/verification_key.json public.json proof.json
```

**Limitation:** We cannot do trusted setup in this session. The circuits above are ready to compile and setup when the toolchain is available.

---

## 5. Tier 2 API Design (for when circuits are ready)

These endpoints would use the same `snarkjs.groth16.fullProve` / `verify` flow as the existing JoinSplit endpoints.

#### POST /prove/balance-gt — ZK proof of balance > threshold

```typescript
// Request — agent sends ONLY private inputs; service generates proof
{
  "balance": "5000000",        // private — never leaves the service
  "blinding": "98765...",      // private
  "threshold": "1000000"       // public — included in proof
}

// Response
{
  "success": true,
  "circuit": "balance-gt",
  "proof": { "pi_a": [...], "pi_b": [...], "pi_c": [...], ... },
  "publicSignals": [
    "1234...",    // commitment = Poseidon(balance, blinding)
    "1000000"     // threshold
  ],
  "contractProof": ["...", "...", "...", "...", "...", "...", "...", "..."],
  "generationTimeMs": 450
}

// The proof can be verified by ANYONE with the verification key.
// The verifier learns: "someone with a committed balance > 1,000,000 generated this proof"
// The verifier does NOT learn the actual balance or blinding.
```

#### POST /prove/range — ZK range proof

```typescript
// Request
{
  "value": "42000",
  "blinding": "11111...",
  "min": "10000",
  "max": "100000"
}

// Response
{
  "success": true,
  "circuit": "range",
  "proof": { ... },
  "publicSignals": [
    "5678...",    // commitment
    "10000",     // min
    "100000"     // max
  ],
  "contractProof": [...],
  "generationTimeMs": 500
}
```

#### POST /prove/membership — ZK Merkle membership proof

```typescript
// Request
{
  "leaf": "3333...",
  "pathElements": ["a1...", "b2...", ...],   // 20 elements
  "pathIndices": [0, 1, 0, 1, ...]           // 20 indices
}

// Response
{
  "success": true,
  "circuit": "membership",
  "proof": { ... },
  "publicSignals": [
    "9999..."    // root (computed by circuit, not provided by caller)
  ],
  "contractProof": [...],
  "generationTimeMs": 1200
}
```

### Tier 2 Pricing

| Endpoint | Cost | Rationale |
|---|---|---|
| POST /prove/balance-gt | $0.005 | ~800 constraints, fast proof |
| POST /prove/range | $0.005 | ~1,100 constraints |
| POST /prove/membership | $0.008 | ~5,300 constraints |
| POST /verify/balance-gt | Free | Verification only |
| POST /verify/range | Free | Verification only |
| POST /verify/membership | Free | Verification only |

---

## 6. Integration with Existing Prover Infrastructure

The `prover.ts` module needs minimal changes to support attestation circuits. The pattern is identical:

```typescript
// Updated CircuitType
export type CircuitType = "1x2" | "2x2" | "balance-gt" | "range" | "membership";

// Updated listCircuits()
export function listCircuits() {
  return [
    // Existing
    { id: "1x2", description: "JoinSplit(1,2,20)", constraintCount: 13726, publicSignals: 7 },
    { id: "2x2", description: "JoinSplit(2,2,20)", constraintCount: 25877, publicSignals: 8 },
    // New attestation circuits (Tier 2)
    { id: "balance-gt", description: "Balance > threshold attestation", constraintCount: 800, publicSignals: 2 },
    { id: "range", description: "Value in [min,max] range proof", constraintCount: 1100, publicSignals: 3 },
    { id: "membership", description: "Merkle set membership proof", constraintCount: 5300, publicSignals: 1 },
  ];
}

// Updated getArtifactPaths — same directory convention
function getArtifactPaths(circuit: CircuitType) {
  const dir = path.join(CIRCUITS_DIR, circuit);
  const prefixes: Record<CircuitType, string> = {
    "1x2": "joinSplit_1x2",
    "2x2": "joinSplit_2x2",
    "balance-gt": "balance_gt",
    "range": "value_in_range",
    "membership": "merkle_membership",
  };
  const prefix = prefixes[circuit];
  return {
    wasm: path.join(dir, `${prefix}.wasm`),
    zkey: path.join(dir, `${prefix}_final.zkey`),
    vkey: path.join(dir, "verification_key.json"),
  };
}
```

The `generateProof()` and `verifyProof()` functions need zero changes — they already accept arbitrary `Record<string, unknown>` inputs and delegate to snarkjs.

---

## 7. Security Considerations

### Tier 1 (Commitment-Based)

- **Trust assumption:** Caller trusts ZKProver service not to leak private values. This is suitable for agent-to-agent scenarios where ZKProver is a trusted intermediary.
- **Commitment binding:** Poseidon is collision-resistant over BN254. The commitment cryptographically binds the caller to their value.
- **Signature forgery:** Attestations are signed by the service wallet (`0x4013AE...`). Verifiers must check this address.
- **Replay protection:** Each attestation includes a timestamp. Verifiers should enforce freshness windows.
- **Field overflow:** All values must be < BN254 field prime (21888...617). The service must validate this.

### Tier 2 (ZK Circuits)

- **Soundness:** Groth16 proofs are computationally sound under the knowledge-of-exponent assumption on BN254.
- **Trusted setup:** Each circuit requires a ceremony. A compromised setup allows proof forgery. For production, use a multi-party ceremony (at least 1 honest participant).
- **Num2Bits overflow:** The `Num2Bits(64)` constraints prevent attackers from using field arithmetic wrap-around to fake balance > threshold when balance is actually small.
- **No private input leakage:** The proof reveals only the public signals. Balance, blinding, leaf values, and Merkle paths remain hidden.

---

## 8. Implementation Roadmap

### Phase 1 — NOW (this session)
1. Add Poseidon-based `/attest/balance-gt`, `/attest/range`, `/attest/membership` endpoints
2. Add `/attest/verify` for signature checking
3. Add to landing page and `/circuits` discovery
4. Gate behind MPP at $0.005 per attestation

### Phase 2 — Next session (requires circom toolchain)
1. Write circom files: `balance_gt.circom`, `value_in_range.circom`, `merkle_membership.circom`
2. Compile circuits
3. Run trusted setup (powers of tau + phase 2)
4. Generate WASM + zkey artifacts
5. Add `/prove/balance-gt`, `/prove/range`, `/prove/membership` endpoints
6. Add corresponding `/verify/*` endpoints

### Phase 3 — Production hardening
1. Multi-party trusted setup ceremony
2. On-chain Solidity verifiers for each circuit (using snarkjs `exportSolidityVerifier`)
3. Rate limiting and abuse prevention
4. Batch attestation endpoint (multiple claims in one request)

---

## 9. Complete Tier 1 Test Script

```typescript
// test-attestation.ts — run with: npx tsx src/test-attestation.ts
import { buildPoseidon } from "circomlibjs";

const SERVER = process.env.SERVER_URL || "http://localhost:3402";

async function main() {
  console.log("Building Poseidon...");
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const hash2 = (a: bigint, b: bigint): bigint => F.toObject(poseidon([a, b]));

  // --- Test 1: Balance > Threshold ---
  console.log("\n=== Test: balance-gt ===");
  const balance = 5000000n;   // 5 USDC
  const blinding1 = 123456789n;
  const commitment1 = hash2(balance, blinding1);

  const res1 = await fetch(`${SERVER}/attest/balance-gt`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      commitment: commitment1.toString(),
      balance: balance.toString(),
      blinding: blinding1.toString(),
      threshold: "1000000",  // prove balance > 1 USDC
    }),
  });
  const data1 = await res1.json();
  console.log("Result:", JSON.stringify(data1, null, 2));

  // --- Test 2: Range Proof ---
  console.log("\n=== Test: range ===");
  const value = 42000n;
  const blinding2 = 987654321n;
  const commitment2 = hash2(value, blinding2);

  const res2 = await fetch(`${SERVER}/attest/range`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      commitment: commitment2.toString(),
      value: value.toString(),
      blinding: blinding2.toString(),
      min: "10000",
      max: "100000",
    }),
  });
  const data2 = await res2.json();
  console.log("Result:", JSON.stringify(data2, null, 2));

  // --- Test 3: Membership ---
  console.log("\n=== Test: membership ===");
  // Build a small Merkle tree: depth 3, leaf at index 0
  const leaf = 999n;
  const empty = 0n;

  // Level 0: hash(leaf, empty)
  const h0 = hash2(leaf, empty);
  // Level 1: hash(h0, hash(empty, empty))
  const h_empty_0 = hash2(empty, empty);
  const h1 = hash2(h0, h_empty_0);
  // Level 2: hash(h1, hash(h_empty_1, h_empty_1))
  const h_empty_1 = hash2(h_empty_0, h_empty_0);
  const root = hash2(h1, h_empty_1);

  const res3 = await fetch(`${SERVER}/attest/membership`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      root: root.toString(),
      leaf: leaf.toString(),
      pathElements: [empty.toString(), h_empty_0.toString(), h_empty_1.toString()],
      pathIndices: [0, 0, 0],
    }),
  });
  const data3 = await res3.json();
  console.log("Result:", JSON.stringify(data3, null, 2));

  // --- Test 4: Verify attestation ---
  if (data1.success && data1.signature) {
    console.log("\n=== Test: verify attestation ===");
    const res4 = await fetch(`${SERVER}/attest/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        attestation: data1.attestation,
        signature: data1.signature,
      }),
    });
    const data4 = await res4.json();
    console.log("Verification:", JSON.stringify(data4, null, 2));
  }

  // --- Test 5: Should fail — wrong commitment ---
  console.log("\n=== Test: balance-gt with wrong blinding (should fail) ===");
  const res5 = await fetch(`${SERVER}/attest/balance-gt`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      commitment: commitment1.toString(),
      balance: balance.toString(),
      blinding: "999",  // wrong blinding
      threshold: "1000000",
    }),
  });
  const data5 = await res5.json();
  console.log("Result:", JSON.stringify(data5, null, 2));
}

main().catch(console.error);
```

---

## 10. Comparison: Tier 1 vs Tier 2

| Property | Tier 1 (Commitment) | Tier 2 (ZK Circuit) |
|---|---|---|
| Privacy from verifier | NO — service sees value | YES — service generates proof without learning anything (service sees inputs but proof hides them from everyone else) |
| Privacy from service | NO — service must see value | NO — service needs private inputs to generate witness |
| Trustless verification | NO — must trust service signature | YES — anyone with vkey can verify |
| On-chain verifiable | NO — only off-chain signature | YES — Solidity verifier contract |
| Implementation effort | Hours | Days (circuit + setup + testing) |
| Proof generation time | <10ms | ~0.5-1.5s |
| Available now | YES | NO (needs trusted setup) |

**Important nuance for Tier 2:** Even with ZK circuits, the ZKProver service sees the private inputs because the agent sends them for witness generation. The ZK property protects the data from *third-party verifiers*, not from the proving service itself. For full privacy from the prover, the agent would need to run the proof locally — but that defeats the purpose of a proving service.

This makes Tier 1 and Tier 2 closer in trust model than they appear: in both cases, the service sees private data. The difference is that Tier 2 proofs are independently verifiable without trusting the service, while Tier 1 attestations require trusting the service's signature.

---

## 11. Directory Structure (Target)

```
zk-proof-service/
  circuits/
    1x2/                       # existing
      joinSplit_1x2.wasm
      joinSplit_1x2_final.zkey
      verification_key.json
    2x2/                       # existing
      joinSplit_2x2.wasm
      joinSplit_2x2_final.zkey
      verification_key.json
    balance-gt/                # Tier 2 — future
      balance_gt.circom
      balance_gt.wasm
      balance_gt_final.zkey
      verification_key.json
    range/                     # Tier 2 — future
      value_in_range.circom
      value_in_range.wasm
      value_in_range_final.zkey
      verification_key.json
    membership/                # Tier 2 — future
      merkle_membership.circom
      merkle_membership.wasm
      merkle_membership_final.zkey
      verification_key.json
  src/
    server.ts                  # + attestation endpoints
    prover.ts                  # + attestation circuit types
    crypto.ts                  # existing Poseidon utilities
    attestation-design.md      # this document
```
