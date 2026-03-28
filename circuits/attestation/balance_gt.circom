pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

/// BalanceGT: Zero-knowledge proof that a committed value exceeds a threshold.
///
/// Public inputs:
///   - commitment : Poseidon(value, blinding) -- binds the prover to a specific value
///   - threshold  : the public threshold to prove against
///
/// Private inputs (witness):
///   - value      : the actual value (NEVER revealed)
///   - blinding   : random blinding factor (NEVER revealed)
///
/// The circuit enforces two constraints:
///   1. commitment == Poseidon(value, blinding)   -- proves knowledge of the opening
///   2. value > threshold                          -- the actual claim
///
/// The range check uses n-bit decomposition of (value - threshold - 1).
/// If the difference fits in n unsigned bits, then value - threshold >= 1,
/// i.e. value > threshold.  n=64 supports values up to 2^64 - 1.

template BalanceGT(n) {
    // --- Public inputs ---
    signal input commitment;
    signal input threshold;

    // --- Private inputs (witness) ---
    signal input value;
    signal input blinding;

    // 1. Verify commitment = Poseidon(value, blinding)
    component hasher = Poseidon(2);
    hasher.inputs[0] <== value;
    hasher.inputs[1] <== blinding;
    commitment === hasher.out;

    // 2. Prove value > threshold via bit decomposition
    //    difference = value - threshold  (must be >= 1)
    //    We decompose (difference - 1) into n bits.
    //    If it fits, then difference >= 1, so value > threshold.
    signal difference;
    difference <== value - threshold;

    signal diffMinusOne;
    diffMinusOne <== difference - 1;

    // Num2Bits(n) constrains that its input fits in n bits (unsigned).
    // If diffMinusOne < 0 (i.e., value <= threshold), this will fail
    // because a negative field element won't decompose into n bits.
    component bits = Num2Bits(n);
    bits.in <== diffMinusOne;
}

component main {public [commitment, threshold]} = BalanceGT(64);
