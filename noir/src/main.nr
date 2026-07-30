//! CAPV allowlist policy circuit (MVP).
//!
//! Proves, in zero knowledge, that an agent action is permitted by a policy that is
//! committed on-chain (as `policy_root`) but never revealed. The v1 policy is an
//! allowlist: the action's target must be a member of a committed Merkle tree.
//!
//! Four in-circuit obligations (mirror the ERC spec):
//!   1. decision == ALLOW (this circuit only proves ALLOW verdicts).
//!   2. policy membership: `target` is a leaf in the allowlist whose root == `policy_root`.
//!   3. action commitment: keccak over the canonical PolicyAction preimage == `action_commitment`.
//!   4. nullifier: derived from (domain, agent, commitment, nonce) == `nullifier`.
//!
//! Notes for whoever runs this:
//!  - `action_commitment` is a full 256-bit keccak, so it is a public `[u8; 32]`, not a Field
//!    (a BN254 Field cannot hold 256 bits). `policy_root` and `nullifier` use pedersen (Field-sized).
//!  - The keccak preimage MUST match Solidity `PolicyAction.commit`:
//!    keccak256(abi.encode(chainId, domainId, agentId, target, value, callDataHash, actionNonce)).
//!    Each value is a 32-byte big-endian word; the order below must not change.
//!  - The allowlist Merkle tree uses pedersen for node hashing, so the off-chain tree builder
//!    must use the same. The on-chain Guard treats `policy_root` as an opaque commitment.
//!  - Version-sensitive calls (to_be_bytes / to_le_bits) are flagged; check against your nargo.

use dep::keccak256::keccak256;

global TREE_DEPTH: u32 = 8; // allowlist up to 2^8 entries; raise as needed

fn main(
    // ---- public inputs: mirror the on-chain Verdict ----
    agent_id: pub Field,
    domain_id: pub Field,
    policy_root: pub Field, // = the allowlist Merkle root (pedersen)
    action_commitment: pub [u8; 32], // = keccak(PolicyAction), full 256 bits
    nullifier: pub Field,
    decision: pub u8, // 1 = ALLOW
    // ---- private witness ----
    chain_id: Field,
    target: Field, // call target address as an integer
    value: Field,
    call_data_hash: Field, // keccak(callData), precomputed off-circuit
    action_nonce: Field,
    index: Field, // leaf index of `target` in the allowlist
    path: [Field; TREE_DEPTH], // sibling hashes bottom-to-top
) {
    // 1. ALLOW only
    assert(decision == 1);

    // 2. Policy membership: recompute the allowlist root from the leaf and assert it matches.
    let leaf = std::hash::pedersen_hash([target]);
    let computed_root = compute_merkle_root(leaf, index, path);
    assert(computed_root == policy_root);

    // 3. Action commitment: keccak over the canonical preimage, byte-for-byte vs the public value.
    let preimage = abi_encode_policy_action(
        chain_id, domain_id, agent_id, target, value, call_data_hash, action_nonce,
    );
    let commit = keccak256(preimage, 224);
    assert(commit == action_commitment);

    // 4. Nullifier = H(domain_id, agent_id, commitment_hi, commitment_lo, action_nonce)
    let (chi, clo) = bytes32_to_two_fields(commit);
    let n = std::hash::pedersen_hash([domain_id, agent_id, chi, clo, action_nonce]);
    assert(n == nullifier);
}

// Recompute a Merkle root from a leaf, its index, and its sibling path (pedersen nodes).
fn compute_merkle_root(leaf: Field, index: Field, path: [Field; TREE_DEPTH]) -> Field {
    let bits: [u1; TREE_DEPTH] = index.to_le_bits(); // low bit = level 0
    let mut current = leaf;
    for i in 0..TREE_DEPTH {
        let sibling = path[i];
        let left = if bits[i] == 0 { current } else { sibling };
        let right = if bits[i] == 0 { sibling } else { current };
        current = std::hash::pedersen_hash([left, right]);
    }
    current
}

// Pack the PolicyAction fields into the 224-byte ABI-encoded preimage (7 x 32-byte words).
// Order and width must match Solidity abi.encode exactly.
fn abi_encode_policy_action(
    chain_id: Field,
    domain_id: Field,
    agent_id: Field,
    target: Field,
    value: Field,
    call_data_hash: Field,
    action_nonce: Field,
) -> [u8; 224] {
    let words = [chain_id, domain_id, agent_id, target, value, call_data_hash, action_nonce];
    let mut out: [u8; 224] = [0; 224];
    for w in 0..7 {
        let be: [u8; 32] = words[w].to_be_bytes(); // 32-byte big-endian word
        for b in 0..32 {
            out[w * 32 + b] = be[b];
        }
    }
    out
}

// Split a 32-byte value into two 16-byte Field limbs (hi, lo) so a full commitment binds
// into a pedersen hash without overflowing the Field.
fn bytes32_to_two_fields(b: [u8; 32]) -> (Field, Field) {
    let mut hi: Field = 0;
    let mut lo: Field = 0;
    for i in 0..16 {
        hi = hi * 256 + (b[i] as Field);
        lo = lo * 256 + (b[i + 16] as Field);
    }
    (hi, lo)
}
