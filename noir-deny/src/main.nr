//! CAPV confidential denial circuit (MVP) — the confidential corner of the DENY board.
//!
//! Proves, in zero knowledge, that an agent action is DENIED by a policy that is committed
//! on-chain (as `policy_root`) but never revealed. The dual of the allowlist circuit: where
//! that one proves `decision == 1` and allowlist membership, this proves `decision == 0` and
//! denylist membership. The policy here is a committed denylist; the action's target being a
//! member of it is a confidential, valid reason to deny, and the denylist is never revealed.
//!
//! Six in-circuit obligations (mirror the ERC spec, DENY side):
//!   1. decision == DENY (this circuit only proves DENY verdicts).
//!   2. denylist membership: `target` is a leaf in the denylist whose root == `policy_root`.
//!   3. action commitment: keccak over the canonical PolicyAction preimage == `action_commitment`.
//!   4. nullifier: derived from (domain, agent, commitment, nonce) == `nullifier`.
//!   5. executor binding: `executor` is a committed public input, bound to the proof.
//!
//! The public inputs and preimage packing are byte-identical to the allowlist circuit, so a DENY
//! proof binds to the same on-chain `Verdict` shape and the same `PolicyAction` commitment. Only the
//! decision changes, and the meaning of `policy_root` (a denylist rather than an allowlist).
//!
//! Note on richer policies: "deny an action that is not explicitly allowed" is non-membership in the
//! allowlist, which needs a sorted/indexed Merkle tree and a range proof. That is future work. This
//! MVP proves the simpler, honest confidential denial: membership in a committed denylist.

use keccak256::keccak256;

global TREE_DEPTH: u32 = 8; // denylist up to 2^8 entries; raise as needed
global KIND_DENIED: u8 = 1; // a rule fired against the target (denylist membership)

fn main(
    // ---- public inputs: mirror the on-chain Verdict ----
    agent_id: pub Field,
    domain_id: pub Field,
    policy_root: pub Field, // = the denylist Merkle root (pedersen)
    action_commitment: pub [u8; 32], // = keccak(PolicyAction), full 256 bits
    nullifier: pub Field,
    decision: pub u8, // 0 = DENY
    policy_kind: pub u8, // 1 = DENIED
    executor: pub Field, // address permitted to consume; committed so the proof binds to it
    // ERC-8354 line 95: every Verdict field MUST be a public input and MUST NOT sit in
    // the private witness. `expiry` was omitted here while the Guard checked it on chain,
    // which left the proof unbound to it: the same proof verified under any expiry the
    // submitter chose. Appended last so no existing public-input index moves.
    expiry: pub Field,
    // ---- private witness ----
    chain_id: Field,
    target: Field, // call target address as an integer
    value: Field,
    call_data_hash: [u8; 32], // keccak(callData): a full 256-bit digest, which a BN254 Field cannot hold
    action_nonce: Field,
    index: Field, // leaf index of `target` in the denylist
    path: [Field; TREE_DEPTH], // sibling hashes bottom-to-top
) {
    // `expiry` is deliberately not constrained here: the Guard performs the time check and
    // the circuit has no notion of block time. It is public so the PROOF COMMITS TO IT,
    // which is the whole requirement. Verified by construction: proving at one expiry and
    // verifying at another fails in the reduction step. Do not delete this binding to
    // silence the unused warning; that is exactly the defect this line exists to close.
    let _ = expiry;

    // 1. DENY only
    assert(decision == 0);
    // The kind is committed, so a relying party cannot be handed a taxonomy the proof never established.
    assert(policy_kind == KIND_DENIED);

    // 5. Executor binding: executor is a committed public input, bound to the proof.
    assert(executor != 0);

    // 2. Denylist membership: recompute the denylist root from the leaf and assert it matches.
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
    let bits: [bool; TREE_DEPTH] = index.to_le_bits();
    let mut current = leaf;
    for i in 0..TREE_DEPTH {
        let sibling = path[i];
        let left = if bits[i] { sibling } else { current };
        let right = if bits[i] { current } else { sibling };
        current = std::hash::pedersen_hash([left, right]);
    }
    current
}

// Pack the PolicyAction fields into the 224-byte ABI-encoded preimage (7 x 32-byte words).
fn abi_encode_policy_action(
    chain_id: Field,
    domain_id: Field,
    agent_id: Field,
    target: Field,
    value: Field,
    call_data_hash: [u8; 32],
    action_nonce: Field,
) -> [u8; 224] {
    let field_words = [chain_id, domain_id, agent_id, target, value];
    let mut out: [u8; 224] = [0; 224];
    for w in 0..5 {
        let be: [u8; 32] = field_words[w].to_be_bytes();
        for b in 0..32 {
            out[w * 32 + b] = be[b];
        }
    }
    for b in 0..32 {
        out[5 * 32 + b] = call_data_hash[b];
    }
    let nonce_be: [u8; 32] = action_nonce.to_be_bytes();
    for b in 0..32 {
        out[6 * 32 + b] = nonce_be[b];
    }
    out
}

// Split a 32-byte value into two 16-byte Field limbs (hi, lo).
fn bytes32_to_two_fields(b: [u8; 32]) -> (Field, Field) {
    let mut hi: Field = 0;
    let mut lo: Field = 0;
    for i in 0..16 {
        hi = hi * 256 + (b[i] as Field);
        lo = lo * 256 + (b[i + 16] as Field);
    }
    (hi, lo)
}

// Self-consistent valid DENY witness built with the circuit's own helpers.
#[test]
fn test_deny_verdict() {
    let target: Field = 0x1234;
    let index: Field = 0;
    let path: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let leaf = std::hash::pedersen_hash([target]);
    let policy_root = compute_merkle_root(leaf, index, path);

    let chain_id: Field = 1;
    let domain_id: Field = 42;
    let agent_id: Field = 7;
    let value: Field = 0;
    let call_data_hash: [u8; 32] = [0; 32];
    let action_nonce: Field = 3;

    let commit = keccak256(
        abi_encode_policy_action(chain_id, domain_id, agent_id, target, value, call_data_hash, action_nonce),
        224,
    );
    let (chi, clo) = bytes32_to_two_fields(commit);
    let nullifier = std::hash::pedersen_hash([domain_id, agent_id, chi, clo, action_nonce]);
    let executor: Field = 0xE0;

    let EXPIRY: Field = 1900000000;
    main(
        agent_id, domain_id, policy_root, commit, nullifier, 0, KIND_DENIED, executor, EXPIRY, chain_id, target, value,
        call_data_hash, action_nonce, index, path,
    );
}
