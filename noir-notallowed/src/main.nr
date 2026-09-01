//! CAPV deny-if-not-allowed circuit (v2) — the richer confidential denial.
//!
//! Two DENYs are not the same claim:
//!   - denylist membership (the `capv_denylist` circuit): a rule prohibits the target -> "denied".
//!   - allowlist NON-membership (this circuit): nothing authorized the target -> "not-permitted".
//! Both prove `decision == 0`. A committed `policy_kind` public input distinguishes them so a
//! consumer gating an irreversible action can tell "a rule refused this" from "no rule allowed it".
//!
//! Non-membership uses an INDEXED (sorted, linked) Merkle tree. Each leaf is
//! `(value, next_value, next_index)`, leaves sorted by value, each pointing to the next-larger one.
//! To prove `target` is absent, exhibit the "low leaf" L that brackets it:
//!   L.value < target  AND  ( L is the maximum (next_value == 0)  OR  target < L.next_value )
//! and prove L is a member of the tree. No leaf holds `target`, so `target` is not a member.
//!
//! DESIGN NOTES:
//!  1. Where `policy_kind` lives. Settled with Merlini on the 8274 thread: a committed public input,
//!     not policy_root semantics (a trusted label) and not domain separation alone. A relying party
//!     therefore cannot be handed a refusal kind the proof never established.
//!  2. Ordering soundness. `<` on Field is only sound when both operands are range-bounded. `target`
//!     and leaf values are addresses (< 2^160), and `addr_lt` decomposes both with `to_le_bits()`
//!     over 160 bits, which range-checks them as it compares. Settled, not a TODO.
//!  3. Tree well-formedness. Non-membership is sound only if the committed root is a correctly linked
//!     indexed tree (each leaf's next pointer really is its in-tree successor). That invariant is
//!     maintained by the off-chain tree builder in `witness.nr` (or by an insertion circuit), not
//!     proved here; it is the standard indexed-Merkle-tree assumption and belongs in Security
//!     Considerations. Still open.
//!
//! The public-input layout below is byte-identical to the ALLOW/denylist circuits except for the
//! added `policy_kind`, so a not-permitted DENY binds to the same on-chain Verdict once policy_kind
//! is threaded through the adapter.

use keccak256::keccak256;

mod witness; // off-chain indexed-tree witness builder; not part of the proving program

pub(crate) global TREE_DEPTH: u32 = 8;
pub(crate) global KIND_NOT_PERMITTED: u8 = 2; // decision == 0 because target is absent from the allowlist

fn main(
    // ---- public inputs: Verdict shape + policy_kind ----
    agent_id: pub Field,
    domain_id: pub Field,
    policy_root: pub Field, // indexed allowlist Merkle root (pedersen)
    action_commitment: pub [u8; 32],
    nullifier: pub Field,
    decision: pub u8, // 0 = DENY
    policy_kind: pub u8, // 2 = NOT_PERMITTED (allowlist non-membership)
    executor: pub Field,
    // ERC-8354 line 95: every Verdict field MUST be a public input and MUST NOT sit in
    // the private witness. `expiry` was omitted here while the Guard checked it on chain,
    // which left the proof unbound to it: the same proof verified under any expiry the
    // submitter chose. Appended last so no existing public-input index moves.
    expiry: pub Field,
    // ---- private witness: action preimage ----
    chain_id: Field,
    target: Field,
    value: Field,
    call_data_hash: [u8; 32],
    action_nonce: Field,
    // ---- private witness: the low leaf bracketing `target` ----
    low_value: Field,
    low_next_value: Field,
    low_next_index: Field,
    low_index: Field,
    low_path: [Field; TREE_DEPTH],
) {
    // `expiry` is deliberately not constrained here: the Guard performs the time check and
    // the circuit has no notion of block time. It is public so the PROOF COMMITS TO IT,
    // which is the whole requirement. Verified by construction: proving at one expiry and
    // verifying at another fails in the reduction step. Do not delete this binding to
    // silence the unused warning; that is exactly the defect this line exists to close.
    let _ = expiry;

    // 1. DENY, specifically the not-permitted kind.
    assert(decision == 0);
    assert(policy_kind == KIND_NOT_PERMITTED);

    // 2. Executor binding.
    assert(executor != 0);

    // 3. Non-membership of `target` in the indexed allowlist. `addr_lt` decomposes to 160 bits,
    // which both compares as unsigned AND range-checks the operands fit an address (design note 2).
    assert(addr_lt(low_value, target)); // strictly below: target is not the low leaf
    let is_max = low_next_value == 0;
    let below_successor = addr_lt(target, low_next_value);
    assert(is_max | below_successor); // target sits in the gap after L, or L is the maximum leaf

    // L is a member of the committed indexed tree.
    let leaf = std::hash::pedersen_hash([low_value, low_next_value, low_next_index]);
    let computed_root = compute_merkle_root(leaf, low_index, low_path);
    assert(computed_root == policy_root);

    // 4. Action commitment (identical packing to the ALLOW / denylist circuits).
    let preimage = abi_encode_policy_action(
        chain_id, domain_id, agent_id, target, value, call_data_hash, action_nonce,
    );
    let commit = keccak256(preimage, 224);
    assert(commit == action_commitment);

    // 5. Nullifier = H(domain_id, agent_id, commitment_hi, commitment_lo, action_nonce).
    let (chi, clo) = bytes32_to_two_fields(commit);
    let n = std::hash::pedersen_hash([domain_id, agent_id, chi, clo, action_nonce]);
    assert(n == nullifier);
}

global ADDR_BITS: u32 = 160; // targets and leaf values are Ethereum addresses

// Unsigned less-than for values that fit in ADDR_BITS bits. `to_le_bits` range-checks that both
// operands are < 2^ADDR_BITS, so the comparison is sound (a bare Field `<` is not). Returns a bool.
pub(crate) fn addr_lt(a: Field, b: Field) -> bool {
    let ab: [bool; ADDR_BITS] = a.to_le_bits();
    let bb: [bool; ADDR_BITS] = b.to_le_bits();
    let mut lt = false;
    let mut gt = false;
    for i in 0..ADDR_BITS {
        let idx = ADDR_BITS - 1 - i; // most-significant bit first
        let ai = ab[idx];
        let bi = bb[idx];
        let tied = !lt & !gt; // still equal on all higher bits
        lt = lt | (tied & !ai & bi); // a has 0, b has 1 at the first differing bit => a < b
        gt = gt | (tied & ai & !bi);
    }
    lt
}

// Recompute a Merkle root from a leaf, its index, and its sibling path (pedersen nodes).
pub(crate) fn compute_merkle_root(leaf: Field, index: Field, path: [Field; TREE_DEPTH]) -> Field {
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
pub(crate) fn abi_encode_policy_action(
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
pub(crate) fn bytes32_to_two_fields(b: [u8; 32]) -> (Field, Field) {
    let mut hi: Field = 0;
    let mut lo: Field = 0;
    for i in 0..16 {
        hi = hi * 256 + (b[i] as Field);
        lo = lo * 256 + (b[i + 16] as Field);
    }
    (hi, lo)
}

// Self-consistent non-membership witness: an allowlist {0x1000, 0x3000} as an indexed tree, proving
// target 0x2000 is absent (it sits in the gap after the low leaf 0x1000 -> 0x3000).
#[test]
fn test_not_permitted() {
    // Low leaf L = (value 0x1000, next_value 0x3000, next_index 1) at index 0.
    let low_value: Field = 0x1000;
    let low_next_value: Field = 0x3000;
    let low_next_index: Field = 1;
    let low_index: Field = 0;
    let low_path: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let leaf = std::hash::pedersen_hash([low_value, low_next_value, low_next_index]);
    let policy_root = compute_merkle_root(leaf, low_index, low_path);

    let target: Field = 0x2000; // absent: 0x1000 < 0x2000 < 0x3000
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
        agent_id, domain_id, policy_root, commit, nullifier, 0, KIND_NOT_PERMITTED, executor, EXPIRY,
        chain_id, target, value, call_data_hash, action_nonce,
        low_value, low_next_value, low_next_index, low_index, low_path,
    );
}
