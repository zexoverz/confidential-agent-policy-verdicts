//! Off-chain witness builder for the not-permitted circuit.
//!
//! Non-membership is only as good as the tree it is proved against: the circuit checks that the low
//! leaf `L` is in the committed tree and brackets `target`, but it cannot check that the tree is a
//! correctly linked indexed tree (design note 3 in `main.nr`). That invariant is this builder's job.
//!
//! It is written in Noir, not a host language, on purpose. The commitment, the nullifier and every
//! tree node have to be computed *bit-identically* to the circuit; here they are computed by calling
//! the circuit's own `abi_encode_policy_action`, `bytes32_to_two_fields` and `pedersen_hash`, so the
//! two cannot drift. It also adds no toolchain — the repo already pins `nargo`.
//!
//! Layout of the tree it builds (the Aztec-style indexed tree):
//!   - leaf 0 is the sentinel head `(0, min(allowlist), 1)`. Address 0 is not a valid allowlist
//!     entry, so the head is the only leaf whose value is 0, and it brackets every target below the
//!     minimum. Empty slots hash to `0`, NOT to `pedersen([0, 0, 0])` — an all-zero *leaf* would be
//!     a second in-tree leaf with `value == 0` and `next_value == 0`, i.e. a valid low leaf for any
//!     target, which would prove non-membership of allowlisted addresses.
//!   - allowlist entry `k` (ascending) sits at leaf `k + 1` as `(value, next_value, next_index)`,
//!     the last one closing the list with `(value, 0, 0)`.
//!
//! Run it with `nargo test --show-output`; the emitted block is a complete `Prover.toml`.

use crate::{
    abi_encode_policy_action, addr_lt, bytes32_to_two_fields, compute_merkle_root, main,
    KIND_NOT_PERMITTED, TREE_DEPTH,
};
use keccak256::keccak256;

global TREE_LEAVES: u32 = 256; // 1 << TREE_DEPTH

/// The action a witness is built for. Mirrors the private half of the circuit's PolicyAction.
pub(crate) struct Action {
    pub(crate) chain_id: Field,
    pub(crate) domain_id: Field,
    pub(crate) agent_id: Field,
    pub(crate) target: Field,
    pub(crate) value: Field,
    pub(crate) call_data_hash: [u8; 32],
    pub(crate) action_nonce: Field,
    pub(crate) executor: Field,
}

/// A complete not-permitted witness: everything `main()` takes, public and private.
pub(crate) struct Witness {
    pub(crate) policy_root: Field,
    pub(crate) action_commitment: [u8; 32],
    pub(crate) nullifier: Field,
    pub(crate) low_value: Field,
    pub(crate) low_next_value: Field,
    pub(crate) low_next_index: Field,
    pub(crate) low_index: Field,
    pub(crate) low_path: [Field; TREE_DEPTH],
}

/// Build the indexed-tree leaf hashes for a sorted allowlist, and assert the input really is one.
///
/// Rejecting an unsorted, duplicated or zero-valued allowlist here is what keeps the linked-list
/// invariant true, which is the assumption the circuit's soundness rests on.
pub(crate) fn build_leaves<let N: u32>(allowlist: [Field; N]) -> [Field; TREE_LEAVES] {
    assert(N + 1 <= TREE_LEAVES, "allowlist does not fit the tree at TREE_DEPTH");

    for k in 0..N {
        assert(allowlist[k] != 0, "0 is the sentinel head, not a valid allowlist entry");
        if k > 0 {
            assert(addr_lt(allowlist[k - 1], allowlist[k]), "allowlist must be strictly ascending");
        }
    }

    let mut leaves: [Field; TREE_LEAVES] = [0; TREE_LEAVES]; // empty slots hash to 0, not to a leaf

    // Sentinel head: value 0, pointing at the smallest allowlist entry.
    let head_next_value = if N == 0 { 0 } else { allowlist[0] };
    let head_next_index: Field = if N == 0 { 0 } else { 1 };
    leaves[0] = std::hash::pedersen_hash([0, head_next_value, head_next_index]);

    for k in 0..N {
        let has_successor = k + 1 < N;
        let next_value = if has_successor { allowlist[k + 1] } else { 0 };
        let next_index: Field = if has_successor { (k + 2) as Field } else { 0 };
        leaves[k + 1] = std::hash::pedersen_hash([allowlist[k], next_value, next_index]);
    }

    leaves
}

/// Merkle root over the leaves plus the sibling path (bottom-to-top) for `index`.
pub(crate) fn root_and_path(
    leaves: [Field; TREE_LEAVES],
    index: u32,
) -> (Field, [Field; TREE_DEPTH]) {
    let mut level = leaves;
    let mut idx = index;
    let mut path: [Field; TREE_DEPTH] = [0; TREE_DEPTH];

    for d in 0..TREE_DEPTH {
        let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        path[d] = level[sibling];
        // Collapse in place. Node j reads 2j and 2j+1, which are never below j, so the valid
        // prefix of the next level is written from still-valid inputs.
        for j in 0..TREE_LEAVES / 2 {
            level[j] = std::hash::pedersen_hash([level[2 * j], level[2 * j + 1]]);
        }
        idx = idx / 2;
    }

    (level[0], path)
}

/// The leaf index of the low leaf bracketing `target`, or a failed assertion if `target` is present.
///
/// Index 0 (the sentinel head) is the answer for any target below the minimum entry.
pub(crate) fn low_leaf_index<let N: u32>(allowlist: [Field; N], target: Field) -> u32 {
    assert(target != 0, "target must be a nonzero address");

    let mut low: u32 = 0;
    let mut is_member = false;
    for k in 0..N {
        if allowlist[k] == target {
            is_member = true;
        }
        if addr_lt(allowlist[k], target) {
            low = k + 1;
        }
    }

    assert(!is_member, "target is IN the allowlist: no non-membership witness exists");
    low
}

/// Build the full witness for `action.target` being absent from `allowlist`.
///
/// The commitment and nullifier are computed with the circuit's own helpers, then the whole thing is
/// run through `main()` — so a witness that returns from here is one the circuit accepts.
pub(crate) fn build_witness<let N: u32>(allowlist: [Field; N], action: Action) -> Witness {
    let leaves = build_leaves(allowlist);
    let low_index = low_leaf_index(allowlist, action.target);
    let (policy_root, low_path) = root_and_path(leaves, low_index);

    // Re-derive the low leaf's fields the same way `build_leaves` laid them out.
    let is_head = low_index == 0;
    let k = if is_head { 0 } else { low_index - 1 };
    let low_value = if is_head { 0 } else { allowlist[k] };
    let has_successor = if is_head { N > 0 } else { k + 1 < N };
    let succ = if is_head { 0 } else { if k + 1 < N { k + 1 } else { 0 } };
    let low_next_value = if has_successor { allowlist[succ] } else { 0 };
    let low_next_index: Field = if has_successor { (succ + 1) as Field } else { 0 };

    let commit = keccak256(
        abi_encode_policy_action(
            action.chain_id,
            action.domain_id,
            action.agent_id,
            action.target,
            action.value,
            action.call_data_hash,
            action.action_nonce,
        ),
        224,
    );
    let (chi, clo) = bytes32_to_two_fields(commit);
    let nullifier =
        std::hash::pedersen_hash([action.domain_id, action.agent_id, chi, clo, action.action_nonce]);

    // Self-check: the emitted witness must satisfy every constraint the circuit imposes.
    main(
        action.agent_id,
        action.domain_id,
        policy_root,
        commit,
        nullifier,
        0,
        KIND_NOT_PERMITTED,
        action.executor,
        action.chain_id,
        action.target,
        action.value,
        action.call_data_hash,
        action.action_nonce,
        low_value,
        low_next_value,
        low_next_index,
        low_index as Field,
        low_path,
    );

    // The bracketing the circuit checks, restated as a builder-side sanity check. The sentinel head
    // needs no special case: its value is 0 and `target` is asserted nonzero.
    assert(addr_lt(low_value, action.target));
    assert((low_next_value == 0) | addr_lt(action.target, low_next_value));

    Witness {
        policy_root,
        action_commitment: commit,
        nullifier,
        low_value,
        low_next_value,
        low_next_index,
        low_index: low_index as Field,
        low_path,
    }
}

/// Print a complete `Prover.toml`, in the same field order as `main()`.
pub(crate) fn emit_prover_toml(action: Action, w: Witness) {
    println("----- BEGIN Prover.toml -----");
    let agent_id = action.agent_id;
    println(f"agent_id = \"{agent_id}\"");
    let domain_id = action.domain_id;
    println(f"domain_id = \"{domain_id}\"");
    let policy_root = w.policy_root;
    println(f"policy_root = \"{policy_root}\"");
    let action_commitment = w.action_commitment;
    println(f"action_commitment = {action_commitment}");
    let nullifier = w.nullifier;
    println(f"nullifier = \"{nullifier}\"");
    println("decision = \"0\"");
    println("policy_kind = \"2\"");
    let executor = action.executor;
    println(f"executor = \"{executor}\"");
    let chain_id = action.chain_id;
    println(f"chain_id = \"{chain_id}\"");
    let target = action.target;
    println(f"target = \"{target}\"");
    let value = action.value;
    println(f"value = \"{value}\"");
    let call_data_hash = action.call_data_hash;
    println(f"call_data_hash = {call_data_hash}");
    let action_nonce = action.action_nonce;
    println(f"action_nonce = \"{action_nonce}\"");
    let low_value = w.low_value;
    println(f"low_value = \"{low_value}\"");
    let low_next_value = w.low_next_value;
    println(f"low_next_value = \"{low_next_value}\"");
    let low_next_index = w.low_next_index;
    println(f"low_next_index = \"{low_next_index}\"");
    let low_index = w.low_index;
    println(f"low_index = \"{low_index}\"");
    println("low_path = [");
    for d in 0..TREE_DEPTH {
        let node = w.low_path[d];
        println(f"  \"{node}\",");
    }
    println("]");
    println("----- END Prover.toml -----");
}

// The allowlist the checked-in fixture is built against: four addresses a treasury agent may call.
// Sorted ascending, as an indexed tree requires.
pub(crate) fn fixture_allowlist() -> [Field; 4] {
    [
        0x1111111111111111111111111111111111111111,
        0x4444444444444444444444444444444444444444,
        0x8888888888888888888888888888888888888888,
        0xcccccccccccccccccccccccccccccccccccccccc,
    ]
}

// The action the checked-in fixture denies: a call to an address nobody allowlisted. It falls in the
// gap between 0x4444... and 0x8888..., so the low leaf is the second entry.
//
// `domain_id` is 43 (0x2b) rather than 42 because 0x2a is already taken on the live Sepolia registry
// 0xBDD6aB65C86fb8f0C47069a0562652d448E98cea by the confidential DENY leg, and `registerDomain`
// reverts with `DomainExists()`. It is a public input and feeds both the commitment preimage and the
// nullifier, so changing it means regenerating the proof, not editing a constant.
pub(crate) fn fixture_action() -> Action {
    Action {
        chain_id: 1,
        domain_id: 43,
        agent_id: 7,
        target: 0x5555555555555555555555555555555555555555,
        value: 0,
        call_data_hash: [0; 32],
        action_nonce: 3,
        executor: 0xE0,
    }
}

/// Emits the `Prover.toml` for the checked-in not-permitted fixture.
#[test]
fn build_fixture_witness() {
    let action = fixture_action();
    let w = build_witness(fixture_allowlist(), action);
    assert(w.low_value == 0x4444444444444444444444444444444444444444);
    assert(w.low_next_value == 0x8888888888888888888888888888888888888888);
    assert(w.low_index == 2);
    emit_prover_toml(action, w);
}

/// The one that matters: a target that IS on the allowlist must not yield a witness.
#[test(should_fail_with = "target is IN the allowlist: no non-membership witness exists")]
fn member_target_has_no_witness() {
    let mut action = fixture_action();
    action.target = 0x8888888888888888888888888888888888888888; // third allowlist entry
    let _ = build_witness(fixture_allowlist(), action);
}

/// Same, for the smallest entry — the one a naive builder is most likely to mis-bracket.
#[test(should_fail_with = "target is IN the allowlist: no non-membership witness exists")]
fn smallest_member_has_no_witness() {
    let mut action = fixture_action();
    action.target = 0x1111111111111111111111111111111111111111;
    let _ = build_witness(fixture_allowlist(), action);
}

/// A target below the minimum entry is bracketed by the sentinel head at leaf 0.
#[test]
fn target_below_minimum_uses_sentinel_head() {
    let mut action = fixture_action();
    action.target = 0x0000000000000000000000000000000000000abc;
    let w = build_witness(fixture_allowlist(), action);
    assert(w.low_index == 0);
    assert(w.low_value == 0);
    assert(w.low_next_value == 0x1111111111111111111111111111111111111111);
}

/// A target above the maximum entry is bracketed by the tail leaf, which closes the list.
#[test]
fn target_above_maximum_uses_tail_leaf() {
    let mut action = fixture_action();
    action.target = 0xffffffffffffffffffffffffffffffffffffffff;
    let w = build_witness(fixture_allowlist(), action);
    assert(w.low_index == 4);
    assert(w.low_value == 0xcccccccccccccccccccccccccccccccccccccccc);
    assert(w.low_next_value == 0); // the maximum leaf
}

/// An unsorted allowlist is rejected rather than silently producing an unsound root.
#[test(should_fail_with = "allowlist must be strictly ascending")]
fn unsorted_allowlist_is_rejected() {
    let _ = build_leaves([
        0x8888888888888888888888888888888888888888,
        0x1111111111111111111111111111111111111111,
    ]);
}

/// Address 0 is the sentinel head's value, so it cannot also be an allowlist entry.
#[test(should_fail_with = "0 is the sentinel head, not a valid allowlist entry")]
fn zero_allowlist_entry_is_rejected() {
    let _ = build_leaves([0, 0x1111111111111111111111111111111111111111]);
}

/// The root the builder computes is the root the circuit recomputes from the low leaf and its path.
#[test]
fn path_reproduces_the_root() {
    let allowlist = fixture_allowlist();
    let leaves = build_leaves(allowlist);
    let (root, path) = root_and_path(leaves, 2);
    let leaf = std::hash::pedersen_hash([
        allowlist[1],
        allowlist[2],
        3,
    ]);
    assert(compute_merkle_root(leaf, 2, path) == root);
}
