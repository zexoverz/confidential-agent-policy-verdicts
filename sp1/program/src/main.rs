//! Confidential Agent Policy Verdict — SP1 interpreter (SKELETON).
//!
//! Proves: a private ruleset (committed in the ERC-7812 policy root) evaluated a private
//! action to `decision`, binding the result to the public `Verdict`. See ../README.md.
//!
//! NOTE: skeleton only. The ruleset language, Poseidon inclusion-proof gadget, and Groth16
//! wrapper are TODO. This documents the in-circuit obligations as a starting point.

// #![no_main]
// sp1_zkvm::entrypoint!(main);

/// Public inputs — mirror the on-chain `Verdict` struct (all committed).
struct PublicVerdict {
    agent_id: [u8; 32],
    domain_id: [u8; 32],
    policy_root: [u8; 32],
    action_commitment: [u8; 32],
    executor: [u8; 20],
    expiry: u64,
    nullifier: [u8; 32],
    decision: u8,
}

/// Private witness — never leaves the prover.
struct Witness {
    ruleset: Vec<u8>,       // the secret policy
    // action preimage:
    target: [u8; 20],
    value: [u8; 32],
    call_data: Vec<u8>,
    action_nonce: [u8; 32],
    version: u64,           // policy version -> key = H(domain_id, version)
    inclusion_proof: Vec<u8>, // ERC-7812 SMT path for policyCommitment under policy_root
}

fn main() {
    // let public: PublicVerdict = sp1_zkvm::io::read();
    // let w: Witness = sp1_zkvm::io::read();

    // 1) policy_commitment = H(ruleset); assert inclusion under policy_root at H(domain_id, version).
    //    verify_smt_inclusion(public.policy_root, poseidon(domain_id, version), poseidon(w.ruleset), w.inclusion_proof)

    // 2) recompute action_commitment over the CANONICAL preimage (must match src/PolicyAction.sol
    //    byte-for-byte — same field order) and assert == public.action_commitment.
    //    assert_eq!(
    //        keccak(chainid, domain_id, agent_id, target, value, keccak(call_data), action_nonce),
    //        public.action_commitment
    //    )

    // 3) decision = evaluate_ruleset(&w.ruleset, action_ctx, agent_ctx);  // COMPUTED, not attested
    //    assert_eq!(decision, public.decision)

    // 4) nullifier = H(domain_id, agent_id, action_commitment, action_nonce)
    //    assert_eq!(nullifier, public.nullifier)

    // commit public inputs -> proof
}
