# SP1 Policy Interpreter (proving program)

The **load-bearing design choice** of this ERC: we prove a *fixed interpreter*, not a
compiled policy. The ruleset is a **private witness**; the `Verdict` fields are the
**public inputs**. Because the program is fixed, `programKey` (the SP1 vkey) stays constant
across weekly policy changes — only the ERC-7812 root moves. No new verifier per rule change.

## Proof obligations (what the program MUST enforce)

Public inputs = the ABI-encoded `Verdict` (agentId, domainId, policyRoot, actionCommitment,
executor, expiry, nullifier, decision). Private witness = the ruleset + the action preimage
+ the ERC-7812 inclusion proof.

1. `H(ruleset)` = a `policyCommitment` that is **included in `policyRoot`** (ERC-7812 SMT
   inclusion proof under key `H(domainId, version)`). `H` = Poseidon for the deployed registry.
2. The private action preimage `(target, value, callData, actionNonce)` hashes to
   `actionCommitment = keccak256(abi.encode(chainid, agentId, target, value, keccak256(callData), actionNonce))`.
   (SP1 exposes keccak256 as a precompile, so this matches the EVM's hash for free.)
3. Evaluating the ruleset over the action + agent context yields `decision`.
   The program **computes** `decision` — it is never accepted as an input to be attested.
4. `nullifier = H(domainId, agentId, actionCommitment, actionNonce)` — derived in-circuit.
5. `executor` and every other Verdict field are committed as public inputs (executor binding
   is what stops a mempool front-run — see Security Considerations in the spec).

Output: a Groth16-wrapped proof verifiable on-chain by `IVerifier.verifyProof(programKey, abi.encode(v), proof)`.

## Status
Skeleton. `program/src/main.rs` documents the obligations; the ruleset language, the Poseidon
inclusion-proof gadget, and the Groth16 wrapper are the remaining work. Build target: `sp1-sdk`.
