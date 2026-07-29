# Confidential Agent Policy Verdicts — Reference Implementation

Reference implementation of the draft ERC **Confidential Agent Policy Verdicts**: a
pre-execution allow/deny verdict on an autonomous agent's action, proven in zero-knowledge
against a policy that is *committed to but never disclosed on-chain*.

- Discussion: [Ethereum Magicians thread](https://ethereum-magicians.org/t/draft-idea-confidential-agent-policy-verdicts/29088)
- Builds on ERC-8004 (agent identity) and ERC-7812 (evidence registry).

> Status: **draft / work in progress.** The Solidity guard, registry, and Test Cases suite are
> complete and passing; the SP1 proving program is a documented skeleton, not a finished circuit.

## What's here

| Path | What |
|------|------|
| `src/IConfidentialPolicyVerdict.sol` | Normative core: the `Verdict` struct + Guard interface |
| `src/IPolicyDomainRegistry.sol` | Recommended companion registry interface |
| `src/IVerifier.sol` | ZK proof verifier interface (`programKey` + public inputs + proof) |
| `src/ConfidentialPolicyVerdict.sol` | **The Guard** — `verify` / `consume` / `isConsumed`, checks in spec order |
| `src/PolicyDomainRegistry.sol` | Concrete registry: domains, root rotation with grace, immediate revocation |
| `src/GuardedExecutor.sol` | Example: recompute `actionCommitment` (binds chainid + nonce) → consume → execute |
| `src/mocks/MockVerifier.sol` | Test double for the verifier |
| `test/ConfidentialPolicyVerdict.t.sol` | The spec's Test Cases as a Foundry suite (10 cases) |
| `sp1/` | Interpreter proving-program skeleton (the load-bearing "fixed interpreter") |

## Build & test

```bash
git submodule update --init --recursive   # pulls forge-std (or: forge install)
forge build
forge test -vvv
```

Requires [Foundry](https://book.getfoundry.sh/getting-started/installation). Tested with
forge 1.5.1, Solc 0.8.28 — the suite is 10/10 green.

## How it fits together

`consume(Verdict, proof)` runs seven checks in this exact order, and reverts on the first failure:

1. domain is active
2. `decision == ALLOW`
3. `executor == msg.sender`
4. verdict not expired
5. verdict not already consumed (nullifier unseen)
6. `policyRoot` currently acceptable for the domain
7. proof verifies

On success it records the nullifier and emits `VerdictConsumed`. `verify()` is the view-only
counterpart and wraps the verifier in try/catch, so a *malformed* proof returns `false` rather
than reverting — while `consume` reverts `InvalidProof`.

The verifier sits behind `IVerifier.verifyProof(programKey, publicInputs, proof)`, keeping the
guard proving-system agnostic (SP1 / Groth16 / RISC0 all slot in behind the same call).

## Open design questions

These are live and being discussed on the Magicians thread — feedback welcome:

1. **Where does action-binding live?** `consume` receives a `Verdict` (with `actionCommitment`)
   but not the action params, so it cannot recompute the commitment itself. Here, the *guarded
   contract* (`GuardedExecutor`) recomputes and compares before calling `consume`. Should the
   guard stay a minimal verdict primitive (this choice), or should the standard define a single
   entrypoint that takes action + verdict together?
2. **`v.executor` semantics through a guarded contract.** `consume` requires
   `v.executor == msg.sender`, but in the guarded-contract flow `msg.sender` is the contract, so
   the executor binds to the contract rather than the user — reopening front-running of
   `execute()`. Executor = direct submitter, or executor = end EOA with a trusted relayer?

## License

Released under [CC0-1.0](./LICENSE) — no rights reserved, matching EIP reference-implementation
convention.
