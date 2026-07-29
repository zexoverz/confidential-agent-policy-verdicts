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

The guard is **ERC-165** discoverable. The `IConfidentialPolicyVerdict` interfaceId is **`0x6c832e88`**
(XOR of its five function selectors — `verify`, `verdictDigest`, both `consume` overloads, and
`isConsumed`; the inherited `IERC165.supportsInterface` is excluded, per Solidity's `type().interfaceId`).

## Design decisions

Two questions were raised on the Magicians thread and resolved there; this implementation reflects
the resolution:

1. **Action-binding — canonical commitment.** `consume` receives a `Verdict` (with
   `actionCommitment`) but not the action params, so it cannot recompute the commitment itself. The
   standard fixes a **canonical action preimage** (`src/PolicyAction.sol`) that both the guarded
   contract and the proving program hash byte-for-byte — the guard stays a minimal verdict
   primitive, but the commitment is no longer per-integrator. The preimage is domain-separated
   (`chainId` + `domainId`) to block cross-chain / cross-domain replay. Modelled on ERC-4337's
   canonical UserOperation hash.
2. **Executor — cryptographic binding, not positional.** `consume` still succeeds for direct
   submission (`msg.sender == v.executor`), but a relayer may submit on the executor's behalf by
   presenting an **EIP-712 signature** by `v.executor` over `verdictDigest(v)` — verified with
   `SignatureChecker`, so a **smart-contract account (ERC-1271)** executor works too. The verdict's
   single-use nullifier gives the signature replay protection for free. Because the action is
   committed *and* the executor is bound by signature, front-running the submission is neutral:
   any submitter causes the identical committed execution.

## License

Released under [CC0-1.0](./LICENSE) — no rights reserved, matching EIP reference-implementation
convention.
