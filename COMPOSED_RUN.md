# Composed run: ERC-8274 inference + ERC-8354 (CAPV) on one flow

Two corners meeting on one action. ERC-8274 attests the AI inference ran (the recompute / proof
corner). CAPV proves the resulting action clears a policy that is never revealed (the confidential
corner). Same action, two orthogonal guarantees.

There are two levels. Start with the mock, then swap in your real verifier.

## 1. Shape check (no setup, runs in the suite)

`test/ComposedVerify.t.sol` uses a mock ERC-8274 verifier so you can see the composition shape with
zero config.

```bash
forge test --match-contract ComposedVerify -vv
```

## 2. Live run against YOUR real ERC-8274 verifier

`test/ComposedLiveRun.t.sol` calls a real deployed `IProofVerifier`. Point it at the chain where your
verifier lives, pass your inference proof, and it forks that chain and calls the real thing. No code
change needed, just env vars. If the env is unset the test skips, so it never breaks the normal suite.

```bash
RPC_URL=<rpc for the chain your verifier is on> \
ERC8274_VERIFIER=0x<your deployed IProofVerifier address> \
INFERENCE_INPUT_HASH=0x<inputHash> \
INFERENCE_OUTPUT_HASH=0x<outputHash> \
INFERENCE_PROOF=0x<proof bytes> \
INFERENCE_METADATA=0x<optional, defaults to empty> \
forge test --match-contract ComposedLiveRun -vvv
```

`IProofVerifier` here is exactly ERC-8274's:
`verify(bytes32 inputHash, bytes32 outputHash, bytes metadata, bytes proof) returns (bool)`.

## Binding the two to the same action (last step, together)

The CAPV half above runs the reference witness, so both layers execute but the verdict is not yet
bound to your inference's output. To make it one coherent action:

1. We agree on the action the agent takes from the inference output (target, value, calldata, nonce).
2. I issue a CAPV proof whose `actionCommitment` is the canonical `PolicyAction` commitment over that
   action (this is the byte-for-byte hash the circuit and the EVM both compute).
3. Swap the fixture proof and `Verdict` in `ComposedLiveRun` for that one. Nothing else changes.

Then it is one flow: your ERC-8274 verifier attests the inference, and CAPV attests the resulting
action clears a confidential allowlist, with the nullifier burned so the verdict is one-time.

Ping me with the action bytes and I will turn around the CAPV proof.
