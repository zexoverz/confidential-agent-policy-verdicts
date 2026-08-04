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

## The CAPV leg is already bound to the t/28083 #150 action

You published a real action tuple and a signed `/review` verdict in the ERC-8274 thread (post #150).
The CAPV side is now bound to those exact bytes, so this is no longer "ping me for a proof" — the
proof exists and consumes on-chain today:

```bash
forge test --match-test test_capv_leg_binds_babyblue_action -vv
```

That test needs no env and no fork. It registers the run's domain, then consumes a real CAPV proof whose
`actionCommitment` is the canonical `PolicyAction` commitment over your tuple, burning the nullifier.

The bound values (Sepolia Multicall3 `aggregate3([])`, `actionNonce` 5, `executor`
`0x1C21…9093`, `agentId` 54848):

| field | value |
|-------|-------|
| `domainId` | `0x16079127bc55bd85d480837115b9bd82d26f03809c0bc4c6c80f7220836afad0` (your proposed `keccak256("erc8274-t28083-composed-live-run")`) |
| `policyRoot` | `0x204a14dc3ab2fdead5450192caea7428c2751b53a95b57d22f93cccb61af19a8` (allowlist of one entry: the Multicall3 target; the policy itself never goes on-chain) |
| `actionCommitment` | `0x5b5ec31c336cc8f95dc6d9025d1d008c6ed2cd5067b9c421b1d36927e230173a` |
| `nullifier` | `0x17f36ca085e9f988cc9e033ea510d5b6963265cb99e57e9677b0658531e0315f` |

Reproduce `actionCommitment` yourself:
`cast keccak $(cast abi-encode "f(uint256,bytes32,uint256,address,uint256,bytes32,uint256)" 11155111 0x16079127bc55bd85d480837115b9bd82d26f03809c0bc4c6c80f7220836afad0 54848 0xcA11bde05977b3631167028862bE2a173976CA11 0 0xcfacbfe211cf3be67a1d64a6499a2af0ae475e2c0965c2a42f969d243df2b6cd 5)`

Binding a full 256-bit `callDataHash` (yours is `0xcfac…`, larger than the BN254 field) needed a circuit
fix: `callDataHash` now enters the proving program as raw bytes, not a field element. Public inputs are
unchanged, so the `Verdict` envelope, the adapter, and the 38-input layout are identical.

## Both legs on one flow

`test_live_erc8274_plus_capv` in `ComposedLiveRun.t.sol` binds the ERC-8274 leg to the same tuple. Point
it at your deployed verifier and it forks your chain, verifies your inference proof, then consumes the
CAPV verdict above. Then all three verdicts (CAPV confidential, your `/review`, TMerlini's `recompute`)
present through the same `IProofVerifier` boundary and land on `/ledger`, checkable against one socket.
