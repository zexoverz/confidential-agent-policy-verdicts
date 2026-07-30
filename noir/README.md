# CAPV allowlist circuit (Noir)

The zero-knowledge circuit for the reference implementation. Proves an action is permitted by a committed-but-hidden allowlist policy. The proving backend is an implementation detail behind the ERC's `IVerifier`; this one is Noir, proven with Barretenberg to a Groth16 proof for cheap on-chain verification.

`src/main.nr` documents the four obligations it enforces. This is a work in progress: the circuit compiles the allowlist MVP; the byte packing in `abi_encode_policy_action` must be cross-checked against Solidity `PolicyAction.commit`.

## Toolchain

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup            # installs nargo
# barretenberg (bb) for proving + verifier generation:
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
bbup
```

## Build and prove

```bash
nargo check                 # generates Prover.toml with the input fields
# fill Prover.toml with a witness, then:
nargo execute               # runs the circuit, writes the witness
bb prove -b ./target/capv_allowlist.json -w ./target/capv_allowlist.gz -o ./target/proof
```

## On-chain verifier

```bash
bb write_vk -b ./target/capv_allowlist.json -o ./target/vk
bb contract -k ./target/vk -o ./target/Verifier.sol
```

`Verifier.sol` is the Solidity verifier. Wrap it to implement the ERC's `IVerifier.verifyProof(programKey, publicInputs, proof)` (the `programKey` is the verification key commitment; `publicInputs` is the encoded Verdict), and register it as a domain's verifier in `PolicyDomainRegistry`. That replaces `MockVerifier`.

## Public input layout

The circuit's public inputs mirror the on-chain `Verdict`: `agent_id`, `domain_id`, `policy_root`, `action_commitment` (`[u8; 32]`), `nullifier`, `decision`. The wrapper must feed them in the order Barretenberg expects when it calls the generated verifier.

## Status

- [x] allowlist membership + action-commitment + nullifier obligations
- [x] compiles on nargo 1.0.0-beta.25 (3795 gates) and `nargo test` passes (valid witness satisfies all four)
- [ ] verify keccak preimage packing matches Solidity byte-for-byte
- [ ] wrap the generated verifier behind `IVerifier` + swap out `MockVerifier`
- [ ] Tokyo delta on top of this (Mandate: private accumulator, or CAPVand: multi-policy)
