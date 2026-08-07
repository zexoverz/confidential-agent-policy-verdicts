# CAPV confidential denial circuit (Noir)

The confidential corner of the DENY board: a zero-knowledge proof that an action is **denied** by a
committed-but-hidden policy. Dual of the allowlist circuit — `assert(decision == 0)` and membership in
a committed **denylist** (`policy_root`). Public inputs and the PolicyAction commitment are byte-identical
to the allowlist circuit, so a DENY proof binds to the same on-chain `Verdict` shape.

## Build, prove, verify (nargo 1.0.0-beta.25 + bb 5.1.0)

```bash
nargo test                                   # self-consistent DENY witness passes
nargo compile && nargo execute               # -> target/capv_denylist.gz

# EVM (keccak transcript) proof + on-chain verifier:
bb write_vk -b target/capv_denylist.json -o target --oracle_hash keccak
bb prove   -b target/capv_denylist.json -w target/capv_denylist.gz -o target --oracle_hash keccak
bb verify  -k target/vk -p target/proof -i target/public_inputs --oracle_hash keccak   # verified
bb write_solidity_verifier -k target/vk --optimized -o target/DenyVerifier.sol
```

`fixtures/` holds a checked-in keccak-transcript proof (`deny.proof`, `deny.public_inputs`) for the
denylist-of-one witness (target `0x1234`, decision 0). The generated verifier is checked in at
`../src/verifier/DenyHonkVerifier.sol`.

## Status

- [x] circuit compiles, `nargo test` passes, decision == 0 enforced
- [x] real UltraHonk DENY proof generated and verified (keccak transcript, EVM-ready)
- [x] on-chain verifier generated (`DenyHonkVerifier`)
- [ ] on-chain close: deploy the verifier + adapter, register a denial domain, anchor via
      `ProvableDenialAnchor` (the ZK-gated anchor) so a real confidential DENY is recompute-verifiable
      on Sepolia, alongside the transparent corner already live

## Richer policy (future)

"Deny an action not explicitly allowed" is non-membership in the allowlist, which needs a
sorted/indexed Merkle tree and a range proof. This MVP proves the simpler, honest confidential denial:
membership in a committed denylist.
