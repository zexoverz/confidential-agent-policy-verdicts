# CAPV deny-if-not-allowed circuit (Noir)

The richer confidential denial: prove an action's target is **not a member** of a committed
allowlist, i.e. *not-permitted* (default-deny). This is a different claim from the `capv_denylist`
circuit's *denied* (a rule fired). Both prove `decision == 0`; a committed `policy_kind` public
input distinguishes them.

## Structure

- **Indexed / sorted / linked Merkle tree.** Each leaf is `(value, next_value, next_index)`, leaves
  sorted by value, each pointing to the next-larger one.
- **Low-leaf non-membership.** Exhibit the leaf `L` bracketing `target`:
  `L.value < target` and (`L` is the maximum, `next_value == 0`, or `target < L.next_value`), and
  prove `L` is in the tree. No leaf holds `target`, so it is absent.
- **Sound comparison.** `addr_lt` decomposes to 160 bits, which compares as unsigned and
  range-checks the operands are addresses (a bare Field `<` is not sound).
- **`policy_kind` public input** = `2` (NOT_PERMITTED). Public inputs are otherwise byte-identical
  to the ALLOW / denylist circuits: 39 flattened elements, same order, same adapter.

## Witness builder

`src/witness.nr` builds the indexed tree off-chain and emits a complete `Prover.toml`. It is written
in Noir rather than a host language so that the commitment, the nullifier and every tree node are
computed by calling the circuit's own helpers — the two cannot drift, and no toolchain is added.

Leaf 0 is a sentinel head `(0, min(allowlist), 1)`; entry `k` sits at leaf `k + 1`; empty slots hash
to `0` rather than to `pedersen([0, 0, 0])`. That last detail is load-bearing: an all-zero *leaf*
would be an in-tree leaf with `value == 0` and `next_value == 0`, which the circuit would accept as
a low leaf for **any** target, including allowlisted ones. The builder also rejects an unsorted,
duplicated or zero-valued allowlist, which is what keeps the linked-list invariant the circuit's
soundness rests on.

```bash
nargo test --show-output      # 9 tests, including "a member target yields no witness"
```

## Build, prove, verify (nargo 1.0.0-beta.25 + bb 5.1.0)

```bash
nargo test --show-output      # copy the emitted block into Prover.toml
nargo compile && nargo execute                # -> target/capv_not_allowed.gz

# EVM (keccak transcript) proof + on-chain verifier:
bb write_vk -b target/capv_not_allowed.json -o target --oracle_hash keccak
bb prove   -b target/capv_not_allowed.json -w target/capv_not_allowed.gz -o target --oracle_hash keccak
bb verify  -k target/vk -p target/proof -i target/public_inputs --oracle_hash keccak   # verified
bb write_solidity_verifier -k target/vk --optimized -o target/NotAllowedVerifier.sol
```

`--optimized` is not cosmetic: it was measured at -71.5% on-chain verify gas (2,564,863 -> 731,3xx)
for these verifiers, and reported upstream as Aztec #24997.

`fixtures/` holds the checked-in keccak-transcript proof (`not_allowed.proof`,
`not_allowed.public_inputs`) and the witness it was built from (`Prover.not_allowed.toml`): an
allowlist of four addresses, proving `0x5555...5555` is absent. The generated verifier is checked in
at `../src/verifier/NotAllowedHonkVerifier.sol`.

## Status

- [x] circuit compiles, `nargo test` passes, `decision == 0` and `policy_kind == 2` enforced
- [x] off-chain indexed-tree witness builder, with a test that an allowlisted target yields no witness
- [x] real UltraHonk not-permitted proof generated and verified (keccak transcript, EVM-ready)
- [x] on-chain verifier generated (`NotAllowedHonkVerifier`), 39 public inputs through the shared adapter
- [x] anchored end to end: `ProvableDenialAnchor` records the denial and `denialKind()` returns `2`
      (`../test/NotPermittedAnchor.t.sol`)
- [ ] on-chain close: deploy the verifier + adapter to Sepolia and anchor a live not-permitted
      denial, alongside the denylist and transparent corners

## Settled

1. **Where `policy_kind` lives** — a committed public input, settled with Merlini on the 8274 thread.
   Not policy_root semantics (a trusted label), not domain separation alone.
2. **Ordering soundness** — `addr_lt`'s 160-bit decomposition range-checks both operands as it
   compares them.

## Open

**Tree well-formedness.** Non-membership is sound only if the committed root is a correctly linked
indexed tree. The builder maintains that invariant and refuses malformed input, but the circuit does
not prove it — an insertion circuit would. This is the standard indexed-Merkle assumption and belongs
in Security Considerations.
