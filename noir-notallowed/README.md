# CAPV deny-if-not-allowed circuit (Noir) — PRE-DRAFT

The richer confidential denial: prove an action's target is **not a member** of a committed
allowlist, i.e. *not-permitted* (default-deny). This is a different claim from the `capv_denylist`
circuit's *denied* (a rule fired). Both prove `decision == 0`; a committed `policy_kind` public
input distinguishes them.

## Structure (design-independent, settled)

- **Indexed / sorted / linked Merkle tree.** Each leaf is `(value, next_value, next_index)`, leaves
  sorted by value, each pointing to the next-larger one.
- **Low-leaf non-membership.** Exhibit the leaf `L` bracketing `target`:
  `L.value < target` and (`L` is the maximum, `next_value == 0`, or `target < L.next_value`), and
  prove `L` is in the tree. No leaf holds `target`, so it is absent.
- **Sound comparison.** `addr_lt` decomposes to 160 bits, which compares as unsigned and
  range-checks the operands are addresses (a bare Field `<` is unsound).
- **`policy_kind` public input** = `2` (NOT_PERMITTED). Public inputs are otherwise byte-identical
  to the ALLOW / denylist circuits.

```bash
nargo test     # test_not_permitted: allowlist {0x1000, 0x3000}, proves 0x2000 absent — passes
nargo compile
```

## Open (pending)

1. **Where `policy_kind` lives** — public input (this draft), policy_root semantics, or domain
   separation. Being settled with Merlini on the 8274 thread. Only the wiring changes if it moves.
2. **Tree well-formedness** — non-membership is sound only if the committed root is a correctly
   linked indexed tree. That invariant is kept by the off-chain builder / insertion circuit, not
   proved here; it's the standard indexed-Merkle assumption and belongs in Security Considerations.
3. **Finalize** — a `should_fail` test for a member target, an EVM (`-t evm`) proof, the verifier,
   and thread `policy_kind` through the adapter's public-input serialization.
