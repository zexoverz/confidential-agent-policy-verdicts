# Bastion Composed Gate Example

Shows how to compose CAPV (confidential ZK policy verdicts) with
Bastion's programmable public policy engine.

## What it demonstrates

This is a live composed gate contract that layers two independent
policy evaluations before letting an agent action execute:

1. CONFIDENTIAL (ZK) - CAPV: a Noir circuit proves the action was
   evaluated against a committed secret policy and permitted. The
   policy rules stay off-chain. Only the ZK proof goes on-chain.

2. PUBLIC (transparent) - Bastion: the action is evaluated against
   programmable transparent rules (amount caps, allowlists, rate
   limits, cooldowns) with full auditable reasoning.

Both layers must pass for execution to proceed.

## Architecture

```
Agent submits: Verdict + Proof + Action
        |
Layer 1: CAPV Guard
  - Recomputes PolicyAction commitment
  - Verifies ZK proof (UltraHonk from Noir circuit)
  - Consumes nullifier (single-use)
        |
Layer 2: Bastion Policy
  - checkTransaction(agent, target, value, data)
  - Returns (allowed, reason)
        |
    Execute
```

## Full confidentiality spectrum

| Layer | Visibility | Use Case |
|-------|-----------|----------|
| CAPV | Secret | Organizational blacklists, proprietary risk models |
| Bastion | Transparent | Regulatory caps, compliance allowlists, audit trails |

## Usage

```solidity
constructor(
    IConfidentialPolicyVerdict _capv,   // CAPV guard contract
    IBastionPolicy _bastion,            // Bastion policy contract
    bytes32 _domainId                   // policy domain identifier
)

function executeDualGate(
    Verdict calldata v,    // CAPV verdict (with ZK proof)
    bytes calldata proof,  // UltraHonk proof from Noir circuit
    address agent,         // agent address for Bastion lookup
    address target,        // call target
    bytes calldata data,   // calldata
    uint256 actionNonce    // replay protection
) external payable
```

## Reference

- CAPV: https://github.com/zexoverz/confidential-agent-policy-verdicts
- Bastion: https://github.com/zkos-labs/bastion
