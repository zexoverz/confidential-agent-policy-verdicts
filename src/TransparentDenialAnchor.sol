// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {IProvableDenial} from "./IProvableDenial.sol";
import {Verdict} from "./IConfidentialPolicyVerdict.sol";
import {PolicyAction, PolicyActionLib} from "./PolicyAction.sol";

/// @notice Transparent (recompute) denial anchor: the ERC-8274 transparent corner of the DENY board.
/// @dev Where `ProvableDenialAnchor` gates anchoring on a ZK proof against the domain's program (the
/// confidential corner), this corner carries no secret. The "proof" is the public PolicyAction
/// preimage and anchoring is a recompute-and-compare, so anyone can reproduce the commitment from
/// chain data. It exposes the identical `isDenied` surface, so a recompute-denial verifier binds to
/// it the same way it would bind to the confidential anchor. Same non-suppression property either
/// way: evaluated-and-denied becomes distinguishable from never-evaluated, and now publicly checkable.
contract TransparentDenialAnchor is IProvableDenial {
    using PolicyActionLib for PolicyAction;

    // domainId => nullifier => denied
    mapping(bytes32 => mapping(bytes32 => bool)) private _denied;

    /// @dev The preimage's domain must match the verdict's domain, so a denial cannot be anchored
    /// under a domain the action was not scoped to.
    error DomainMismatch(bytes32 preimageDomain, bytes32 verdictDomain);

    /// @inheritdoc IProvableDenial
    function isDenied(bytes32 domainId, bytes32 nullifier) public view returns (bool) {
        return _denied[domainId][nullifier];
    }

    /// @inheritdoc IProvableDenial
    /// @dev `proof` is the ABI-encoded PolicyAction preimage. The commitment is recomputed and
    /// compared to the verdict; there is no cryptographic secret in this corner.
    function anchorDenial(Verdict calldata v, bytes calldata proof) external {
        if (v.decision != 0) revert NotADenial(v.decision);
        if (_denied[v.domainId][v.nullifier]) revert DenialReplayed(v.nullifier);

        PolicyAction memory a = abi.decode(proof, (PolicyAction));
        if (a.domainId != v.domainId) revert DomainMismatch(a.domainId, v.domainId);
        if (a.commit() != v.actionCommitment) revert DenialProofInvalid();

        _denied[v.domainId][v.nullifier] = true;
        emit DenialAnchored(v.nullifier, v.agentId, v.domainId, v.policyRoot, v.actionCommitment);
    }
}
