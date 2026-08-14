// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {IProvableDenial} from "./IProvableDenial.sol";
import {Verdict, PolicyKind} from "./IConfidentialPolicyVerdict.sol";
import {IPolicyDomainRegistry} from "./IPolicyDomainRegistry.sol";
import {IVerifier} from "./IVerifier.sol";

/// @notice Companion anchor for provable denial. Standalone from the core Guard so the ALLOW path
/// stays untouched; it shares the same registry, verifier, and Verdict discipline.
/// @dev In production the ALLOW `consume()` and DENY `anchorDenial()` nullifier spaces SHOULD be
/// coordinated (a shared registry, or a cross-check) so a single action cannot be both consumed and
/// denied. This reference keeps its own denial record for a minimal, non-invasive companion.
contract ProvableDenialAnchor is IProvableDenial {
    IPolicyDomainRegistry public immutable registry;

    // domainId => nullifier => denied
    mapping(bytes32 => mapping(bytes32 => bool)) private _denied;
    // domainId => nullifier => the refusal kind that was anchored (0 when nothing is anchored)
    mapping(bytes32 => mapping(bytes32 => uint8)) private _kind;

    constructor(IPolicyDomainRegistry _registry) {
        registry = _registry;
    }

    /// @inheritdoc IProvableDenial
    function isDenied(bytes32 domainId, bytes32 nullifier) public view returns (bool) {
        return _denied[domainId][nullifier];
    }

    /// @inheritdoc IProvableDenial
    function denialKind(bytes32 domainId, bytes32 nullifier) public view returns (uint8) {
        return _kind[domainId][nullifier];
    }

    /// @inheritdoc IProvableDenial
    /// @dev Same discipline as the ALLOW path minus the executor binding and the expiry window: a
    /// denial is a public, permanent record. Checks run in the same order the core Guard uses.
    function anchorDenial(Verdict calldata v, bytes calldata proof) external {
        IPolicyDomainRegistry.Domain memory d = registry.domain(v.domainId);
        if (!d.active) revert DenialDomainInactive(v.domainId);
        if (v.decision != 0) revert NotADenial(v.decision);
        // The kind must be a refusal and must agree with the decision, so a denial cannot be
        // anchored under the ALLOWED kind and lose the distinction it was proven with.
        if (!PolicyKind.agreesWithDecision(v.policyKind, v.decision)) revert NotARefusalKind(v.policyKind);
        if (_denied[v.domainId][v.nullifier]) revert DenialReplayed(v.nullifier);
        if (!registry.isRootAcceptable(v.domainId, v.policyRoot)) revert DenialPolicyRootRejected(v.policyRoot);
        if (!IVerifier(d.verifier).verifyProof(d.programKey, abi.encode(v), proof)) revert DenialProofInvalid();

        _denied[v.domainId][v.nullifier] = true;
        _kind[v.domainId][v.nullifier] = v.policyKind;
        emit DenialAnchored(v.nullifier, v.agentId, v.domainId, v.policyRoot, v.actionCommitment, v.policyKind);
    }
}
