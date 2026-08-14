// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Verdict, PolicyKind} from "./IConfidentialPolicyVerdict.sol";

/// @notice Provable-denial companion to the Confidential Policy Verdict standard.
///
/// A DENY verdict (`decision == 0`) carries a valid proof but is never consumed, so under the core
/// standard a denial leaves no trace: "evaluated and denied" is indistinguishable from "never
/// evaluated". This companion anchors a denial by burning the verdict's nullifier against a separate
/// denial record, giving the confidential path a positive, replay-protected trace of a denial without
/// revealing the policy. The ALLOW happy path in `IConfidentialPolicyVerdict` is untouched.
interface IProvableDenial {
    event DenialAnchored(
        bytes32 indexed nullifier,
        uint256 indexed agentId,
        bytes32 indexed domainId,
        bytes32 policyRoot,
        bytes32 actionCommitment,
        uint8 policyKind
    );

    error NotADenial(uint8 decision);
    error DenialReplayed(bytes32 nullifier);
    error DenialDomainInactive(bytes32 domainId);
    error DenialPolicyRootRejected(bytes32 root);
    error DenialProofInvalid();
    /// @dev The verdict carries a kind that is not a refusal, so it cannot be anchored as a denial.
    error NotARefusalKind(uint8 policyKind);

    /// @notice Anchor a DENY verdict. MUST require `v.decision == 0`, verify the proof against the
    /// domain's program, and burn the nullifier against the denial record. Unlike consumption, it is
    /// not bound to an executor and is not time-boxed by the verdict's expiry: a denial is a
    /// permanent, publicly anchorable record.
    function anchorDenial(Verdict calldata v, bytes calldata proof) external;

    function isDenied(bytes32 domainId, bytes32 nullifier) external view returns (bool);

    /// @notice The refusal kind anchored for this nullifier, or `PolicyKind.ALLOWED` (0) when nothing
    /// is anchored. This is the §4 carriage requirement: a consumer gating an irreversible action can
    /// tell "a rule refused this" (DENIED) from "nothing authorized it" (NOT_PERMITTED) instead of
    /// reading one generic denial. A kind proven in-circuit but dropped here would let the taxonomy be
    /// adopted in words while the mechanism is discarded at the boundary.
    function denialKind(bytes32 domainId, bytes32 nullifier) external view returns (uint8);
}
