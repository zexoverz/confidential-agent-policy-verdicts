// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.0;

import {IConfidentialCredential} from "./interfaces/IConfidentialCredential.sol";
import {ConfidentialCredentialGuard} from "./ConfidentialCredentialGuard.sol";
import {CredentialDomainRegistry} from "./libraries/CredentialDomainRegistry.sol";
import {IVerifier} from "./verifier/IVerifier.sol";

/// @title GuardedAgentExecutor — Example Consumer
/// @notice Demonstrates how to integrate ConfidentialCredentialGuard into
///         a workflow. Not audited. For reference only.
contract GuardedAgentExecutor {
    ConfidentialCredentialGuard public immutable guard;

    event ActionExecuted(
        bytes32 indexed nullifier,
        uint256 indexed agentId,
        bytes32 actionCommitment
    );

    constructor(address _guard) {
        guard = ConfidentialCredentialGuard(_guard);
    }

    /// @notice Execute an action under a confidential credential.
    /// @dev The caller must supply a Capability whose actionCommitment matches
    ///      the intended action. The Guard never sees the action parameters.
    function execute(
        IConfidentialCredential.Capability calldata cap,
        bytes calldata proof,
        bytes32 expectedActionCommitment
    ) external returns (bytes32) {
        require(cap.actionCommitment == expectedActionCommitment, "CCC: action mismatch");
        bytes32 nullifier = guard.consume(cap, proof);
        emit ActionExecuted(nullifier, cap.agentId, cap.actionCommitment);
        return nullifier;
    }
}