// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.0;

/// @title CredentialCommitment — Canonical Domain-Separated Hashing
/// @notice Computes nullifier and credential commitment exactly as specified
///         in ERC-XXXX §3.3. These functions MUST be used by both the circuit
///         and any Solidity-side parity checks.
library CredentialCommitment {
    bytes32 internal constant NULLIFIER_TAG = keccak256("ERC-XXXX/nullifier/v1");
    bytes32 internal constant CREDENTIAL_TAG = keccak256("ERC-XXXX/credential/v1");

    /// @notice Compute nullifier = H(NULLIFIER_TAG, salt)
    function computeNullifier(bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(NULLIFIER_TAG, salt));
    }

    /// @notice Compute capabilityCommitment = H(CREDENTIAL_TAG, salt, agentId, homeChainId,
    ///         homeDomainId, capabilityIndex, actionCommitment)
    function computeCredentialCommitment(
        bytes32 salt,
        uint256 agentId,
        uint256 homeChainId,
        uint256 homeDomainId,
        uint256 capabilityIndex,
        bytes32 actionCommitment
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                CREDENTIAL_TAG,
                salt,
                bytes32(agentId),
                bytes32(homeChainId),
                bytes32(homeDomainId),
                bytes32(capabilityIndex),
                actionCommitment
            )
        );
    }
}