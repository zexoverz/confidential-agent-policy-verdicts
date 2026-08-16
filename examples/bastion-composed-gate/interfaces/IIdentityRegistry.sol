// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

/// @title IIdentityRegistry
/// @notice Minimal ERC 8004 Identity Registry lookup used to resolve an agent's
///         onchain address from the tokenId a CAPV verdict commits to.
interface IIdentityRegistry {
    /// @notice Returns the address controlling the given agent identity token.
    function ownerOf(uint256 agentId) external view returns (address);
}
