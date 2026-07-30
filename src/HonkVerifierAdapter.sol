// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {IVerifier} from "./IVerifier.sol";
import {Verdict} from "./IConfidentialPolicyVerdict.sol";

/// @notice Minimal view of the bb-generated UltraHonk verifier.
interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// @notice Adapts the Noir/UltraHonk allowlist verifier to the ERC's `IVerifier`. It serializes the
/// Verdict fields that are the circuit's public inputs and calls the generated Honk verifier.
///
/// The circuit's public inputs, in `main()` order, are 37 elements:
///   [0] agentId, [1] domainId, [2] policyRoot, [3..34] the 32 bytes of actionCommitment
///   (each byte as a field element), [35] nullifier, [36] decision.
/// `executor` and `expiry` are NOT circuit inputs — the Guard enforces them on-chain.
contract HonkVerifierAdapter is IVerifier {
    IHonkVerifier public immutable honk;

    constructor(IHonkVerifier _honk) {
        honk = _honk;
    }

    /// @param publicInputs abi.encode(Verdict) as passed by the Guard.
    function verifyProof(
        bytes32,
        /* programKey */
        bytes calldata publicInputs,
        bytes calldata proof
    )
        external
        view
        returns (bool)
    {
        Verdict memory v = abi.decode(publicInputs, (Verdict));
        return honk.verify(proof, _toPublicInputs(v));
    }

    /// @notice The 37-element public-input vector the circuit expects, from a Verdict.
    function _toPublicInputs(Verdict memory v) internal pure returns (bytes32[] memory pi) {
        pi = new bytes32[](37);
        pi[0] = bytes32(v.agentId);
        pi[1] = v.domainId;
        pi[2] = v.policyRoot;
        for (uint256 i = 0; i < 32; i++) {
            pi[3 + i] = bytes32(uint256(uint8(v.actionCommitment[i])));
        }
        pi[35] = v.nullifier;
        pi[36] = bytes32(uint256(v.decision));
    }
}
