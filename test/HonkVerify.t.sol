// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {HonkVerifier} from "../src/verifier/HonkVerifier.sol";

/// @notice Verifies the real UltraHonk proof (produced by bb from the Noir allowlist circuit) against
/// the generated on-chain verifier. If this passes, the reference impl has an end-to-end real proof,
/// not a mock. The proof + public inputs are committed fixtures generated from Prover.example.toml.
contract HonkVerifyTest is Test {
    function test_real_allowlist_proof_verifies_onchain() public {
        HonkVerifier verifier = new HonkVerifier();

        bytes memory proof = vm.readFileBinary("./test/fixtures/allowlist.proof");
        bytes memory piRaw = vm.readFileBinary("./test/fixtures/allowlist.public_inputs");

        uint256 n = piRaw.length / 32;
        bytes32[] memory publicInputs = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 off = 32 + i * 32;
            bytes32 w;
            assembly {
                w := mload(add(piRaw, off))
            }
            publicInputs[i] = w;
        }

        assertTrue(verifier.verify(proof, publicInputs), "real proof failed on-chain verification");
    }
}
