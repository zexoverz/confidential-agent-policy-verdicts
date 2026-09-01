// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {DenyHonkVerifier} from "../src/verifier/DenyHonkVerifier.sol";
import {HonkVerifierAdapter, IHonkVerifier} from "../src/HonkVerifierAdapter.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {Verdict, PolicyKind} from "../src/IConfidentialPolicyVerdict.sol";

/// @dev Verifies the real confidential-DENY proof (decision == 0) on-chain through the same
/// Verdict -> 38-public-input adapter the ALLOW path uses. If this passes, the Sepolia anchor will too.
contract DenyVerifyTest is Test {
    // DenyHonkVerifier's own VK_HASH (src/verifier/DenyHonkVerifier.sol:20).
    bytes32 constant PROGRAM_KEY = 0x0b60fc55fc2bcb71089336a87895321b4da50b971179fdec06cd6c1bc6ef0ff4;

    /// The expiry the checked-in fixture proofs were generated with.
    uint64 constant FIXTURE_EXPIRY = 1900000000;

    function test_realDenyProofVerifies() public {
        DenyHonkVerifier honk = new DenyHonkVerifier();
        HonkVerifierAdapter adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)), PROGRAM_KEY);

        Verdict memory v = Verdict({
            agentId: 7,
            domainId: bytes32(uint256(42)),
            policyRoot: 0x053d4542d140ad2350a0ee79fae4a522821274e428bd881e7e803ecd816635ac,
            actionCommitment: 0x7ccb7a4e9d51128b951cbeddefaec1140180a3d13f6eae6f06596dc432057cfa,
            executor: address(0xE0),
            // The proof commits to `expiry` as public input [39], so a Verdict presented to a real
        // proof MUST carry the value the fixture was proven with. It used to be free here.
        expiry: FIXTURE_EXPIRY,
            nullifier: 0x041271fcaf479f6ab927df3a03f74d3809e9f49d880cd7a9595c8dc0a58a5e03,
            decision: 0,
            policyKind: PolicyKind.DENIED
        });
        bytes memory proof = vm.readFileBinary("./test/fixtures/deny.proof");

        assertTrue(
            IVerifier(address(adapter)).verifyProof(PROGRAM_KEY, abi.encode(v), proof),
            "real confidential DENY proof must verify"
        );
    }

    /// @notice A wrong program key must fail closed, not pass through to the underlying verifier.
    function test_FIXED_WrongProgramKeyRejects() public {
        DenyHonkVerifier honk = new DenyHonkVerifier();
        HonkVerifierAdapter adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)), PROGRAM_KEY);

        Verdict memory v = Verdict({
            agentId: 7,
            domainId: bytes32(uint256(42)),
            policyRoot: 0x053d4542d140ad2350a0ee79fae4a522821274e428bd881e7e803ecd816635ac,
            actionCommitment: 0x7ccb7a4e9d51128b951cbeddefaec1140180a3d13f6eae6f06596dc432057cfa,
            executor: address(0xE0),
            expiry: 0,
            nullifier: 0x041271fcaf479f6ab927df3a03f74d3809e9f49d880cd7a9595c8dc0a58a5e03,
            decision: 0,
            policyKind: PolicyKind.DENIED
        });
        bytes memory proof = vm.readFileBinary("./test/fixtures/deny.proof");
        bytes32 wrongKey = bytes32(uint256(PROGRAM_KEY) + 1);

        assertFalse(
            IVerifier(address(adapter)).verifyProof(wrongKey, abi.encode(v), proof),
            "adapter accepted a proof under the wrong program key"
        );
    }
}
