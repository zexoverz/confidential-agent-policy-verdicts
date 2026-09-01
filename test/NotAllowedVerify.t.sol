// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {NotAllowedHonkVerifier} from "../src/verifier/NotAllowedHonkVerifier.sol";
import {HonkVerifierAdapter, IHonkVerifier} from "../src/HonkVerifierAdapter.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {Verdict, PolicyKind} from "../src/IConfidentialPolicyVerdict.sol";

/// @dev Verifies the real not-permitted proof (allowlist NON-membership, decision == 0,
/// policyKind == 2) on-chain through the same Verdict -> 39-public-input adapter the ALLOW and
/// denylist paths use. The witness is the one `noir-notallowed/src/witness.nr` emits: an allowlist
/// of four addresses, and a target (0x5555...) that sits in the gap between the second and third.
contract NotAllowedVerifyTest is Test {
    /// The expiry the checked-in fixture proofs were generated with.
    uint64 constant FIXTURE_EXPIRY = 1900000000;

    bytes32 constant POLICY_ROOT = 0x24e703f14986ec5abcb79d7292a4593b3370440fd4d1f2b6e51653e2e045707f;
    bytes32 constant COMMITMENT = 0xd1f89cac88ca71fea90df48ba29278d5782dc8eb76127bf7bfdafca71aaa8048;
    bytes32 constant NULLIFIER = 0x1d38c31e6bb446623f552d36f1ce11aa86c06cefe2b5a26e53f4700792f32c84;
    // NotAllowedHonkVerifier's own VK_HASH (src/verifier/NotAllowedHonkVerifier.sol:20).
    bytes32 constant PROGRAM_KEY = 0x298a64f0bc045f79db372712eeefa00964f4867c029f8262ee724e2dca86eef6;

    NotAllowedHonkVerifier internal honk;
    HonkVerifierAdapter internal adapter;

    function setUp() public {
        honk = new NotAllowedHonkVerifier();
        adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)), PROGRAM_KEY);
    }

    function _verdict() internal pure returns (Verdict memory v) {
        v = Verdict({
            agentId: 7,
            domainId: bytes32(uint256(43)),
            policyRoot: POLICY_ROOT,
            actionCommitment: COMMITMENT,
            executor: address(0xE0),
            // The proof commits to `expiry` as public input [39], so a Verdict presented to a real
        // proof MUST carry the value the fixture was proven with. It used to be free here.
        expiry: FIXTURE_EXPIRY,
            nullifier: NULLIFIER,
            decision: 0,
            policyKind: PolicyKind.NOT_PERMITTED
        });
    }

    function _proof() internal view returns (bytes memory) {
        return vm.readFileBinary("./test/fixtures/not_allowed.proof");
    }

    function test_realNotPermittedProofVerifies() public view {
        assertTrue(
            IVerifier(address(adapter)).verifyProof(PROGRAM_KEY, abi.encode(_verdict()), _proof()),
            "real not-permitted proof must verify"
        );
    }

    /// `policyKind` is a committed public input, so the taxonomy cannot be re-labelled at the
    /// boundary: the same proof presented as DENIED (a rule fired) is rejected. As in the ALLOW
    /// path, UltraHonk rejects a mismatched public input by reverting, which the Guard's `verify`
    /// turns into a `false` via its try/catch; here we assert the rejection.
    function test_proofRejectsDeniedKind() public {
        Verdict memory v = _verdict();
        v.policyKind = PolicyKind.DENIED;
        vm.expectRevert();
        IVerifier(address(adapter)).verifyProof(PROGRAM_KEY, abi.encode(v), _proof());
    }

    /// The executor is committed too, so the proof does not carry over to another consumer.
    function test_proofRejectsWrongExecutor() public {
        Verdict memory v = _verdict();
        v.executor = address(0xBAD);
        vm.expectRevert();
        IVerifier(address(adapter)).verifyProof(PROGRAM_KEY, abi.encode(v), _proof());
    }

    /// The root is the allowlist the target was proven absent from; another root is another policy.
    function test_proofRejectsWrongPolicyRoot() public {
        Verdict memory v = _verdict();
        v.policyRoot = keccak256("some other allowlist");
        vm.expectRevert();
        IVerifier(address(adapter)).verifyProof(PROGRAM_KEY, abi.encode(v), _proof());
    }

    /// @notice A wrong program key must fail closed, not pass through to the underlying verifier.
    function test_FIXED_WrongProgramKeyRejects() public view {
        bytes32 wrongKey = bytes32(uint256(PROGRAM_KEY) + 1);
        assertFalse(
            IVerifier(address(adapter)).verifyProof(wrongKey, abi.encode(_verdict()), _proof()),
            "adapter accepted a proof under the wrong program key"
        );
    }
}
