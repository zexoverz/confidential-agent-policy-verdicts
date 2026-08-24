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
    bytes32 constant POLICY_ROOT = 0x24e703f14986ec5abcb79d7292a4593b3370440fd4d1f2b6e51653e2e045707f;
    bytes32 constant COMMITMENT = 0x648bba7f2f0e1fc3771b2f4da93abd8a1fff957a44e2979804f09fb681071e17;
    bytes32 constant NULLIFIER = 0x1efbeda52f387ca0664fa2c3e5b89d61493504338c227a5cc47891db50cc098f;

    NotAllowedHonkVerifier internal honk;
    HonkVerifierAdapter internal adapter;

    function setUp() public {
        honk = new NotAllowedHonkVerifier();
        adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)));
    }

    function _verdict() internal pure returns (Verdict memory v) {
        v = Verdict({
            agentId: 7,
            domainId: bytes32(uint256(42)),
            policyRoot: POLICY_ROOT,
            actionCommitment: COMMITMENT,
            executor: address(0xE0),
            expiry: 0,
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
            IVerifier(address(adapter)).verifyProof(bytes32(0), abi.encode(_verdict()), _proof()),
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
        IVerifier(address(adapter)).verifyProof(bytes32(0), abi.encode(v), _proof());
    }

    /// The executor is committed too, so the proof does not carry over to another consumer.
    function test_proofRejectsWrongExecutor() public {
        Verdict memory v = _verdict();
        v.executor = address(0xBAD);
        vm.expectRevert();
        IVerifier(address(adapter)).verifyProof(bytes32(0), abi.encode(v), _proof());
    }

    /// The root is the allowlist the target was proven absent from; another root is another policy.
    function test_proofRejectsWrongPolicyRoot() public {
        Verdict memory v = _verdict();
        v.policyRoot = keccak256("some other allowlist");
        vm.expectRevert();
        IVerifier(address(adapter)).verifyProof(bytes32(0), abi.encode(v), _proof());
    }
}
