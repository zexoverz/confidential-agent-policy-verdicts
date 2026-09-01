// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {HonkVerifier} from "../src/verifier/HonkVerifier.sol";
import {HonkVerifierAdapter, IHonkVerifier} from "../src/HonkVerifierAdapter.sol";
import {Verdict, PolicyKind} from "../src/IConfidentialPolicyVerdict.sol";

/// @notice The full IVerifier path: a Verdict, serialized by the adapter into the circuit's public
/// inputs, verifying the real UltraHonk proof. If this passes, the Guard's `consume` can use the
/// adapter as the domain verifier and the reference impl is no longer mocked end to end.
/// `executor` is now a committed circuit public input, so the proof binds to it (spec Security
/// Considerations) — the negative test proves a different executor is rejected.
contract AdapterVerifyTest is Test {
    // HonkVerifier's own VK_HASH (src/verifier/HonkVerifier.sol:20) -- the program key this
    // adapter must be constructed with and called with to accept a proof.
    bytes32 constant PROGRAM_KEY = 0x10d07da428220548a6d7c4f405b1c8ded613a92e0b797262985a9ccdb1e6288e;

    /// The expiry the checked-in fixture proofs were generated with.
    uint64 constant FIXTURE_EXPIRY = 1900000000;

    function _witnessVerdict() internal pure returns (Verdict memory v) {
        // The Verdict for the committed witness (Prover.example.toml). expiry is now bound by the proof, not Guard-only.
        v = Verdict({
            agentId: 7,
            domainId: bytes32(uint256(42)),
            policyRoot: 0x053d4542d140ad2350a0ee79fae4a522821274e428bd881e7e803ecd816635ac,
            actionCommitment: 0x7ccb7a4e9d51128b951cbeddefaec1140180a3d13f6eae6f06596dc432057cfa,
            executor: address(0xE0),
            // The proof commits to `expiry` as public input [39], so a Verdict presented to a real
        // proof MUST carry the value the fixture was proven with. It used to be free here.
        expiry: FIXTURE_EXPIRY,
            nullifier: 0x041271fcaf479f6ab927df3a03f74d3809e9f49d880cd7a9595c8dc0a58a5e03,
            decision: 1,
            policyKind: PolicyKind.ALLOWED
        });
    }

    function test_real_proof_through_iverifier() public {
        HonkVerifier honk = new HonkVerifier();
        HonkVerifierAdapter adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)), PROGRAM_KEY);

        Verdict memory v = _witnessVerdict();
        bytes memory proof = vm.readFileBinary("./test/fixtures/allowlist.proof");
        assertTrue(
            adapter.verifyProof(PROGRAM_KEY, abi.encode(v), proof), "IVerifier path failed on real proof"
        );
    }

    /// @notice The proof is bound to executor 0xE0 in-circuit. Verifying it against any other
    /// executor MUST fail — this is the property the spec requires and Gap 1 was closing. The
    /// UltraHonk verifier rejects a mismatched public input by reverting (SumcheckFailed), which
    /// the Guard's `verify` turns into a `false` via its try/catch; here we assert the rejection.
    function test_proof_rejects_wrong_executor() public {
        HonkVerifier honk = new HonkVerifier();
        HonkVerifierAdapter adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)), PROGRAM_KEY);

        Verdict memory v = _witnessVerdict();
        v.executor = address(0xBEEF); // anything other than the committed 0xE0
        bytes memory proof = vm.readFileBinary("./test/fixtures/allowlist.proof");
        vm.expectRevert();
        adapter.verifyProof(PROGRAM_KEY, abi.encode(v), proof);
    }

    /// @notice The gap this file's earlier version had: `programKey` was accepted as a parameter
    /// but never checked, so ANY value -- including a stale key from a domain that has since
    /// rotated onto a different program -- verified an otherwise-valid proof. A wrong key MUST
    /// fail closed (return false), not revert and not pass through to the underlying verifier.
    function test_FIXED_WrongProgramKeyRejects() public {
        HonkVerifier honk = new HonkVerifier();
        HonkVerifierAdapter adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)), PROGRAM_KEY);

        Verdict memory v = _witnessVerdict();
        bytes memory proof = vm.readFileBinary("./test/fixtures/allowlist.proof");
        bytes32 wrongKey = bytes32(uint256(PROGRAM_KEY) + 1);
        assertFalse(
            adapter.verifyProof(wrongKey, abi.encode(v), proof),
            "adapter accepted a proof under the wrong program key"
        );
    }
}
