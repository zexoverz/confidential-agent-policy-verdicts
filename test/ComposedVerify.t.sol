// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ConfidentialPolicyVerdict} from "../src/ConfidentialPolicyVerdict.sol";
import {PolicyDomainRegistry} from "../src/PolicyDomainRegistry.sol";
import {Verdict, PolicyKind} from "../src/IConfidentialPolicyVerdict.sol";
import {HonkVerifier} from "../src/verifier/HonkVerifier.sol";
import {HonkVerifierAdapter, IHonkVerifier} from "../src/HonkVerifierAdapter.sol";

/// @notice Minimal view of the ERC-8274 inference-proof verifier (the algorithm layer).
interface IProofVerifier {
    function verify(bytes32 inputHash, bytes32 outputHash, bytes calldata metadata, bytes calldata proof)
        external
        view
        returns (bool);
}

/// @notice Mock ERC-8274 verifier standing in for a real zkML / opML / TEE backend. Returns true for a
/// known (inputHash, outputHash). In a real run with babyblue this is swapped for a deployed ERC-8274
/// `IProofVerifier`; the CAPV half below is unchanged.
contract MockInferenceVerifier is IProofVerifier {
    function verify(bytes32, bytes32, bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }
}

/// @notice The two corners meeting on one flow. ERC-8274 attests the AI inference ran (the recompute /
/// proof corner). ERC-8354 (CAPV) proves the resulting action clears a policy that is never revealed
/// (the confidential corner). Same action, two orthogonal guarantees, no overlap. This is the composed
/// example offered in the ERC-8274 thread: 8274 under the counterparty, confidential policy under CAPV.
contract ComposedVerifyTest is Test {
    // HonkVerifier's own VK_HASH (src/verifier/HonkVerifier.sol:20).
    bytes32 constant PROGRAM_KEY = 0x10d07da428220548a6d7c4f405b1c8ded613a92e0b797262985a9ccdb1e6288e;

    /// The expiry the checked-in fixture proofs were generated with.
    uint64 constant FIXTURE_EXPIRY = 1900000000;

    function test_erc8274_inference_then_capv_confidential_verdict() public {
        // ---- Layer 1: ERC-8274 verifies the AI inference produced the output ----
        IProofVerifier inference = new MockInferenceVerifier();
        bytes32 inputHash = keccak256("prompt: rebalance treasury");
        bytes32 outputHash = keccak256("decision: transfer to 0x1234");
        assertTrue(inference.verify(inputHash, outputHash, "", hex""), "ERC-8274 inference proof must verify");

        // ---- Layer 2: ERC-8354 (CAPV) verifies the resulting action clears a confidential policy ----
        vm.warp(1_700_000_000);
        PolicyDomainRegistry registry = new PolicyDomainRegistry();
        HonkVerifier honk = new HonkVerifier();
        HonkVerifierAdapter adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)), PROGRAM_KEY);
        ConfidentialPolicyVerdict guard = new ConfidentialPolicyVerdict(registry);

        bytes32 domainId = bytes32(uint256(42));
        bytes32 policyRoot = 0x053d4542d140ad2350a0ee79fae4a522821274e428bd881e7e803ecd816635ac;
        registry.registerDomain(domainId, address(0xA11CE), address(adapter), PROGRAM_KEY, 1 hours);
        registry.updateRoot(domainId, policyRoot);

        address executor = address(0xE0);
        Verdict memory v = Verdict({
            agentId: 7,
            domainId: domainId,
            policyRoot: policyRoot,
            actionCommitment: 0x7ccb7a4e9d51128b951cbeddefaec1140180a3d13f6eae6f06596dc432057cfa,
            executor: executor,
            // The proof commits to `expiry` as public input [39], so a Verdict presented to a real
        // proof MUST carry the value the fixture was proven with. It used to be free here.
        expiry: FIXTURE_EXPIRY,
            nullifier: 0x041271fcaf479f6ab927df3a03f74d3809e9f49d880cd7a9595c8dc0a58a5e03,
            decision: 1,
            policyKind: PolicyKind.ALLOWED
        });

        bytes memory proof = vm.readFileBinary("./test/fixtures/allowlist.proof");
        vm.prank(executor);
        guard.consume(v, proof);

        // Both corners met on one flow: the inference is attested (8274) and the resulting action is
        // confidentially permitted (8354), with the nullifier burned so the verdict is one-time.
        assertTrue(guard.isConsumed(domainId, v.nullifier), "CAPV verdict must be consumed");
    }
}
