// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ConfidentialPolicyVerdict} from "../src/ConfidentialPolicyVerdict.sol";
import {PolicyDomainRegistry} from "../src/PolicyDomainRegistry.sol";
import {Verdict, PolicyKind} from "../src/IConfidentialPolicyVerdict.sol";
import {HonkVerifier} from "../src/verifier/HonkVerifier.sol";
import {HonkVerifierAdapter, IHonkVerifier} from "../src/HonkVerifierAdapter.sol";

/// @notice The definitive no-mock test: the Guard's real `consume` runs all seven checks, with the
/// proof step verifying the REAL UltraHonk proof through the Honk verifier adapter. If this passes,
/// the reference implementation is verified end to end with no mock in the path.
contract ConsumeRealTest is Test {
    // HonkVerifier's own VK_HASH (src/verifier/HonkVerifier.sol:20).
    bytes32 constant PROGRAM_KEY = 0x15dfad359ae3d919488f92128f12290d908220925f263eeec28e8a97f21a372a;

    function test_consume_with_real_proof() public {
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
            expiry: uint64(block.timestamp + 1 hours),
            nullifier: 0x041271fcaf479f6ab927df3a03f74d3809e9f49d880cd7a9595c8dc0a58a5e03,
            decision: 1,
            policyKind: PolicyKind.ALLOWED
        });

        bytes memory proof = vm.readFileBinary("./test/fixtures/allowlist.proof");
        vm.prank(executor);
        guard.consume(v, proof);

        assertTrue(guard.isConsumed(domainId, v.nullifier), "verdict not consumed with real proof");
    }
}
