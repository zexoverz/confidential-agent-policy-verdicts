// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ProvableDenialAnchor} from "../src/ProvableDenialAnchor.sol";
import {IProvableDenial} from "../src/IProvableDenial.sol";
import {ConfidentialPolicyVerdict} from "../src/ConfidentialPolicyVerdict.sol";
import {Verdict} from "../src/IConfidentialPolicyVerdict.sol";
import {PolicyDomainRegistry} from "../src/PolicyDomainRegistry.sol";
import {MockVerifier} from "../src/mocks/MockVerifier.sol";

/// @notice The provable-denial companion: a DENY verdict leaves a replay-protected trace, while the
/// ALLOW path in the core Guard stays untouched. This is the piece that lets an observer tell
/// "evaluated and denied" from "never evaluated" on the confidential path.
contract ProvableDenialTest is Test {
    // Re-declared locally so vm.expectEmit can match it.
    event DenialAnchored(
        bytes32 indexed nullifier,
        uint256 indexed agentId,
        bytes32 indexed domainId,
        bytes32 policyRoot,
        bytes32 actionCommitment
    );

    PolicyDomainRegistry registry;
    ProvableDenialAnchor denial;
    ConfidentialPolicyVerdict guard;
    MockVerifier verifier;

    bytes32 constant DOMAIN = keccak256("acme-compliance");
    bytes32 constant ROOT = keccak256("root-v1");
    bytes32 constant PROGRAM = keccak256("interpreter-vkey");
    address constant EXECUTOR = address(0xE0);

    function setUp() public {
        vm.warp(1_700_000_000);
        registry = new PolicyDomainRegistry();
        verifier = new MockVerifier();
        denial = new ProvableDenialAnchor(registry);
        guard = new ConfidentialPolicyVerdict(registry);
        registry.registerDomain(DOMAIN, address(0xA11CE), address(verifier), PROGRAM, 1 hours);
        registry.updateRoot(DOMAIN, ROOT);
    }

    function _deny() internal view returns (Verdict memory v) {
        v = Verdict({
            agentId: 1,
            domainId: DOMAIN,
            policyRoot: ROOT,
            actionCommitment: keccak256("action"),
            executor: EXECUTOR,
            expiry: uint64(block.timestamp + 1 hours),
            nullifier: keccak256("nf-deny-1"),
            decision: 0
        });
    }

    // A DENY verdict anchors: it records the denial and emits the trace.
    function test_AnchorDenial() public {
        Verdict memory v = _deny();
        vm.expectEmit(true, true, true, true);
        emit DenialAnchored(v.nullifier, v.agentId, v.domainId, v.policyRoot, v.actionCommitment);
        denial.anchorDenial(v, "proof");
        assertTrue(denial.isDenied(DOMAIN, v.nullifier));
    }

    // Anchoring the same denial twice reverts.
    function test_DenialReplay() public {
        Verdict memory v = _deny();
        denial.anchorDenial(v, "proof");
        vm.expectRevert(abi.encodeWithSelector(IProvableDenial.DenialReplayed.selector, v.nullifier));
        denial.anchorDenial(v, "proof");
    }

    // An ALLOW verdict cannot be anchored as a denial.
    function test_AllowNotAnchorable() public {
        Verdict memory v = _deny();
        v.decision = 1;
        vm.expectRevert(abi.encodeWithSelector(IProvableDenial.NotADenial.selector, uint8(1)));
        denial.anchorDenial(v, "proof");
    }

    // Invalid proof reverts.
    function test_InvalidProofReverts() public {
        verifier.setResult(false);
        Verdict memory v = _deny();
        vm.expectRevert(IProvableDenial.DenialProofInvalid.selector);
        denial.anchorDenial(v, "proof");
    }

    // A revoked/inactive domain reverts.
    function test_InactiveDomainReverts() public {
        registry.revokeDomain(DOMAIN);
        Verdict memory v = _deny();
        vm.expectRevert(abi.encodeWithSelector(IProvableDenial.DenialDomainInactive.selector, DOMAIN));
        denial.anchorDenial(v, "proof");
    }

    // The whole point: an anchored denial is a distinct, independent state from consumption. The
    // ALLOW Guard's consumed set is untouched, so "denied" and "allowed" never collapse into each other.
    function test_DenialIsNotConsumption() public {
        Verdict memory v = _deny();
        denial.anchorDenial(v, "proof");
        assertTrue(denial.isDenied(DOMAIN, v.nullifier));
        assertFalse(guard.isConsumed(DOMAIN, v.nullifier));
    }
}
