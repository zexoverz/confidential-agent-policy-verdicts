// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TransparentDenialAnchor} from "../src/TransparentDenialAnchor.sol";
import {IProvableDenial} from "../src/IProvableDenial.sol";
import {Verdict, PolicyKind} from "../src/IConfidentialPolicyVerdict.sol";
import {PolicyAction, PolicyActionLib} from "../src/PolicyAction.sol";

/// @dev Transparent (recompute) denial anchor: the "proof" is the public PolicyAction preimage, so
/// anchoring is a recompute-and-compare with no ZK secret. These tests exercise the honest property
/// and the guards a recompute-denial verifier binds to.
contract TransparentDenialAnchorTest is Test {
    using PolicyActionLib for PolicyAction;

    TransparentDenialAnchor internal anchor;

    bytes32 constant DOMAIN = bytes32(uint256(0x1607));
    bytes32 constant OTHER_DOMAIN = bytes32(uint256(0xdead));
    bytes32 constant NULLIFIER = bytes32(uint256(0x17f3));

    function setUp() public {
        anchor = new TransparentDenialAnchor();
    }

    function _action() internal pure returns (PolicyAction memory a) {
        a = PolicyAction({
            chainId: 11155111,
            domainId: DOMAIN,
            agentId: 54848,
            target: 0xcA11bde05977b3631167028862bE2a173976CA11,
            value: 0,
            callDataHash: keccak256("aggregate3([])"),
            actionNonce: 5
        });
    }

    function _denyVerdict(PolicyAction memory a) internal pure returns (Verdict memory v) {
        v = Verdict({
            agentId: a.agentId,
            domainId: a.domainId,
            policyRoot: bytes32(uint256(0x204a)),
            actionCommitment: a.commit(),
            executor: address(0x1C21),
            expiry: 1_700_003_600,
            nullifier: NULLIFIER,
            decision: 0,
            policyKind: PolicyKind.DENIED
        });
    }

    function test_anchorsAndReportsDenied() public {
        PolicyAction memory a = _action();
        Verdict memory v = _denyVerdict(a);

        vm.expectEmit(true, true, true, true);
        emit IProvableDenial.DenialAnchored(
            v.nullifier, v.agentId, v.domainId, v.policyRoot, v.actionCommitment, v.policyKind
        );
        anchor.anchorDenial(v, abi.encode(a));

        assertTrue(anchor.isDenied(DOMAIN, NULLIFIER), "denial must be anchored");
    }

    /// THE POINT: an action nobody anchored is not denied, so evaluated-and-denied is distinguishable
    /// from never-evaluated.
    function test_unevaluatedIsNotDenied() public view {
        assertFalse(anchor.isDenied(DOMAIN, NULLIFIER));
        assertFalse(anchor.isDenied(DOMAIN, bytes32(uint256(0x9999))));
    }

    /// Domain-scoped: a denial under one domain does not mark the action denied under another.
    function test_domainScoped() public {
        PolicyAction memory a = _action();
        anchor.anchorDenial(_denyVerdict(a), abi.encode(a));
        assertTrue(anchor.isDenied(DOMAIN, NULLIFIER));
        assertFalse(anchor.isDenied(OTHER_DOMAIN, NULLIFIER), "denial must not cross domains");
    }

    function test_revertsOnNonDenial() public {
        PolicyAction memory a = _action();
        Verdict memory v = _denyVerdict(a);
        v.decision = 1;
        vm.expectRevert(abi.encodeWithSelector(IProvableDenial.NotADenial.selector, uint8(1)));
        anchor.anchorDenial(v, abi.encode(a));
    }

    function test_revertsOnReplay() public {
        PolicyAction memory a = _action();
        Verdict memory v = _denyVerdict(a);
        anchor.anchorDenial(v, abi.encode(a));
        vm.expectRevert(abi.encodeWithSelector(IProvableDenial.DenialReplayed.selector, v.nullifier));
        anchor.anchorDenial(v, abi.encode(a));
    }

    function test_revertsOnCommitmentMismatch() public {
        PolicyAction memory a = _action();
        Verdict memory v = _denyVerdict(a);
        v.actionCommitment = keccak256("not the real commitment");
        vm.expectRevert(IProvableDenial.DenialProofInvalid.selector);
        anchor.anchorDenial(v, abi.encode(a));
    }

    function test_revertsOnDomainMismatch() public {
        PolicyAction memory a = _action();
        Verdict memory v = _denyVerdict(a);
        v.domainId = OTHER_DOMAIN; // verdict claims a domain the preimage was not scoped to
        v.actionCommitment = a.commit();
        vm.expectRevert(
            abi.encodeWithSelector(TransparentDenialAnchor.DomainMismatch.selector, a.domainId, OTHER_DOMAIN)
        );
        anchor.anchorDenial(v, abi.encode(a));
    }
}
