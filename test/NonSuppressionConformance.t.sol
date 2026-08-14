// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TransparentDenialAnchor} from "../src/TransparentDenialAnchor.sol";
import {IProvableDenial} from "../src/IProvableDenial.sol";
import {Verdict, PolicyKind} from "../src/IConfidentialPolicyVerdict.sol";
import {PolicyAction, PolicyActionLib} from "../src/PolicyAction.sol";

/// @dev ERC-8274 non-suppression conformance vectors (§6). For each state the section names, a refusal
/// the implementation must make, written so the test passes only because the refusal is present and
/// would fail the moment it is removed. Two vectors are live today; two light up once `policy_kind` is
/// carried into the Verdict struct and the anchor read surface (the §4 carriage requirement, pending
/// the group vote). The two that go unchecked by default are exactly the two that get confused, so the
/// suite keeps them present as skipped rather than absent.
contract NonSuppressionConformanceTest is Test {
    using PolicyActionLib for PolicyAction;

    TransparentDenialAnchor internal anchor;
    bytes32 constant DOMAIN = bytes32(uint256(0x1607));
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

    function _deny(PolicyAction memory a) internal pure returns (Verdict memory v) {
        v = Verdict({
            agentId: a.agentId,
            domainId: a.domainId,
            policyRoot: bytes32(uint256(0x204a)),
            actionCommitment: a.commit(),
            executor: address(0x1C21),
            expiry: 0,
            nullifier: NULLIFIER,
            decision: 0,
            policyKind: PolicyKind.DENIED
        });
    }

    /// §6.1 — a DENY MUST leave a readable trace, and an absence MUST never read as a denial.
    /// The refusal: the anchor refuses to report an un-anchored action as denied. Remove that (default
    /// isDenied to true) and the absence assertions fail.
    function test_conformance_denialLeavesTrace_absenceIsNotDenial() public {
        PolicyAction memory a = _action();
        // absence: before any anchor, the action is not denied.
        assertFalse(anchor.isDenied(DOMAIN, NULLIFIER), "unevaluated action must not read as denied");
        // a real DENY leaves a readable, replay-protected trace.
        anchor.anchorDenial(_deny(a), abi.encode(a));
        assertTrue(anchor.isDenied(DOMAIN, NULLIFIER), "a denial must leave a readable trace");
        // a different, still-unevaluated action stays absent.
        assertFalse(anchor.isDenied(DOMAIN, bytes32(uint256(0xBEEF))), "absence stays absence");
    }

    /// §6.2 — an unevaluated action MUST NOT be able to manufacture a decision=0 record. The
    /// transparent anchor only records a denial whose commitment recomputes from the public preimage,
    /// so a claim over an action never committed is refused. Remove the recompute check and the revert
    /// stops, letting silence become a denial.
    function test_conformance_unevaluatedCannotManufactureDenial() public {
        PolicyAction memory a = _action();
        Verdict memory v = _deny(a);
        // a verdict whose commitment does not recompute from the supplied preimage is refused.
        v.actionCommitment = keccak256("an action that was never evaluated");
        vm.expectRevert(IProvableDenial.DenialProofInvalid.selector);
        anchor.anchorDenial(v, abi.encode(a));
        // nothing was recorded.
        assertFalse(anchor.isDenied(DOMAIN, NULLIFIER), "a refused anchor records nothing");
    }

    /// §6.3 — NOT-PERMITTED MUST be distinguishable from DENIED at the consumed surface.
    /// Two decision=0 verdicts, a denylist hit and an allowlist non-membership, must read back as
    /// different kinds rather than one generic denial. The refusal being tested is the loss of that
    /// distinction: collapse `denialKind` to a constant and this fails.
    function test_conformance_notPermittedDistinctFromDenied() public {
        PolicyAction memory a = _action();

        // (1) a rule fired against the action.
        Verdict memory denied = _deny(a);
        anchor.anchorDenial(denied, abi.encode(a));

        // (2) a different action that nothing authorized.
        PolicyAction memory b = _action();
        b.actionNonce = 6;
        Verdict memory notPermitted = _deny(b);
        notPermitted.actionCommitment = b.commit();
        notPermitted.nullifier = bytes32(uint256(0x17f4));
        notPermitted.policyKind = PolicyKind.NOT_PERMITTED;
        anchor.anchorDenial(notPermitted, abi.encode(b));

        // both are denials...
        assertTrue(anchor.isDenied(DOMAIN, NULLIFIER), "denylist hit is a denial");
        assertTrue(anchor.isDenied(DOMAIN, bytes32(uint256(0x17f4))), "non-membership is a denial");
        // ...but they are not the same claim.
        assertEq(anchor.denialKind(DOMAIN, NULLIFIER), PolicyKind.DENIED, "a rule refused this");
        assertEq(
            anchor.denialKind(DOMAIN, bytes32(uint256(0x17f4))),
            PolicyKind.NOT_PERMITTED,
            "nothing authorized this"
        );
        assertTrue(
            anchor.denialKind(DOMAIN, NULLIFIER) != anchor.denialKind(DOMAIN, bytes32(uint256(0x17f4))),
            "the two refusals must not collapse into one generic denial"
        );
    }

    /// §6.4 — a kind proven in-circuit but absent from the consumed verdict MUST be refused.
    /// A verdict that dropped its kind on the way to the boundary carries the default ALLOWED kind,
    /// which is not a refusal. Anchoring it must revert rather than record a kindless denial, so the
    /// taxonomy cannot be adopted in words while the mechanism is discarded at the boundary.
    function test_conformance_kindMustSurviveToConsumedVerdict() public {
        PolicyAction memory a = _action();
        Verdict memory v = _deny(a);
        v.policyKind = PolicyKind.ALLOWED; // the kind was proven in-circuit but dropped here

        vm.expectRevert(abi.encodeWithSelector(IProvableDenial.NotARefusalKind.selector, PolicyKind.ALLOWED));
        anchor.anchorDenial(v, abi.encode(a));

        // and nothing was recorded, so a dropped kind cannot leave a half-record behind.
        assertFalse(anchor.isDenied(DOMAIN, NULLIFIER), "a kindless denial records nothing");
        assertEq(anchor.denialKind(DOMAIN, NULLIFIER), PolicyKind.ALLOWED, "no kind is anchored");
    }
}
