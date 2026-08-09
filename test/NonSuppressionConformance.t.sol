// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TransparentDenialAnchor} from "../src/TransparentDenialAnchor.sol";
import {IProvableDenial} from "../src/IProvableDenial.sol";
import {Verdict} from "../src/IConfidentialPolicyVerdict.sol";
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
            decision: 0
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
    /// Pending: requires `policy_kind` on the Verdict struct and the anchor read (the §4 carriage
    /// requirement). Once threaded, this asserts two decision=0 verdicts, a denylist hit and an
    /// allowlist non-membership, read back as denied vs not_permitted rather than one generic denied.
    function test_conformance_notPermittedDistinctFromDenied() public {
        vm.skip(true); // lights up when policy_kind reaches the Verdict struct + read surface
    }

    /// §6.4 — a kind proven in-circuit but absent from the consumed verdict MUST be refused.
    /// Pending: the carriage check. Once `policy_kind` is a Verdict field, this asserts a verdict that
    /// dropped its kind before consumption is rejected, so the taxonomy cannot be adopted in words
    /// while the mechanism is silently discarded at the boundary.
    function test_conformance_kindMustSurviveToConsumedVerdict() public {
        vm.skip(true); // lights up when policy_kind reaches the Verdict struct + read surface
    }
}
