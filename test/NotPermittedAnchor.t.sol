// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {NotAllowedHonkVerifier} from "../src/verifier/NotAllowedHonkVerifier.sol";
import {HonkVerifierAdapter, IHonkVerifier} from "../src/HonkVerifierAdapter.sol";
import {ProvableDenialAnchor} from "../src/ProvableDenialAnchor.sol";
import {TransparentDenialAnchor} from "../src/TransparentDenialAnchor.sol";
import {IProvableDenial} from "../src/IProvableDenial.sol";
import {PolicyDomainRegistry} from "../src/PolicyDomainRegistry.sol";
import {Verdict, PolicyKind} from "../src/IConfidentialPolicyVerdict.sol";
import {PolicyAction, PolicyActionLib} from "../src/PolicyAction.sol";

/// @notice The not-permitted kind, end to end on both corners of the DENY board.
///
/// `denialKind()` is what keeps "a rule refused this" (DENIED) apart from "nothing authorized this"
/// (NOT_PERMITTED) for a relying party gating an irreversible action. Here the distinction is carried
/// by a real UltraHonk proof of allowlist NON-membership: `policyKind == 2` is a committed public
/// input, so the anchor records a kind the proof actually established.
contract NotPermittedAnchorTest is Test {
    /// The expiry the checked-in fixture proofs were generated with.
    uint64 constant FIXTURE_EXPIRY = 1900000000;

    using PolicyActionLib for PolicyAction;

    bytes32 constant DOMAIN = bytes32(uint256(43));
    bytes32 constant POLICY_ROOT = 0x24e703f14986ec5abcb79d7292a4593b3370440fd4d1f2b6e51653e2e045707f;
    bytes32 constant COMMITMENT = 0xd1f89cac88ca71fea90df48ba29278d5782dc8eb76127bf7bfdafca71aaa8048;
    bytes32 constant NULLIFIER = 0x1d38c31e6bb446623f552d36f1ce11aa86c06cefe2b5a26e53f4700792f32c84;
    bytes32 constant PROGRAM = keccak256("capv_not_allowed");
    address constant EXECUTOR = address(0xE0);
    // The target the proof shows is absent from the committed allowlist.
    address constant TARGET = 0x5555555555555555555555555555555555555555;

    PolicyDomainRegistry internal registry;
    ProvableDenialAnchor internal anchor;
    TransparentDenialAnchor internal transparentAnchor;

    function setUp() public {
        vm.warp(1_700_000_000);
        registry = new PolicyDomainRegistry();
        anchor = new ProvableDenialAnchor(registry);
        transparentAnchor = new TransparentDenialAnchor();

        NotAllowedHonkVerifier honk = new NotAllowedHonkVerifier();
        HonkVerifierAdapter adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)), PROGRAM);
        registry.registerDomain(DOMAIN, address(0xA11CE), address(adapter), PROGRAM, 1 hours);
        registry.updateRoot(DOMAIN, POLICY_ROOT);
    }

    function _verdict() internal pure returns (Verdict memory v) {
        v = Verdict({
            agentId: 7,
            domainId: DOMAIN,
            policyRoot: POLICY_ROOT,
            actionCommitment: COMMITMENT,
            executor: EXECUTOR,
            // The proof commits to `expiry` as public input [39], so a Verdict presented to a real
        // proof MUST carry the value the fixture was proven with. It used to be free here.
        expiry: FIXTURE_EXPIRY,
            nullifier: NULLIFIER,
            decision: 0,
            policyKind: PolicyKind.NOT_PERMITTED
        });
    }

    /// The action the circuit committed to. Its `commit()` must equal the commitment the proof
    /// carries — the same preimage packing on both sides of the boundary.
    function _action() internal pure returns (PolicyAction memory a) {
        a = PolicyAction({
            chainId: 11155111,
            domainId: DOMAIN,
            agentId: 7,
            target: TARGET,
            value: 0,
            callDataHash: bytes32(0),
            actionNonce: 3
        });
    }

    function _proof() internal view returns (bytes memory) {
        return vm.readFileBinary("./test/fixtures/not_allowed.proof");
    }

    // THE POINT: a real non-membership proof anchors, and the anchor reports kind 2, not just "denied".
    function test_anchorsNotPermittedWithRealProof() public {
        Verdict memory v = _verdict();

        vm.expectEmit(true, true, true, true);
        emit IProvableDenial.DenialAnchored(
            v.nullifier, v.agentId, v.domainId, v.policyRoot, v.actionCommitment, PolicyKind.NOT_PERMITTED
        );
        anchor.anchorDenial(v, _proof());

        assertTrue(anchor.isDenied(DOMAIN, NULLIFIER), "not-permitted denial must be anchored");
        assertEq(anchor.denialKind(DOMAIN, NULLIFIER), PolicyKind.NOT_PERMITTED, "kind must be 2");
    }

    /// A kind the proof did not establish is not anchorable: relabelling the same proof as DENIED
    /// changes a committed public input, so verification fails. The Honk verifier signals that by
    /// reverting rather than returning false, so the anchor's own `DenialProofInvalid` is not
    /// reached — the anchoring is refused either way.
    function test_cannotRelabelAsDenied() public {
        Verdict memory v = _verdict();
        v.policyKind = PolicyKind.DENIED;
        vm.expectRevert();
        anchor.anchorDenial(v, _proof());
    }

    /// Nor as ALLOWED — that one is rejected earlier, on the decision/kind agreement check.
    function test_cannotAnchorUnderAllowedKind() public {
        Verdict memory v = _verdict();
        v.policyKind = PolicyKind.ALLOWED;
        vm.expectRevert(
            abi.encodeWithSelector(IProvableDenial.NotARefusalKind.selector, PolicyKind.ALLOWED)
        );
        anchor.anchorDenial(v, _proof());
    }

    /// An allowlist root the domain never accepted is rejected before the proof is even verified.
    function test_unacceptedRootReverts() public {
        Verdict memory v = _verdict();
        v.policyRoot = keccak256("an allowlist this domain never committed");
        vm.expectRevert(
            abi.encodeWithSelector(IProvableDenial.DenialPolicyRootRejected.selector, v.policyRoot)
        );
        anchor.anchorDenial(v, _proof());
    }

    /// Anchoring is single-use on the confidential corner too.
    function test_replayReverts() public {
        Verdict memory v = _verdict();
        anchor.anchorDenial(v, _proof());
        vm.expectRevert(abi.encodeWithSelector(IProvableDenial.DenialReplayed.selector, NULLIFIER));
        anchor.anchorDenial(v, _proof());
    }

    /// An action nobody anchored has kind 0 and is not denied — never-evaluated stays distinguishable.
    function test_unevaluatedHasNoKind() public view {
        assertFalse(anchor.isDenied(DOMAIN, NULLIFIER));
        assertEq(anchor.denialKind(DOMAIN, NULLIFIER), 0);
    }

    /// The transparent corner carries the same kind with no secret: the PolicyAction preimage the
    /// circuit hashed recomputes, on-chain, to the very commitment the proof committed to.
    function test_transparentCornerCarriesTheSameKind() public {
        PolicyAction memory a = _action();
        assertEq(a.commit(), COMMITMENT, "on-chain packing must match the circuit's preimage");

        Verdict memory v = _verdict();
        transparentAnchor.anchorDenial(v, abi.encode(a));

        assertTrue(transparentAnchor.isDenied(DOMAIN, NULLIFIER));
        assertEq(
            transparentAnchor.denialKind(DOMAIN, NULLIFIER),
            PolicyKind.NOT_PERMITTED,
            "both corners report the same kind"
        );
    }

    /// The two refusal kinds are independent records, so a relying party reading `denialKind` gets
    /// the reason it was actually given, per (domain, nullifier).
    function test_deniedAndNotPermittedDoNotCollapse() public {
        PolicyAction memory a = _action();
        transparentAnchor.anchorDenial(_verdict(), abi.encode(a));

        PolicyAction memory other = _action();
        other.actionNonce = 4;
        Verdict memory ruleFired = _verdict();
        ruleFired.nullifier = keccak256("nf-denied-1");
        ruleFired.actionCommitment = other.commit();
        ruleFired.policyKind = PolicyKind.DENIED;
        transparentAnchor.anchorDenial(ruleFired, abi.encode(other));

        assertEq(transparentAnchor.denialKind(DOMAIN, NULLIFIER), PolicyKind.NOT_PERMITTED);
        assertEq(transparentAnchor.denialKind(DOMAIN, ruleFired.nullifier), PolicyKind.DENIED);
    }
}
