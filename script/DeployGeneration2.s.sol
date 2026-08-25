// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {PolicyDomainRegistry} from "../src/PolicyDomainRegistry.sol";
import {ConfidentialPolicyVerdict} from "../src/ConfidentialPolicyVerdict.sol";
import {ProvableDenialAnchor} from "../src/ProvableDenialAnchor.sol";
import {IPolicyDomainRegistry} from "../src/IPolicyDomainRegistry.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {Verdict, PolicyKind} from "../src/IConfidentialPolicyVerdict.sol";

/// @notice Redeploys the registry-bound half of the Sepolia stack, because the live registry
/// `0xBDD6aB65C86fb8f0C47069a0562652d448E98cea` predates two fixes that are in this repository:
/// the grace window now ages each superseded generation from its own supersession rather than from
/// the current root's takeover (`SupersededRoot[MAX_ROOT_HISTORY]` instead of a single `_previous`
/// slot), and `Domain` carries `identityRegistry` so a domain can declare the ERC-8004 registry its
/// agent ids live in.
///
/// @dev `registry` is `immutable` in both `ConfidentialPolicyVerdict` and `ProvableDenialAnchor`,
/// so a new registry forces new instances of both. Nothing else moves: `TransparentDenialAnchor`
/// holds no registry reference, and the Honk verifiers and their adapters resolve nothing from the
/// registry, so generation 1's are reused at their existing addresses.
///
/// The three domain ids are re-registered unchanged. The circuits bind `chain_id` and `domain_id`
/// and never the registry address, so every proof already published stays valid under this registry.
/// `verifier`, `programKey` and `maxRootAge` are carried across exactly as they read on the live
/// registry today.
///
/// Reading all three live records back, `registrar` is already the deploying EOA on `0x…002a` and on
/// the composed-run domain, and is Forge's default sender only on `0x…002b`. So that one field is the
/// only value that differs from generation 1. It is not a fix that can be applied in place:
/// `registerDomain` is once-only and there is no setter, which is why it survives only as a new
/// registration here.
contract DeployGeneration2 is Script {
    /// The EOA that must own every domain. Passed explicitly rather than taken from `msg.sender`:
    /// on the generation-1 not-permitted deploy `msg.sender` resolved to Forge's default sender and
    /// `registerDomain` is once-only, so the wrong registrar is permanent there.
    address constant REGISTRAR = 0xb0175f56d4731C02aC9A30877fcD7c18C6af1858;

    /// Generation 1, read from `0xBDD6aB65C86fb8f0C47069a0562652d448E98cea` and reused as-is.
    address constant DENY_ADAPTER = 0x0f1b6f28C736cc58bfa486ED28C26182b41Cf76d;
    address constant NOT_ALLOWED_ADAPTER = 0xcb037101D5932d5F8760CDdaA0fB8BE1a8662DB4;
    address constant COMPOSED_ADAPTER = 0x42c799cC90122705FC180B4801f4067B76843B1e;

    bytes32 constant DENY_DOMAIN = bytes32(uint256(0x2a));
    bytes32 constant NOT_ALLOWED_DOMAIN = bytes32(uint256(0x2b));
    bytes32 constant COMPOSED_DOMAIN = 0x16079127bc55bd85d480837115b9bd82d26f03809c0bc4c6c80f7220836afad0;

    bytes32 constant DENY_ROOT = 0x053d4542d140ad2350a0ee79fae4a522821274e428bd881e7e803ecd816635ac;
    bytes32 constant NOT_ALLOWED_ROOT = 0x24e703f14986ec5abcb79d7292a4593b3370440fd4d1f2b6e51653e2e045707f;
    bytes32 constant COMPOSED_ROOT = 0x204a14dc3ab2fdead5450192caea7428c2751b53a95b57d22f93cccb61af19a8;

    uint64 constant MAX_ROOT_AGE = 1 hours;

    // The public inputs each checked-in proof is bound to, kept in sync with the circuits' Prover.toml
    // files. Every one of them is a public input, so none may drift.
    bytes32 constant NOT_ALLOWED_COMMITMENT = 0xd1f89cac88ca71fea90df48ba29278d5782dc8eb76127bf7bfdafca71aaa8048;
    bytes32 constant NOT_ALLOWED_NULLIFIER = 0x1d38c31e6bb446623f552d36f1ce11aa86c06cefe2b5a26e53f4700792f32c84;

    bytes32 constant DENY_COMMITMENT = 0x7ccb7a4e9d51128b951cbeddefaec1140180a3d13f6eae6f06596dc432057cfa;
    bytes32 constant DENY_NULLIFIER = 0x041271fcaf479f6ab927df3a03f74d3809e9f49d880cd7a9595c8dc0a58a5e03;

    bytes32 constant COMPOSED_COMMITMENT = 0x5b5ec31c336cc8f95dc6d9025d1d008c6ed2cd5067b9c421b1d36927e230173a;
    bytes32 constant COMPOSED_NULLIFIER = 0x17f36ca085e9f988cc9e033ea510d5b6963265cb99e57e9677b0658531e0315f;
    address constant COMPOSED_EXECUTOR = 0x1C213D41668e5bDe79AaEE2240c6f6Ad7b4c9093;

    /// The denial legs share the fixture executor and agent id; the composed run does not.
    address constant DENIAL_EXECUTOR = address(0xe0);
    uint256 constant DENIAL_AGENT_ID = 7;

    function run() external {
        vm.startBroadcast();
        PolicyDomainRegistry registry = new PolicyDomainRegistry();
        ConfidentialPolicyVerdict guard = new ConfidentialPolicyVerdict(registry);
        ProvableDenialAnchor anchor = new ProvableDenialAnchor(registry);

        // programKey stays bytes32(0) on all three, as on generation 1: each domain binds its
        // program through the deployed verifier address rather than a separate commitment.
        registry.registerDomain(DENY_DOMAIN, REGISTRAR, DENY_ADAPTER, bytes32(0), MAX_ROOT_AGE);
        registry.updateRoot(DENY_DOMAIN, DENY_ROOT);

        registry.registerDomain(NOT_ALLOWED_DOMAIN, REGISTRAR, NOT_ALLOWED_ADAPTER, bytes32(0), MAX_ROOT_AGE);
        registry.updateRoot(NOT_ALLOWED_DOMAIN, NOT_ALLOWED_ROOT);

        registry.registerDomain(COMPOSED_DOMAIN, REGISTRAR, COMPOSED_ADAPTER, bytes32(0), MAX_ROOT_AGE);
        registry.updateRoot(COMPOSED_DOMAIN, COMPOSED_ROOT);
        vm.stopBroadcast();

        _report(registry, DENY_DOMAIN, "0x..002a  confidential DENY");
        _report(registry, NOT_ALLOWED_DOMAIN, "0x..002b  NOT_PERMITTED    ");
        _report(registry, COMPOSED_DOMAIN, "composed run             ");

        // Recompute checks, view-only and routed through the NEW registry, one per leg. Every domain
        // this script writes gets checked, not just one: a mistyped root or a verifier copied from the
        // wrong leg would let `registerDomain`/`updateRoot` succeed silently, with no revert and no
        // on-chain signal. Running each published proof back through the registry is what turns a
        // wrong constant into a visible `false` here.
        //
        // This is also the whole point of the deployment. A stranger repeats these reads against the
        // deployed addresses and needs to trust nobody.
        console2.log("");
        _recompute(
            registry,
            "0x..002a  confidential DENY",
            "./test/fixtures/deny.proof",
            Verdict({
                agentId: DENIAL_AGENT_ID,
                domainId: DENY_DOMAIN,
                policyRoot: DENY_ROOT,
                actionCommitment: DENY_COMMITMENT,
                executor: DENIAL_EXECUTOR,
                expiry: 0,
                nullifier: DENY_NULLIFIER,
                decision: 0,
                policyKind: PolicyKind.DENIED
            })
        );
        _recompute(
            registry,
            "0x..002b  NOT_PERMITTED",
            "./test/fixtures/not_allowed.proof",
            Verdict({
                agentId: DENIAL_AGENT_ID,
                domainId: NOT_ALLOWED_DOMAIN,
                policyRoot: NOT_ALLOWED_ROOT,
                actionCommitment: NOT_ALLOWED_COMMITMENT,
                executor: DENIAL_EXECUTOR,
                expiry: 0,
                nullifier: NOT_ALLOWED_NULLIFIER,
                decision: 0,
                policyKind: PolicyKind.NOT_PERMITTED
            })
        );
        _recompute(
            registry,
            "composed run",
            "./test/fixtures/composed_live.proof",
            Verdict({
                agentId: 54848,
                domainId: COMPOSED_DOMAIN,
                policyRoot: COMPOSED_ROOT,
                actionCommitment: COMPOSED_COMMITMENT,
                executor: COMPOSED_EXECUTOR,
                expiry: 1_700_003_600, // the proof's bound expiry (a public input)
                nullifier: COMPOSED_NULLIFIER,
                decision: 1,
                policyKind: PolicyKind.ALLOWED
            })
        );

        console2.log("");
        console2.log("PolicyDomainRegistry (gen 2)", address(registry));
        console2.log("ConfidentialPolicyVerdict   ", address(guard));
        console2.log("ProvableDenialAnchor        ", address(anchor));
    }

    /// @dev Resolves the verifier and programKey out of the new registry exactly the way the Guard and
    /// the anchor resolve them, confirms the root the proof is bound to is acceptable there, then runs
    /// the checked-in proof through that verifier. Nothing is hardcoded on the call path: a wrong
    /// `verifier` or `policyRoot` constant surfaces as `false` rather than passing unnoticed.
    function _recompute(
        PolicyDomainRegistry registry,
        string memory label,
        string memory fixturePath,
        Verdict memory v
    ) internal view {
        IPolicyDomainRegistry.Domain memory d = registry.domain(v.domainId);
        bool rootOk = registry.isRootAcceptable(v.domainId, v.policyRoot);
        bytes memory proof = vm.readFileBinary(fixturePath);
        bool ok = IVerifier(d.verifier).verifyProof(d.programKey, abi.encode(v), proof);
        console2.log(label);
        console2.log("  root acceptable on new registry", rootOk);
        console2.log("  proof verifies via new registry", ok);
    }

    function _report(PolicyDomainRegistry registry, bytes32 domainId, string memory label) internal view {
        IPolicyDomainRegistry.Domain memory d = registry.domain(domainId);
        (bytes32 root, uint64 version,) = registry.currentRoot(domainId);
        console2.log("");
        console2.log(label);
        console2.log("  registrar       ", d.registrar);
        console2.log("  identityRegistry", d.identityRegistry);
        console2.log("  verifier        ", d.verifier);
        console2.log("  maxRootAge      ", d.maxRootAge);
        console2.log("  active          ", d.active);
        console2.log("  admin           ", registry.admin(domainId));
        console2.logBytes32(root);
        console2.log("  root version    ", version);
    }
}
