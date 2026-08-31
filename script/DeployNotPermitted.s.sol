// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {PolicyDomainRegistry} from "../src/PolicyDomainRegistry.sol";
import {NotAllowedHonkVerifier} from "../src/verifier/NotAllowedHonkVerifier.sol";
import {HonkVerifierAdapter, IHonkVerifier} from "../src/HonkVerifierAdapter.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {Verdict, PolicyKind} from "../src/IConfidentialPolicyVerdict.sol";

/// @notice Deploys the not-permitted (allowlist non-membership) leg and registers its domain against
/// the registry the live DENY board already reads, so the third refusal kind gets a real,
/// recompute-verifiable verifier alongside ALLOWED and DENIED.
///
/// @dev No new anchor is needed. ProvableDenialAnchor resolves its verifier from
/// `registry.domain(v.domainId).verifier`, so registering this domain is exactly what lets the
/// already-deployed anchor record a NOT_PERMITTED denial. The script ends with a view-only recompute
/// check, the same way DeployComposedRun does: anyone can call the deployed adapter over the published
/// proof and get true, which is what makes the deployment checkable by someone who does not trust us.
contract DeployNotPermitted is Script {
    /// The registry the live DENY anchors already read from.
    PolicyDomainRegistry constant REGISTRY = PolicyDomainRegistry(0xBDD6aB65C86fb8f0C47069a0562652d448E98cea);
    /// The anchor that will be able to record the denial once this domain exists.
    address constant PROVABLE_DENIAL_ANCHOR = 0xBAb4a69EEc7282dFFB18De2655F32797D800AdA5;

    // Public inputs the checked-in not_allowed proof is bound to, kept in sync with
    // noir-notallowed/Prover.toml. Every one of these is a public input, so none may drift.
    //
    // 0x2b, not 0x2a: the confidential DENY leg already holds 0x2a on this registry and
    // `registerDomain` reverts with `DomainExists()`. Because domain_id is a public input that also
    // feeds the commitment preimage and the nullifier, the proof below was regenerated under 0x2b.
    //
    // The witness also commits to chain_id 11155111 (Sepolia), the chain this leg is anchored on.
    // Nothing on-chain reads it — it is a private input — but the witness is published as
    // recompute-verifiable, so it names the chain the deployment actually lives on.
    bytes32 constant DOMAIN_ID = bytes32(uint256(0x2b));
    bytes32 constant POLICY_ROOT = 0x24e703f14986ec5abcb79d7292a4593b3370440fd4d1f2b6e51653e2e045707f;
    bytes32 constant COMMITMENT = 0xd1f89cac88ca71fea90df48ba29278d5782dc8eb76127bf7bfdafca71aaa8048;
    bytes32 constant NULLIFIER = 0x1d38c31e6bb446623f552d36f1ce11aa86c06cefe2b5a26e53f4700792f32c84;
    address constant EXECUTOR = address(0xe0);
    uint256 constant AGENT_ID = 7;
    // NotAllowedHonkVerifier's own VK_HASH (src/verifier/NotAllowedHonkVerifier.sol:20).
    bytes32 constant PROGRAM_KEY = 0x2747114ccc2ace618efcd53e2322dc9b1e0978b808bd80713454591b9584cc6c;

    function run() external {
        vm.startBroadcast();
        NotAllowedHonkVerifier honk = new NotAllowedHonkVerifier();
        HonkVerifierAdapter adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)), PROGRAM_KEY);

        // programKey is now bound at the adapter (zexoverz/confidential-agent-policy-verdicts#3):
        // the registry declares the same value so a future `updateProgram` that rotates the key
        // without also rotating `verifier` correctly stops verifying against this adapter, rather
        // than silently continuing to accept proofs for a program this domain no longer runs.
        REGISTRY.registerDomain(DOMAIN_ID, msg.sender, address(adapter), PROGRAM_KEY, 1 hours);
        REGISTRY.updateRoot(DOMAIN_ID, POLICY_ROOT);
        vm.stopBroadcast();

        Verdict memory v = Verdict({
            agentId: AGENT_ID,
            domainId: DOMAIN_ID,
            policyRoot: POLICY_ROOT,
            actionCommitment: COMMITMENT,
            executor: EXECUTOR,
            expiry: 0,
            nullifier: NULLIFIER,
            decision: 0,
            policyKind: PolicyKind.NOT_PERMITTED
        });
        bytes memory proof = vm.readFileBinary("./test/fixtures/not_allowed.proof");
        bool ok = IVerifier(address(adapter)).verifyProof(PROGRAM_KEY, abi.encode(v), proof);

        console2.log("not_allowed proof verifies via deployed adapter:", ok);
        console2.log("NotAllowedHonkVerifier", address(honk));
        console2.log("Adapter/IVerifier     ", address(adapter));
        console2.log("Registry              ", address(REGISTRY));
        console2.log("Anchor that reads it  ", PROVABLE_DENIAL_ANCHOR);
    }
}
