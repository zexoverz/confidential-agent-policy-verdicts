// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {PolicyDomainRegistry} from "../src/PolicyDomainRegistry.sol";
import {ConfidentialPolicyVerdict} from "../src/ConfidentialPolicyVerdict.sol";
import {HonkVerifier} from "../src/verifier/HonkVerifier.sol";
import {HonkVerifierAdapter, IHonkVerifier} from "../src/HonkVerifierAdapter.sol";
import {IVerifier} from "../src/IVerifier.sol";
import {Verdict, PolicyKind} from "../src/IConfidentialPolicyVerdict.sol";

/// @notice Deploys the CAPV verifier stack and registers the ERC-8274 composed-run domain, giving the
/// CAPV leg a real on-chain, recompute-verifiable verifier for the /ledger entry (t/28083 #150).
/// The composed_live verdict's consume is bound to babyblue's executor and a fixed expiry, so it is not
/// re-consumable off a fresh chain. What IS recompute-verifiable is the proof itself: anyone can call the
/// deployed adapter's verifyProof over the published public inputs and get true.
contract DeployComposedRun is Script {
    bytes32 constant DOMAIN_ID = 0x16079127bc55bd85d480837115b9bd82d26f03809c0bc4c6c80f7220836afad0;
    bytes32 constant POLICY_ROOT = 0x204a14dc3ab2fdead5450192caea7428c2751b53a95b57d22f93cccb61af19a8;

    function run() external {
        vm.startBroadcast();
        PolicyDomainRegistry registry = new PolicyDomainRegistry();
        HonkVerifier honk = new HonkVerifier();
        HonkVerifierAdapter adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)));
        ConfidentialPolicyVerdict guard = new ConfidentialPolicyVerdict(registry);

        registry.registerDomain(DOMAIN_ID, msg.sender, address(adapter), bytes32(0), 1 hours);
        registry.updateRoot(DOMAIN_ID, POLICY_ROOT);
        vm.stopBroadcast();

        // Recompute check: the composed_live proof verifies through the deployed adapter (view, no state).
        Verdict memory v = Verdict({
            agentId: 54848,
            domainId: DOMAIN_ID,
            policyRoot: POLICY_ROOT,
            actionCommitment: 0x5b5ec31c336cc8f95dc6d9025d1d008c6ed2cd5067b9c421b1d36927e230173a,
            executor: 0x1C213D41668e5bDe79AaEE2240c6f6Ad7b4c9093,
            expiry: 1_700_003_600, // the proof's bound expiry (a public input)
            nullifier: 0x17f36ca085e9f988cc9e033ea510d5b6963265cb99e57e9677b0658531e0315f,
            decision: 1,
            policyKind: PolicyKind.ALLOWED
        });
        bytes memory proof = vm.readFileBinary("./test/fixtures/composed_live.proof");
        bool ok = IVerifier(address(adapter)).verifyProof(bytes32(0), abi.encode(v), proof);

        console2.log("composed_live proof verifies via deployed adapter:", ok);
        console2.log("Registry        ", address(registry));
        console2.log("HonkVerifier    ", address(honk));
        console2.log("Adapter/IVerifier", address(adapter));
        console2.log("Guard           ", address(guard));
    }
}
