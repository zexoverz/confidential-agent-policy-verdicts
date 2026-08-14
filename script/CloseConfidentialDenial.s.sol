// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {DenyHonkVerifier} from "../src/verifier/DenyHonkVerifier.sol";
import {HonkVerifierAdapter, IHonkVerifier} from "../src/HonkVerifierAdapter.sol";
import {PolicyDomainRegistry} from "../src/PolicyDomainRegistry.sol";
import {IProvableDenial} from "../src/IProvableDenial.sol";
import {Verdict, PolicyKind} from "../src/IConfidentialPolicyVerdict.sol";

/// @notice Closes the confidential (ZK) corner of the DENY board on-chain. Deploys the denial verifier
/// + adapter, registers a denial domain, and anchors a real confidential DENY through the ZK-gated
/// ProvableDenialAnchor — the same anchor whose verifier gate the ALLOW-only circuit could not satisfy.
/// With the denial circuit it now can: a genuine decision=0 UltraHonk proof verifies on-chain and the
/// nullifier is burned against the denial record.
contract CloseConfidentialDenial is Script {
    PolicyDomainRegistry constant REGISTRY =
        PolicyDomainRegistry(0xdf5Bf6C89Fc54F9ea75f2BaE6E33227400A965bd);
    IProvableDenial constant ANCHOR = IProvableDenial(0x053d3570da47A0F767AE8E5AB3CeFe63dfeea511);

    bytes32 constant DENIAL_DOMAIN = bytes32(uint256(42)); // matches the circuit's domain_id public input
    bytes32 constant POLICY_ROOT = 0x053d4542d140ad2350a0ee79fae4a522821274e428bd881e7e803ecd816635ac;
    bytes32 constant COMMIT = 0x7ccb7a4e9d51128b951cbeddefaec1140180a3d13f6eae6f06596dc432057cfa;
    bytes32 constant NULLIFIER = 0x041271fcaf479f6ab927df3a03f74d3809e9f49d880cd7a9595c8dc0a58a5e03;

    function run() external {
        bytes memory proof = vm.readFileBinary("./test/fixtures/deny.proof");

        vm.startBroadcast();
        DenyHonkVerifier honk = new DenyHonkVerifier();
        HonkVerifierAdapter adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)));

        REGISTRY.registerDomain(DENIAL_DOMAIN, msg.sender, address(adapter), bytes32(0), 1 hours);
        REGISTRY.updateRoot(DENIAL_DOMAIN, POLICY_ROOT);

        Verdict memory v = Verdict({
            agentId: 7,
            domainId: DENIAL_DOMAIN,
            policyRoot: POLICY_ROOT,
            actionCommitment: COMMIT,
            executor: address(0xE0),
            expiry: 0,
            nullifier: NULLIFIER,
            decision: 0,
            policyKind: PolicyKind.DENIED
        });
        ANCHOR.anchorDenial(v, proof);
        vm.stopBroadcast();

        console2.log("DenyHonkVerifier", address(honk));
        console2.log("DenyAdapter     ", address(adapter));
        console2.log("isDenied(denialDomain, nullifier)", ANCHOR.isDenied(DENIAL_DOMAIN, NULLIFIER));
    }
}
