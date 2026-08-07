// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {ProvableDenialAnchor} from "../src/ProvableDenialAnchor.sol";
import {IPolicyDomainRegistry} from "../src/IPolicyDomainRegistry.sol";

/// @notice Deploys the ProvableDenialAnchor against the already-deployed composed-run registry, giving
/// the DENY board a live, recompute-verifiable anchor so the recompute-denial leg can bind to one
/// address and close the second three-way run through the same ERC-8274 boundary as the ALLOW side.
contract DeployDenialAnchor is Script {
    IPolicyDomainRegistry constant REGISTRY =
        IPolicyDomainRegistry(0xdf5Bf6C89Fc54F9ea75f2BaE6E33227400A965bd);

    function run() external {
        vm.startBroadcast();
        ProvableDenialAnchor anchor = new ProvableDenialAnchor(REGISTRY);
        vm.stopBroadcast();
        console2.log("ProvableDenialAnchor", address(anchor));
        console2.log("registry            ", address(REGISTRY));
    }
}
