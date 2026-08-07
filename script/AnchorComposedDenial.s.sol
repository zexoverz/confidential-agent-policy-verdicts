// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {TransparentDenialAnchor} from "../src/TransparentDenialAnchor.sol";
import {Verdict} from "../src/IConfidentialPolicyVerdict.sol";
import {PolicyAction} from "../src/PolicyAction.sol";

/// @notice Deploys the transparent denial anchor and anchors the composed-run action as a DENY, using
/// babyblue's canonical tuple from t/28083 #150 (the same actionCommitment every other leg binds to).
/// This lights up the positive corner of the recompute-denial leg: isDenied(domainId, nullifier) is
/// now true on-chain and publicly recomputable, closing the DENY board through the transparent corner.
contract AnchorComposedDenial is Script {
    bytes32 constant DOMAIN_ID = 0x16079127bc55bd85d480837115b9bd82d26f03809c0bc4c6c80f7220836afad0;
    bytes32 constant POLICY_ROOT = 0x204a14dc3ab2fdead5450192caea7428c2751b53a95b57d22f93cccb61af19a8;
    bytes32 constant ACTION_COMMITMENT = 0x5b5ec31c336cc8f95dc6d9025d1d008c6ed2cd5067b9c421b1d36927e230173a;
    bytes32 constant NULLIFIER = 0x17f36ca085e9f988cc9e033ea510d5b6963265cb99e57e9677b0658531e0315f;
    address constant EXECUTOR = 0x1C213D41668e5bDe79AaEE2240c6f6Ad7b4c9093;
    address constant TARGET = 0xcA11bde05977b3631167028862bE2a173976CA11; // Multicall3
    bytes32 constant CALLDATA_HASH = 0xcfacbfe211cf3be67a1d64a6499a2af0ae475e2c0965c2a42f969d243df2b6cd;

    function run() external {
        vm.startBroadcast();
        TransparentDenialAnchor anchor = new TransparentDenialAnchor();

        Verdict memory v = Verdict({
            agentId: 54848,
            domainId: DOMAIN_ID,
            policyRoot: POLICY_ROOT,
            actionCommitment: ACTION_COMMITMENT,
            executor: EXECUTOR,
            expiry: 1_700_003_600,
            nullifier: NULLIFIER,
            decision: 0
        });
        PolicyAction memory a = PolicyAction({
            chainId: 11155111,
            domainId: DOMAIN_ID,
            agentId: 54848,
            target: TARGET,
            value: 0,
            callDataHash: CALLDATA_HASH,
            actionNonce: 5
        });

        anchor.anchorDenial(v, abi.encode(a));
        vm.stopBroadcast();

        bool denied = anchor.isDenied(DOMAIN_ID, NULLIFIER);
        console2.log("TransparentDenialAnchor", address(anchor));
        console2.log("isDenied(domain,nullifier)", denied);
    }
}
