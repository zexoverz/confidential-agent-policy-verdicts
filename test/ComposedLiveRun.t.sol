// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ConfidentialPolicyVerdict} from "../src/ConfidentialPolicyVerdict.sol";
import {PolicyDomainRegistry} from "../src/PolicyDomainRegistry.sol";
import {Verdict} from "../src/IConfidentialPolicyVerdict.sol";
import {HonkVerifier} from "../src/verifier/HonkVerifier.sol";
import {HonkVerifierAdapter, IHonkVerifier} from "../src/HonkVerifierAdapter.sol";

/// @notice Minimal view of the ERC-8274 inference-proof verifier (the algorithm layer).
interface IProofVerifier {
    function verify(bytes32 inputHash, bytes32 outputHash, bytes calldata metadata, bytes calldata proof)
        external
        view
        returns (bool);
}

/// @notice The LIVE composed run: a REAL deployed ERC-8274 `IProofVerifier` plus the real CAPV consume,
/// on one flow. Point it at the chain where the 8274 verifier is deployed and it calls the real thing.
///
/// This is the turnkey version for the counterparty (babyblue): fill in four env vars, run one command.
/// If `ERC8274_VERIFIER` is unset the test skips, so the normal suite is unaffected.
///
/// Run it:
///   RPC_URL=<rpc for the chain your verifier is on> \
///   ERC8274_VERIFIER=0x<your deployed IProofVerifier> \
///   INFERENCE_INPUT_HASH=0x<inputHash> INFERENCE_OUTPUT_HASH=0x<outputHash> \
///   INFERENCE_PROOF=0x<proof bytes> INFERENCE_METADATA=0x<metadata bytes, optional> \
///   forge test --match-contract ComposedLiveRun -vvv
contract ComposedLiveRunTest is Test {
    function test_live_erc8274_plus_capv() public {
        address verifierAddr = vm.envOr("ERC8274_VERIFIER", address(0));
        string memory rpc = vm.envOr("RPC_URL", string(""));
        if (verifierAddr == address(0) || bytes(rpc).length == 0) {
            emit log("skip: set ERC8274_VERIFIER + RPC_URL to run the live composed run against a real verifier");
            vm.skip(true);
            return;
        }

        // Fork the chain where the ERC-8274 verifier lives, then call the real deployed verifier.
        vm.createSelectFork(rpc);

        // ---- Layer 1: REAL ERC-8274 verifier attests the inference ----
        IProofVerifier inference = IProofVerifier(verifierAddr);
        bytes32 inputHash = vm.envBytes32("INFERENCE_INPUT_HASH");
        bytes32 outputHash = vm.envBytes32("INFERENCE_OUTPUT_HASH");
        bytes memory metadata = vm.envOr("INFERENCE_METADATA", bytes(""));
        bytes memory proof8274 = vm.envBytes("INFERENCE_PROOF");
        assertTrue(
            inference.verify(inputHash, outputHash, metadata, proof8274),
            "ERC-8274 inference proof must verify on the real deployed verifier"
        );
        emit log("layer 1 ok: ERC-8274 inference verified on the real deployed verifier");

        // ---- Layer 2: real CAPV confidential verdict on the resulting action ----
        // The CAPV side uses the reference witness. To bind the verdict to THIS inference's output,
        // agree on the action bytes and Faisal issues a CAPV proof whose actionCommitment matches;
        // then swap the fixture below for that proof + Verdict. Everything else is unchanged.
        vm.warp(1_700_000_000);
        PolicyDomainRegistry registry = new PolicyDomainRegistry();
        HonkVerifier honk = new HonkVerifier();
        HonkVerifierAdapter adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)));
        ConfidentialPolicyVerdict guard = new ConfidentialPolicyVerdict(registry);

        bytes32 domainId = bytes32(uint256(42));
        bytes32 policyRoot = 0x053d4542d140ad2350a0ee79fae4a522821274e428bd881e7e803ecd816635ac;
        registry.registerDomain(domainId, address(0xA11CE), address(adapter), bytes32(0), 1 hours);
        registry.updateRoot(domainId, policyRoot);

        address executor = address(0xE0);
        Verdict memory v = Verdict({
            agentId: 7,
            domainId: domainId,
            policyRoot: policyRoot,
            actionCommitment: 0x7ccb7a4e9d51128b951cbeddefaec1140180a3d13f6eae6f06596dc432057cfa,
            executor: executor,
            expiry: uint64(block.timestamp + 1 hours),
            nullifier: 0x041271fcaf479f6ab927df3a03f74d3809e9f49d880cd7a9595c8dc0a58a5e03,
            decision: 1
        });
        bytes memory capvProof = vm.readFileBinary("./test/fixtures/allowlist.proof");
        vm.prank(executor);
        guard.consume(v, capvProof);
        assertTrue(guard.isConsumed(domainId, v.nullifier), "CAPV verdict must be consumed");
        emit log("layer 2 ok: CAPV confidential verdict consumed -- both corners met on one live flow");
    }
}
