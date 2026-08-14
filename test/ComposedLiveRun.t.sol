// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ConfidentialPolicyVerdict} from "../src/ConfidentialPolicyVerdict.sol";
import {PolicyDomainRegistry} from "../src/PolicyDomainRegistry.sol";
import {Verdict, PolicyKind} from "../src/IConfidentialPolicyVerdict.sol";
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

        // ---- Layer 2: real CAPV confidential verdict, bound to the SAME action bytes (t/28083 #150) ----
        (ConfidentialPolicyVerdict guard, bytes32 domainId, Verdict memory v, bytes memory capvProof) =
            _capvLegForBabyblueAction();
        vm.prank(v.executor);
        guard.consume(v, capvProof);
        assertTrue(guard.isConsumed(domainId, v.nullifier), "CAPV verdict must be consumed");
        emit log("layer 2 ok: CAPV confidential verdict consumed -- both corners met on one live flow");
    }

    /// @notice The CAPV leg alone, bound to babyblue's real Sepolia action tuple from t/28083 post #150.
    /// Runs with no env and no fork, so Faisal's side is demonstrably real today: a CAPV proof whose
    /// `actionCommitment` is the canonical commitment over the exact bytes babyblue published (target,
    /// value, calldata, nonce, executor, agentId), consumed on-chain with the nullifier burned. The
    /// ERC-8274 leg above binds to the same bytes once a real verifier address is supplied via env.
    function test_capv_leg_binds_babyblue_action() public {
        (ConfidentialPolicyVerdict guard, bytes32 domainId, Verdict memory v, bytes memory capvProof) =
            _capvLegForBabyblueAction();
        vm.prank(v.executor);
        guard.consume(v, capvProof);
        assertTrue(guard.isConsumed(domainId, v.nullifier), "CAPV verdict for babyblue's action must consume");
    }

    /// @dev Deploys a fresh CAPV stack and registers the composed-run domain with a confidential
    /// allowlist whose single entry is the Multicall3 target. The returned Verdict + proof are bound to
    /// babyblue's fixture: `actionCommitment` = keccak(abi.encode(chainId, domainId, agentId, target,
    /// value, callDataHash, actionNonce)) over the exact tuple; `policyRoot` and `nullifier` are the
    /// circuit outputs for that witness (see noir test_print_witness_composed). The confidential policy
    /// itself (the allowlist) never appears on-chain, only its root.
    function _capvLegForBabyblueAction()
        internal
        returns (ConfidentialPolicyVerdict guard, bytes32 domainId, Verdict memory v, bytes memory capvProof)
    {
        vm.warp(1_700_000_000);
        PolicyDomainRegistry registry = new PolicyDomainRegistry();
        HonkVerifier honk = new HonkVerifier();
        HonkVerifierAdapter adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)));
        guard = new ConfidentialPolicyVerdict(registry);

        // domainId babyblue proposed for the run: keccak256("erc8274-t28083-composed-live-run").
        domainId = 0x16079127bc55bd85d480837115b9bd82d26f03809c0bc4c6c80f7220836afad0;
        bytes32 policyRoot = 0x204a14dc3ab2fdead5450192caea7428c2751b53a95b57d22f93cccb61af19a8;
        registry.registerDomain(domainId, address(0xA11CE), address(adapter), bytes32(0), 1 hours);
        registry.updateRoot(domainId, policyRoot);

        v = Verdict({
            agentId: 54848, // babyblue's real ERC-8004 Identity Registry token id
            domainId: domainId,
            policyRoot: policyRoot,
            actionCommitment: 0x5b5ec31c336cc8f95dc6d9025d1d008c6ed2cd5067b9c421b1d36927e230173a,
            executor: 0x1C213D41668e5bDe79AaEE2240c6f6Ad7b4c9093, // babyblue's real Sepolia key
            expiry: uint64(block.timestamp + 1 hours),
            nullifier: 0x17f36ca085e9f988cc9e033ea510d5b6963265cb99e57e9677b0658531e0315f,
            decision: 1,
            policyKind: PolicyKind.ALLOWED
        });
        capvProof = vm.readFileBinary("./test/fixtures/composed_live.proof");
    }
}
