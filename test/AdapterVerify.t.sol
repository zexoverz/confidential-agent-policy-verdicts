// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {HonkVerifier} from "../src/verifier/HonkVerifier.sol";
import {HonkVerifierAdapter, IHonkVerifier} from "../src/HonkVerifierAdapter.sol";
import {Verdict} from "../src/IConfidentialPolicyVerdict.sol";

/// @notice The full IVerifier path: a Verdict, serialized by the adapter into the circuit's public
/// inputs, verifying the real UltraHonk proof. If this passes, the Guard's `consume` can use the
/// adapter as the domain verifier and the reference impl is no longer mocked end to end.
contract AdapterVerifyTest is Test {
    function test_real_proof_through_iverifier() public {
        HonkVerifier honk = new HonkVerifier();
        HonkVerifierAdapter adapter = new HonkVerifierAdapter(IHonkVerifier(address(honk)));

        // The Verdict for the committed witness (Prover.example.toml). executor/expiry are Guard-only.
        Verdict memory v = Verdict({
            agentId: 7,
            domainId: bytes32(uint256(42)),
            policyRoot: 0x053d4542d140ad2350a0ee79fae4a522821274e428bd881e7e803ecd816635ac,
            actionCommitment: 0x7ccb7a4e9d51128b951cbeddefaec1140180a3d13f6eae6f06596dc432057cfa,
            executor: address(0),
            expiry: 0,
            nullifier: 0x041271fcaf479f6ab927df3a03f74d3809e9f49d880cd7a9595c8dc0a58a5e03,
            decision: 1
        });

        bytes memory proof = vm.readFileBinary("./test/fixtures/allowlist.proof");
        assertTrue(
            adapter.verifyProof(bytes32(0), abi.encode(v), proof), "IVerifier path failed on real proof"
        );
    }
}
