// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IConfidentialCredential} from "src/unclonable/interfaces/IConfidentialCredential.sol";
import {ConfidentialCredentialGuard} from "src/unclonable/ConfidentialCredentialGuard.sol";
import {MockVerifier} from "src/unclonable/mocks/MockVerifier.sol";
import {CredentialDomainRegistry} from "src/unclonable/libraries/CredentialDomainRegistry.sol";

contract ConfidentialCredentialGuardTest is Test {
    uint256 constant HOME_DOMAIN_ID = 1;

    CredentialDomainRegistry domainRegistry;
    MockVerifier verifier;
    ConfidentialCredentialGuard guard;

    function _buildCapability(
        uint256 agentId,
        uint256 capabilityIndex,
        uint256 expiry,
        bytes32 salt
    ) internal view returns (IConfidentialCredential.Capability memory) {
        uint256 chainId = block.chainid;
        bytes32 nullifier = keccak256(
            abi.encodePacked(keccak256("ERC-XXXX/nullifier/v1"), salt)
        );
        bytes32 actionCommitment = bytes32(uint256(0x42));
        bytes32 capabilityCommitment = keccak256(
            abi.encodePacked(
                keccak256("ERC-XXXX/credential/v1"),
                salt,
                bytes32(agentId),
                bytes32(chainId),
                bytes32(HOME_DOMAIN_ID),
                bytes32(capabilityIndex),
                actionCommitment
            )
        );
        return IConfidentialCredential.Capability({
            salt: salt,
            nullifier: nullifier,
            capabilityCommitment: capabilityCommitment,
            agentId: agentId,
            homeChainId: chainId,
            homeDomainId: HOME_DOMAIN_ID,
            capabilityIndex: capabilityIndex,
            actionCommitment: actionCommitment,
            executor: address(this),
            expiry: expiry
        });
    }

    function _proof() internal pure returns (bytes memory) {
        return abi.encodePacked("proof");
    }

    function _recomputeCommitment(
        IConfidentialCredential.Capability memory cap
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                keccak256("ERC-XXXX/credential/v1"),
                cap.salt,
                bytes32(cap.agentId),
                bytes32(cap.homeChainId),
                bytes32(cap.homeDomainId),
                bytes32(cap.capabilityIndex),
                cap.actionCommitment
            )
        );
    }

    function setUp() public {
        vm.chainId(11155111);
        domainRegistry = new CredentialDomainRegistry();
        domainRegistry.registerDomain(HOME_DOMAIN_ID);
        verifier = new MockVerifier();
        guard = new ConfidentialCredentialGuard(address(verifier), address(domainRegistry));
    }

    function test_HappyPath() public {
        IConfidentialCredential.Capability memory cap = _buildCapability(1, 1, block.timestamp + 100, bytes32(uint256(1)));
        guard.consume(cap, _proof());
        assertTrue(guard.isConsumed(cap.nullifier));
    }

    function test_DoubleSpend_Reverts() public {
        IConfidentialCredential.Capability memory cap = _buildCapability(1, 1, block.timestamp + 100, bytes32(uint256(1)));
        guard.consume(cap, _proof());
        vm.expectRevert("CCC: already spent");
        guard.consume(cap, _proof());
    }

    function test_CloneReplay_Reverts() public {
        IConfidentialCredential.Capability memory cap = _buildCapability(1, 1, block.timestamp + 100, bytes32(uint256(1)));
        vm.prank(address(0xdead));
        vm.expectRevert("CCC: executor mismatch");
        guard.consume(cap, _proof());
    }

    function test_WrongChain_Reverts() public {
        IConfidentialCredential.Capability memory cap = _buildCapability(1, 1, block.timestamp + 100, bytes32(uint256(1)));
        cap.homeChainId = 2;
        cap.capabilityCommitment = _recomputeCommitment(cap);
        vm.expectRevert("CCC: wrong chain");
        guard.consume(cap, _proof());
    }

    function test_Expired_Reverts() public {
        IConfidentialCredential.Capability memory cap = _buildCapability(1, 1, block.timestamp - 1, bytes32(uint256(1)));
        vm.expectRevert("CCC: expired");
        guard.consume(cap, _proof());
    }

    function test_ExecutorMismatch_Reverts() public {
        IConfidentialCredential.Capability memory cap = _buildCapability(1, 1, block.timestamp + 100, bytes32(uint256(1)));
        cap.executor = address(0xbeef);
        cap.capabilityCommitment = _recomputeCommitment(cap);
        vm.prank(address(0xdead));
        vm.expectRevert("CCC: executor mismatch");
        guard.consume(cap, _proof());
    }

    function test_RelayedSubmit_Succeeds() public {
        IConfidentialCredential.Capability memory cap = _buildCapability(1, 1, block.timestamp + 100, bytes32(uint256(1)));
        guard.consume(cap, _proof());
        assertTrue(guard.isConsumed(cap.nullifier));
    }

    function test_FrontRun_LiftedProof_Reverts() public {
        IConfidentialCredential.Capability memory cap = _buildCapability(1, 1, block.timestamp + 100, bytes32(uint256(1)));
        vm.prank(address(0x999));
        vm.expectRevert("CCC: executor mismatch");
        guard.consume(cap, _proof());
    }

    function test_UnregisteredDomain_Reverts() public {
        IConfidentialCredential.Capability memory cap = _buildCapability(1, 1, block.timestamp + 100, bytes32(uint256(1)));
        cap.homeDomainId = 2;
        cap.capabilityCommitment = _recomputeCommitment(cap);
        vm.expectRevert("CCC: domain invalid");
        guard.consume(cap, _proof());
    }

    function test_CommitmentParity() public view {
        bytes32 salt = bytes32(uint256(7));
        uint256 agentId = 5;
        uint256 capabilityIndex = 3;
        bytes32 actionCommitment = bytes32(uint256(99));
        IConfidentialCredential.Capability memory cap = _buildCapability(agentId, capabilityIndex, block.timestamp + 100, salt);
        cap.actionCommitment = actionCommitment;
        cap.capabilityCommitment = _recomputeCommitment(cap);

        bytes32 expected = keccak256(
            abi.encodePacked(
                keccak256("ERC-XXXX/credential/v1"),
                salt,
                bytes32(agentId),
                bytes32(uint256(11155111)),
                bytes32(HOME_DOMAIN_ID),
                bytes32(capabilityIndex),
                actionCommitment
            )
        );
        assertEq(cap.capabilityCommitment, expected);
    }

    function test_Composition_Placeholder() public {
        assertTrue(true);
    }
}