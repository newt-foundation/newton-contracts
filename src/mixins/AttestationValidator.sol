// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {NewtonMessage} from "../core/NewtonMessage.sol";
import {TaskLib} from "../libraries/TaskLib.sol";
import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";

contract AttestationValidator is Initializable, OwnableUpgradeable {
    /* CUSTOM ERRORS */
    error AttestationHashMismatch();
    error AttestationExpired();
    error AttestationAlreadySpent();
    error OnlyTaskManager();

    /* STORAGE */
    address public immutable taskManager;
    mapping(bytes32 => bytes32) public attestations;

    /* MODIFIERS */
    modifier onlyTaskManager() {
        require(msg.sender == taskManager, OnlyTaskManager());
        _;
    }

    /* CONSTRUCTOR */
    constructor(
        address _taskManager
    ) {
        taskManager = _taskManager;
    }

    /* INITIALIZER */
    function initialize(
        address _owner
    ) public initializer {
        __Ownable_init();
        _transferOwnership(_owner);
    }

    /* EXTERNAL FUNCTIONS */
    function validateAttestation(
        NewtonMessage.Attestation calldata attestation
    ) external onlyTaskManager returns (bool) {
        TaskLib.sanityCheckAttestation(attestation);
        bytes32 attestationHash = keccak256(abi.encode(attestation));
        require(attestations[attestation.taskId] == attestationHash, AttestationHashMismatch());
        require(uint32(block.number) <= attestation.expiration, AttestationExpired());
        // Prevent double spending of the same attestation by setting the attestation hash to 0
        require(attestations[attestation.taskId] != bytes32(0), AttestationAlreadySpent());
        attestations[attestation.taskId] = bytes32(0);
        return true;
    }

    function invalidateAttestation(
        bytes32 taskId
    ) external onlyTaskManager {
        attestations[taskId] = bytes32(0);
    }

    function createAttestationHash(
        bytes32 taskId,
        bytes32 policyId,
        address policyClient,
        NewtonMessage.Intent calldata intent,
        uint32 expiration
    ) external onlyTaskManager returns (bytes32) {
        NewtonMessage.Attestation memory attestation =
            NewtonMessage.Attestation(taskId, policyId, policyClient, intent, expiration);
        bytes32 attestationHash = keccak256(abi.encode(attestation));
        attestations[taskId] = attestationHash;
        return attestationHash;
    }

    function isAttestationValid(
        NewtonMessage.Attestation calldata attestation
    ) external view returns (bool) {
        TaskLib.sanityCheckAttestation(attestation);
        bytes32 attestationHash = keccak256(abi.encode(attestation));
        return attestations[attestation.taskId] == attestationHash
            && uint32(block.number) <= attestation.expiration
            && attestations[attestation.taskId] != bytes32(0);
    }

    function getAttestationHash(
        bytes32 taskId
    ) external view returns (bytes32) {
        return attestations[taskId];
    }
}
