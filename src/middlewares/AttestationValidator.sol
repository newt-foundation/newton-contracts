// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";
import {TaskLib} from "../libraries/TaskLib.sol";
import {OperatorVerifierLib} from "../libraries/OperatorVerifierLib.sol";
import {
    ISlashingRegistryCoordinator
} from "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {IBLSSignatureChecker} from "@eigenlayer-middleware/src/interfaces/IBLSSignatureChecker.sol";
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
    address public immutable operatorRegistry;
    mapping(bytes32 => bytes32) public attestations;
    mapping(bytes32 => bool) public directlyVerifiedAttestations;
    mapping(bytes32 => uint32) public attestationExpirations;

    /* MODIFIERS */
    modifier onlyTaskManager() {
        require(msg.sender == taskManager, OnlyTaskManager());
        _;
    }

    /* CONSTRUCTOR */
    constructor(
        address _taskManager,
        address _operatorRegistry
    ) {
        taskManager = _taskManager;
        operatorRegistry = _operatorRegistry;
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
        bytes32 hash = keccak256(abi.encode(attestation));
        require(attestations[attestation.taskId] == hash, AttestationHashMismatch());
        require(uint32(block.number) < attestation.expiration, AttestationExpired());
        // Prevent double spending of the same attestation by setting the attestation hash to 0
        require(attestations[attestation.taskId] != bytes32(0), AttestationAlreadySpent());
        attestations[attestation.taskId] = bytes32(0);
        attestationExpirations[attestation.taskId] = 0;
        return true;
    }

    function invalidateAttestation(
        bytes32 taskId
    ) external onlyTaskManager {
        attestations[taskId] = bytes32(0);
        attestationExpirations[taskId] = 0;
    }

    function createAttestationHash(
        bytes32 taskId,
        bytes32 policyId,
        address policyClient,
        NewtonMessage.Intent calldata intent,
        bytes calldata intentSignature,
        uint32 expiration
    ) external onlyTaskManager returns (bytes32) {
        NewtonMessage.Attestation memory attestation = NewtonMessage.Attestation(
            taskId, policyId, policyClient, expiration, intent, intentSignature
        );
        bytes32 hash = keccak256(abi.encode(attestation));
        attestations[taskId] = hash;
        attestationExpirations[taskId] = expiration;
        return hash;
    }

    function isAttestationValid(
        NewtonMessage.Attestation calldata attestation
    ) external view returns (bool) {
        TaskLib.sanityCheckAttestation(attestation);
        bytes32 hash = keccak256(abi.encode(attestation));
        return attestations[attestation.taskId] == hash
            && uint32(block.number) < attestation.expiration
            && attestations[attestation.taskId] != bytes32(0);
    }

    function attestationHash(
        bytes32 taskId
    ) external view returns (bytes32) {
        return attestations[taskId];
    }

    function markDirectlyVerified(
        bytes32 taskId
    ) external onlyTaskManager {
        directlyVerifiedAttestations[taskId] = true;
    }

    function isDirectlyVerified(
        bytes32 taskId
    ) external view returns (bool) {
        return directlyVerifiedAttestations[taskId];
    }

    function validateAttestationDirect(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        IBLSSignatureChecker.NonSignerStakesAndSignature calldata nonSignerStakesAndSignature,
        function(bytes32, bytes memory, uint32, IBLSSignatureChecker
                        .NonSignerStakesAndSignature memory)
            external
            view returns (IBLSSignatureChecker.QuorumStakeTotals memory, bytes32) checkSignatures
    ) external onlyTaskManager returns (bool) {
        bytes32 taskId = taskResponse.taskId;

        // Verify task hash matches the one stored in TaskManager
        bytes32 expectedTaskHash = INewtonProverTaskManager(taskManager).taskHash(taskId);
        require(
            TaskLib.taskHash(task) == expectedTaskHash,
            TaskLib.TaskMismatch(expectedTaskHash, TaskLib.taskHash(task))
        );

        // Check if attestation already exists from regular flow (respondToTask was called)
        // If it exists, validate it using the existing attestation instead of direct validation flow
        bytes32 existingAttestationHash = attestations[taskId];
        if (existingAttestationHash != bytes32(0)) {
            // Attestation already exists from respondToTask
            // Use the stored expiration (which was referenceBlock + task.policyConfig.expireAfter from respondToTask)
            uint32 storedExpiration = attestationExpirations[taskId];
            require(storedExpiration != 0, "Attestation expiration not found");

            // Construct attestation using the stored expiration to match the hash
            // Use taskResponse.policyId (policyId is now in TaskResponse, generated by operators)
            NewtonMessage.Attestation memory constructedAttestation = NewtonMessage.Attestation(
                taskId,
                taskResponse.policyId,
                task.policyClient,
                storedExpiration,
                task.intent,
                task.intentSignature
            );

            // Verify only the attestation client can call this
            TaskLib.onlyAttestationClient(constructedAttestation);

            // Validate the existing attestation (this will mark it as spent)
            return this.validateAttestation(constructedAttestation);
        }

        // Direct validation flow: attestation doesn't exist yet
        // Verify BLS signatures
        OperatorVerifierLib.verifyTaskResponseSignatures(
            task,
            taskResponse,
            nonSignerStakesAndSignature,
            ISlashingRegistryCoordinator(operatorRegistry),
            checkSignatures
        );

        // Check evaluation result is true
        require(TaskLib.evaluateResult(taskResponse.evaluationResult), TaskLib.PolicyNotVerified());

        // Use referenceBlock + taskResponse.policyConfig.expireAfter for expiration
        // (policyConfig is now in TaskResponse, generated by operators)
        uint32 referenceBlock = uint32(block.number);
        uint32 expiration = referenceBlock + taskResponse.policyConfig.expireAfter;

        // Construct attestation to check onlyAttestationClient
        // Use taskResponse.policyId (policyId is now in TaskResponse, generated by operators)
        NewtonMessage.Attestation memory attestationToCheck = NewtonMessage.Attestation(
            taskId,
            taskResponse.policyId,
            task.policyClient,
            expiration,
            task.intent,
            task.intentSignature
        );

        // Verify only the attestation client can call this
        TaskLib.onlyAttestationClient(attestationToCheck);

        // Create attestation hash
        NewtonMessage.Attestation memory attestationForHash = NewtonMessage.Attestation(
            taskId,
            taskResponse.policyId,
            task.policyClient,
            expiration,
            task.intent,
            task.intentSignature
        );
        bytes32 hash = keccak256(abi.encode(attestationForHash));
        attestations[taskId] = hash;
        attestationExpirations[taskId] = expiration;

        // Mark as directly verified
        directlyVerifiedAttestations[taskId] = true;

        // Immediately validate (mark as spent)
        TaskLib.sanityCheckAttestation(attestationToCheck);
        require(attestations[taskId] == hash, AttestationHashMismatch());
        require(uint32(block.number) < attestationToCheck.expiration, AttestationExpired());
        require(attestations[taskId] != bytes32(0), AttestationAlreadySpent());
        attestations[taskId] = bytes32(0);

        return true;
    }
}
