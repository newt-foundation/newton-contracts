// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "./interfaces/INewtonProverTaskManager.sol";
import {TaskManagerStorage} from "./middlewares/TaskManagerStorage.sol";
import {NewtonMessage} from "./core/NewtonMessage.sol";
import {TaskLib} from "./libraries/TaskLib.sol";
import {TaskManagerErrors} from "./libraries/TaskManagerErrors.sol";
import {ITaskResponseHandler} from "./interfaces/ITaskResponseHandler.sol";
import "@openzeppelin-upgrades/contracts/security/ReentrancyGuardUpgradeable.sol";
import "@eigenlayer-middleware/src/libraries/BN254.sol";
import {IBLSSignatureChecker} from "@eigenlayer-middleware/src/interfaces/IBLSSignatureChecker.sol";
import {ChallengeVerifier} from "./middlewares/ChallengeVerifier.sol";
import {AttestationValidator} from "./middlewares/AttestationValidator.sol";
import {IOperatorRegistry} from "./interfaces/IOperatorRegistry.sol";
import {BLSSignatureChecker} from "@eigenlayer-middleware/src/BLSSignatureChecker.sol";

/**
 * @title NewtonProverTaskManagerShared
 * @notice Shared implementation logic for both source and destination TaskManager contracts
 * @dev This abstract contract contains all the shared logic to avoid duplication
 */
abstract contract NewtonProverTaskManagerShared is TaskManagerStorage, ReentrancyGuardUpgradeable {
    /* MODIFIERS */
    // onlyTaskGenerator is used to restrict createNewTask and respondToTask from only being called by a permissioned entity
    // in a real world scenario, this would be removed by instead making createNewTask a payable function
    modifier onlyTaskGenerator() {
        require(
            IOperatorRegistry(operatorRegistry).isTaskGenerator(msg.sender),
            TaskManagerErrors.OnlyTaskGenerator()
        );
        _;
    }

    // onlyAttestationClient is used to restrict validateAttestation from only being called by the correct policy client
    modifier onlyAttestationClient(
        NewtonMessage.Attestation calldata attestation
    ) {
        TaskLib.onlyAttestationClient(attestation);
        _;
    }

    modifier onlyValidTaskResponse(
        Task calldata task,
        TaskResponse calldata taskResponse
    ) {
        TaskLib.sanityCheckTaskResponse(
            task, taskResponse, uint32(block.number), taskResponseWindowBlock
        );
        _;
    }

    function createNewTask(
        INewtonProverTaskManager.Task calldata task
    ) external onlyTaskGenerator whenNotPaused {
        INewtonProverTaskManager.Task memory newTask = TaskLib.createTask(task, nonce);
        allTaskHashes[newTask.taskId] = TaskLib.taskHash(newTask);
        emit NewTaskCreated(newTask.taskId, newTask);
        unchecked {
            ++nonce;
        }
    }

    function respondToTask(
        Task calldata task,
        TaskResponse calldata taskResponse,
        bytes calldata signatureData
    ) external onlyTaskGenerator onlyValidTaskResponse(task, taskResponse) whenNotPaused {
        bytes32 taskId = taskResponse.taskId;
        require(
            TaskLib.taskHash(task) == allTaskHashes[taskId],
            TaskLib.TaskMismatch(allTaskHashes[taskId], TaskLib.taskHash(task))
        );
        require(allTaskResponses[taskId] == bytes32(0), TaskLib.TaskAlreadyResponded());

        // Validate policyTaskData from TaskResponse (moved from createTask)
        // Operators generate policyTaskData independently; this validates the aggregated result
        TaskLib.validateTaskResponsePolicyData(taskResponse);

        // Delegate verification to task response handler
        bytes32 hashOfNonSigners = ITaskResponseHandler(taskResponseHandler)
            .verifyTaskResponse(task, taskResponse, signatureData);

        uint32 referenceBlock = uint32(block.number);
        // Use taskResponse.policyConfig (from operator-generated data) instead of task.policyConfig
        uint32 responseExpireBlock = referenceBlock + taskResponse.policyConfig.expireAfter;
        ResponseCertificate memory responseCertificate = ResponseCertificate(
            referenceBlock, responseExpireBlock, hashOfNonSigners, signatureData
        );
        bytes32 responseHash = keccak256(abi.encode(taskResponse, responseCertificate));
        allTaskResponses[taskId] = responseHash;
        ChallengeVerifier(challengeVerifier)
            .setTaskHashesAndResponses(taskId, allTaskHashes[taskId], responseHash);
        if (TaskLib.evaluateResult(taskResponse.evaluationResult)) {
            AttestationValidator(attestationValidator)
                .createAttestationHash(
                    taskId,
                    taskResponse.policyId,
                    taskResponse.policyClient,
                    taskResponse.intent,
                    taskResponse.intentSignature,
                    responseExpireBlock
                );
        }
        emit TaskResponded(taskResponse, responseCertificate);
    }

    function raiseAndResolveChallenge(
        Task calldata task,
        TaskResponse calldata taskResponse,
        ResponseCertificate calldata responseCertificate,
        ChallengeData calldata challenge,
        BN254.G1Point[] memory pubkeysOfNonSigningOperators
    ) external whenNotPaused {
        bool isChallengeResolved = ChallengeVerifier(challengeVerifier)
            .raiseAndResolveChallenge(
                task, taskResponse, responseCertificate, challenge, pubkeysOfNonSigningOperators
            );
        bytes32 taskId = taskResponse.taskId;
        if (isChallengeResolved) {
            // Challenged attestation is now invalid
            AttestationValidator(attestationValidator).invalidateAttestation(taskId);
            emit TaskChallengedSuccessfully(taskId, msg.sender);
        } else {
            emit TaskChallengedUnsuccessfully(taskId, msg.sender);
        }
    }

    function validateAttestation(
        NewtonMessage.Attestation calldata attestation
    ) external onlyAttestationClient(attestation) whenNotPaused returns (bool) {
        if (ChallengeVerifier(challengeVerifier).isTaskChallenged(attestation.taskId)) {
            return false;
        }
        bool isAttestationValid =
            AttestationValidator(attestationValidator).validateAttestation(attestation);
        if (isAttestationValid) {
            emit AttestationSpent(attestation.taskId, attestation);
        }
        return isAttestationValid;
    }

    function updateTaskResponseWindowBlock(
        uint32 _taskResponseWindowBlock
    ) external onlyOwner {
        taskResponseWindowBlock = _taskResponseWindowBlock;
    }

    function updateEpochBlocks(
        uint32 _epochBlocks
    ) external onlyOwner {
        epochBlocks = _epochBlocks;
    }

    function validateAttestationDirect(
        Task calldata task,
        TaskResponse calldata taskResponse,
        IBLSSignatureChecker.NonSignerStakesAndSignature calldata nonSignerStakesAndSignature
    ) external onlySourceChain whenNotPaused returns (bool) {
        // Delegate to AttestationValidator with checkSignatures function pointer from BLSSignatureChecker
        // On source chains, this contract (via SourceTaskManagerStorage) extends BLSSignatureChecker
        // Cast this to BLSSignatureChecker to access checkSignatures function
        BLSSignatureChecker blsChecker = BLSSignatureChecker(address(this));
        return AttestationValidator(attestationValidator)
            .validateAttestationDirect(
                task, taskResponse, nonSignerStakesAndSignature, blsChecker.checkSignatures
            );
    }

    function challengeDirectlyVerifiedAttestation(
        Task calldata task,
        TaskResponse calldata taskResponse,
        IBLSSignatureChecker.NonSignerStakesAndSignature calldata nonSignerStakesAndSignature
    ) external onlySourceChain whenNotPaused {
        // Delegate to ChallengeVerifier with checkSignatures function pointer from BLSSignatureChecker
        // On source chains, this contract (via SourceTaskManagerStorage) extends BLSSignatureChecker
        // Cast this to BLSSignatureChecker to access checkSignatures function
        BLSSignatureChecker blsChecker = BLSSignatureChecker(address(this));
        ChallengeVerifier(challengeVerifier)
            .challengeDirectlyVerifiedAttestation(
                task, taskResponse, nonSignerStakesAndSignature, blsChecker.checkSignatures
            );
    }

    // Wrapper functions to match interface naming (delegate to storage mappings)
    function taskHash(
        bytes32 taskId
    ) external view returns (bytes32) {
        return allTaskHashes[taskId];
    }

    function taskResponseHash(
        bytes32 taskId
    ) external view returns (bytes32) {
        return allTaskResponses[taskId];
    }
}

