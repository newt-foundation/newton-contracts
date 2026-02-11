// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "./interfaces/INewtonProverTaskManager.sol";
import {INewtonPolicyClient} from "./interfaces/INewtonPolicyClient.sol";
import {INewtonPolicy} from "./interfaces/INewtonPolicy.sol";
import {TaskManagerStorage} from "./middlewares/TaskManagerStorage.sol";
import {NewtonMessage} from "./core/NewtonMessage.sol";
import {TaskLib} from "./libraries/TaskLib.sol";
import {TaskManagerErrors} from "./libraries/TaskManagerErrors.sol";
import {ITaskResponseHandler} from "./interfaces/ITaskResponseHandler.sol";
import "@openzeppelin-upgrades/contracts/security/ReentrancyGuardUpgradeable.sol";
import "@eigenlayer-middleware/src/libraries/BN254.sol";
import {ChallengeVerifier} from "./middlewares/ChallengeVerifier.sol";
import {AttestationValidator} from "./middlewares/AttestationValidator.sol";
import {IOperatorRegistry} from "./interfaces/IOperatorRegistry.sol";

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
        Task calldata task
    ) external onlyTaskGenerator whenNotPaused {
        require(
            allTaskHashes[task.taskId] == bytes32(0),
            TaskLib.TaskAlreadyExists(allTaskHashes[task.taskId])
        );
        INewtonProverTaskManager.Task memory newTask =
            TaskLib.createTask(task, taskCreationBufferWindow);
        allTaskHashes[newTask.taskId] = TaskLib.taskHash(newTask);

        INewtonPolicy.PolicyState memory state =
            getPolicyState(INewtonPolicyClient(task.policyClient));
        emit NewTaskCreated(newTask.taskId, newTask, state);
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
        require(
            allTaskResponses[taskId] == bytes32(0),
            TaskLib.TaskAlreadyResponded(allTaskResponses[taskId])
        );

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

    function updateTaskCreationBufferWindow(
        uint32 _taskCreationBufferWindow
    ) external onlyOwner {
        taskCreationBufferWindow = _taskCreationBufferWindow;
    }

    /// @notice Update the task response handler contract
    /// @param _taskResponseHandler The new task response handler address
    /// @dev This is needed when SourceTaskResponseHandler code changes since it's not upgradeable
    function updateTaskResponseHandler(
        address _taskResponseHandler
    ) external onlyOwner {
        require(_taskResponseHandler != address(0), TaskManagerErrors.InvalidTaskResponseHandler());
        taskResponseHandler = _taskResponseHandler;
        emit TaskResponseHandlerUpdated(_taskResponseHandler);
    }

    function validateAttestationDirect(
        Task calldata task,
        TaskResponse calldata taskResponse,
        bytes calldata signatureData
    ) external whenNotPaused returns (bool) {
        // Delegate to AttestationValidator with taskResponseHandler for verification:
        // - Source chains: SourceTaskResponseHandler decodes NonSignerStakesAndSignature
        // - Destination chains: DestinationTaskResponseHandler decodes BN254Certificate
        return AttestationValidator(attestationValidator)
            .validateAttestationDirect(task, taskResponse, signatureData, taskResponseHandler);
    }

    function challengeDirectlyVerifiedAttestation(
        Task calldata task,
        TaskResponse calldata taskResponse,
        bytes calldata signatureData
    ) external whenNotPaused {
        ChallengeVerifier(challengeVerifier)
            .challengeDirectlyVerifiedAttestation(
                task, taskResponse, signatureData, taskResponseHandler
            );
    }

    function challengeDirectlyVerifiedMismatch(
        Task calldata task,
        TaskResponse calldata taskResponse,
        bytes calldata signatureData
    ) external whenNotPaused {
        ChallengeVerifier(challengeVerifier)
            .challengeDirectlyVerifiedMismatch(
                task, taskResponse, signatureData, taskResponseHandler
            );
        emit TaskChallengedSuccessfully(taskResponse.taskId, msg.sender);
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

    function getPolicyState(
        INewtonPolicyClient client
    ) internal view returns (INewtonPolicy.PolicyState memory state) {
        address policyAddress = client.getPolicyAddress();
        bytes32 policyId = client.getPolicyId();
        INewtonPolicy.PolicyConfig memory policyConfig =
            INewtonPolicy(policyAddress).getPolicyConfig(policyId);

        state = INewtonPolicy.PolicyState({
            policyAddress: policyAddress, policyId: policyId, policyConfig: policyConfig
        });
    }
}
