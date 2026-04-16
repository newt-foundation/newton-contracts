// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";
import {INewtonPolicyClient} from "../interfaces/INewtonPolicyClient.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";
import {TaskLib} from "../libraries/TaskLib.sol";
import {ITaskResponseHandler} from "../interfaces/ITaskResponseHandler.sol";
import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";

contract AttestationValidator is Initializable, OwnableUpgradeable {
    /* CUSTOM ERRORS */
    error AttestationHashMismatch();
    error AttestationExpired();
    error AttestationAlreadySpent();
    error OnlyTaskManager();

    /* CONSTANTS */
    /// @notice Sentinel value indicating an attestation has been spent
    /// @dev Uses max uint32 as sentinel since valid expirations are always < current block + reasonable expireAfter
    uint32 public constant ATTESTATION_SPENT_SENTINEL = type(uint32).max;

    /* STORAGE */
    address public immutable taskManager;
    address public immutable operatorRegistry;
    mapping(bytes32 => bytes32) public attestations;
    mapping(bytes32 => bool) public directlyVerifiedAttestations;
    /// @notice Tracks attestation expirations. Values:
    /// - 0: never created
    /// - ATTESTATION_SPENT_SENTINEL: spent (via validateAttestation or validateAttestationDirect)
    /// - other: valid expiration block
    mapping(bytes32 => uint32) public attestationExpirations;
    /// @dev New mappings appended after existing storage to preserve upgrade safety
    mapping(bytes32 => bytes32) public directTaskHashes;
    mapping(bytes32 => bytes32) public directTaskResponseHashes;

    uint256[45] private __gap;

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
    // IMPORTANT: must be kept in sync with isAttestationValid
    function validateAttestation(
        address caller,
        NewtonMessage.Attestation calldata attestation
    ) external onlyTaskManager returns (bool) {
        TaskLib.onlyAttestationClient(caller, attestation);

        return _validateAttestation(attestation);
    }

    /* INTERNAL FUNCTIONS */
    function _validateAttestation(
        NewtonMessage.Attestation memory attestation
    ) internal returns (bool) {
        TaskLib.sanityCheckAttestation(attestation);
        // Prevent double spending (covers both regular and direct validation flows)
        require(
            attestationExpirations[attestation.taskId] != ATTESTATION_SPENT_SENTINEL,
            AttestationAlreadySpent()
        );
        bytes32 hash = keccak256(abi.encode(attestation));
        require(attestations[attestation.taskId] == hash, AttestationHashMismatch());
        require(uint32(block.number) < attestation.expiration, AttestationExpired());
        // Clear hash for gas refund and mark as spent via sentinel
        attestations[attestation.taskId] = bytes32(0);
        attestationExpirations[attestation.taskId] = ATTESTATION_SPENT_SENTINEL;
        return true;
    }

    function invalidateAttestation(
        bytes32 taskId
    ) external onlyTaskManager {
        attestations[taskId] = bytes32(0);
        // Use sentinel to prevent any future validation of this taskId
        attestationExpirations[taskId] = ATTESTATION_SPENT_SENTINEL;
        // Clear direct verification state to prevent repeated challenge via
        // challengeDirectlyVerifiedMismatch (isDirectlyVerified must return false)
        directlyVerifiedAttestations[taskId] = false;
    }

    function createAttestationHash(
        bytes32 taskId,
        bytes32 policyId,
        address policyClient,
        NewtonMessage.Intent calldata intent,
        bytes calldata intentSignature,
        uint32 expiration
    ) external onlyTaskManager returns (bytes32) {
        // If attestation already spent (e.g., via validateAttestationDirect),
        // preserve spent state to avoid overwriting the sentinel
        if (attestationExpirations[taskId] == ATTESTATION_SPENT_SENTINEL) {
            return bytes32(0);
        }
        // Prevent expiration from colliding with the spent sentinel value,
        // which would make the attestation permanently unspendable
        require(expiration != ATTESTATION_SPENT_SENTINEL, AttestationExpired());
        NewtonMessage.Attestation memory attestation = NewtonMessage.Attestation(
            taskId, policyId, policyClient, expiration, intent, intentSignature
        );
        bytes32 hash = keccak256(abi.encode(attestation));
        attestations[taskId] = hash;
        attestationExpirations[taskId] = expiration;
        return hash;
    }

    // IMPORTANT: must be kept in sync with validateAttestation
    function isAttestationValid(
        address client,
        NewtonMessage.Attestation memory attestation
    ) public view returns (bool) {
        TaskLib.onlyAttestationClient(client, attestation);

        bytes32 stored = attestations[attestation.taskId];
        if (stored == bytes32(0)) return false;
        bytes32 hash = keccak256(abi.encode(attestation));
        if (stored != hash) return false;
        uint32 exp = attestationExpirations[attestation.taskId];
        if (exp == 0 || exp == ATTESTATION_SPENT_SENTINEL || uint32(block.number) >= exp) {
            return false;
        }
        TaskLib.sanityCheckAttestation(attestation);
        return true;
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

    // solhint-disable-next-line function-max-lines
    // IMPORTANT: must be kept in sync with isAttestationDirectValid
    function validateAttestationDirect(
        address caller,
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        bytes calldata signatureData
    ) external onlyTaskManager returns (bool) {
        // Only the correct policy client may directly validate and spend the attestation
        require(
            caller == task.policyClient && caller == taskResponse.policyClient,
            TaskLib.InvalidPolicyClient()
        );
        require(
            INewtonPolicyClient(caller).getPolicyId() == taskResponse.policyId,
            TaskLib.InvalidPolicyId()
        );
        // Verify the policy contract hasn't been revoked or deactivated.
        // The respondToTask path checks this via validateTaskResponsePolicyData;
        // the direct path must check independently since respondToTask may not have run yet.
        require(
            INewtonPolicy(taskResponse.policyAddress).isPolicyVerified(),
            TaskLib.PolicyNotVerified()
        );

        bytes32 taskId = taskResponse.taskId;
        address taskResponseHandler = INewtonProverTaskManager(taskManager).taskResponseHandler();

        // If attestation already exists from regular flow, validate using it instead
        bytes32 existingAttestationHash = attestations[taskId];
        if (existingAttestationHash != bytes32(0)) {
            bytes32 expectedTaskHash = INewtonProverTaskManager(taskManager).taskHash(taskId);
            require(
                TaskLib.taskHash(task) == expectedTaskHash,
                TaskLib.TaskMismatch(expectedTaskHash, TaskLib.taskHash(task))
            );

            // Bind taskResponse to the stored normalized response hash to prevent
            // poisoning of directTaskResponseHashes from caller-supplied input
            bytes32 storedNormalizedResponseHash =
                INewtonProverTaskManager(taskManager).normalizedTaskResponseHash(taskId);
            require(
                storedNormalizedResponseHash != bytes32(0)
                    && keccak256(abi.encode(taskResponse)) == storedNormalizedResponseHash,
                TaskLib.TaskResponseMismatch()
            );

            // Stored expiration was set as referenceBlock + expireAfter during respondToTask
            uint32 storedExpiration = attestationExpirations[taskId];
            require(storedExpiration != 0, "Attestation expiration not found");

            // policyId comes from TaskResponse (generated by operators)
            NewtonMessage.Attestation memory constructedAttestation = NewtonMessage.Attestation(
                taskId,
                taskResponse.policyId,
                task.policyClient,
                storedExpiration,
                task.intent,
                task.intentSignature
            );
            bool result = _validateAttestation(constructedAttestation); // marks as spent

            // Set direct verification state so callers see consistent results
            // regardless of whether the regular flow had already created an attestation
            directlyVerifiedAttestations[taskId] = true;
            directTaskHashes[taskId] = expectedTaskHash;
            directTaskResponseHashes[taskId] = storedNormalizedResponseHash;
            emit INewtonProverTaskManager.DirectTaskResponded(taskId, task, taskResponse);

            return result;
        }

        // Optimistic fast path: validate via task response handler before on-chain task exists
        // Delegates to SourceTaskResponseHandler (BLS) or DestinationTaskResponseHandler (certificate)
        // Prevent double spending across both regular and direct flows
        require(
            attestationExpirations[taskId] != ATTESTATION_SPENT_SENTINEL, AttestationAlreadySpent()
        );

        // Bind every Task field that overlaps with TaskResponse to prevent a malicious
        // policy client from committing a crafted task hash that diverges from the signed
        // response. BLS consensus digest covers only `taskResponse` (see TaskLib.
        // computeConsensusDigest), so task-only fields (taskCreatedBlock, wasmArgs,
        // quorumNumbers, quorumThresholdPercentage) remain caller-controlled in this
        // optimistic branch — they only affect directTaskHashes dedup, not slashing.
        require(task.taskId == taskResponse.taskId, TaskLib.InvalidTaskId());
        require(task.policyClient == taskResponse.policyClient, TaskLib.InvalidPolicyClient());
        require(
            keccak256(abi.encode(task.intent)) == keccak256(abi.encode(taskResponse.intent)),
            TaskLib.TaskResponseMismatch()
        );
        require(
            keccak256(task.intentSignature) == keccak256(taskResponse.intentSignature),
            TaskLib.TaskResponseMismatch()
        );
        require(
            task.initializationTimestamp == taskResponse.initializationTimestamp,
            TaskLib.TaskResponseMismatch()
        );

        ITaskResponseHandler(taskResponseHandler)
            .verifyTaskResponse(task, taskResponse, signatureData);

        uint32 referenceBlock = uint32(block.number);
        uint32 expiration = referenceBlock + taskResponse.policyConfig.expireAfter;

        NewtonMessage.Attestation memory attestationForHash = NewtonMessage.Attestation(
            taskId,
            taskResponse.policyId,
            task.policyClient,
            expiration,
            task.intent,
            task.intentSignature
        );

        TaskLib.sanityCheckAttestation(attestationForHash);
        require(uint32(block.number) < expiration, AttestationExpired());

        // Mark as spent regardless of evaluation result to prevent replay
        directlyVerifiedAttestations[taskId] = true;
        attestationExpirations[taskId] = ATTESTATION_SPENT_SENTINEL;

        // Store hashes for challenger to compare against regular path later
        directTaskHashes[taskId] = TaskLib.taskHash(task);
        directTaskResponseHashes[taskId] = keccak256(abi.encode(taskResponse));
        emit INewtonProverTaskManager.DirectTaskResponded(taskId, task, taskResponse);

        // Revert = invalid attestation; return value = policy decision
        return TaskLib.evaluateResult(taskResponse.evaluationResult);
    }

    // IMPORTANT: must be kept in sync with validateAttestationDirect
    function isAttestationDirectValid(
        address client,
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        bytes calldata signatureData
    ) public view returns (bool) {
        // Only the correct policy client may directly validate and spend the attestation
        if (client != task.policyClient || client != taskResponse.policyClient) {
            return false;
        }
        if (INewtonPolicyClient(client).getPolicyId() != taskResponse.policyId) return false;

        // Verify the policy contract hasn't been revoked or deactivated.
        // The respondToTask path checks this via validateTaskResponsePolicyData;
        // the direct path must check independently since respondToTask may not have run yet.
        if (!INewtonPolicy(taskResponse.policyAddress).isPolicyVerified()) return false;

        bytes32 taskId = taskResponse.taskId;
        address taskResponseHandler = INewtonProverTaskManager(taskManager).taskResponseHandler();

        // If attestation already exists from regular flow, validate using it instead
        bytes32 existingAttestationHash = attestations[taskId];
        if (existingAttestationHash != bytes32(0)) {
            bytes32 expectedTaskHash = INewtonProverTaskManager(taskManager).taskHash(taskId);
            if (TaskLib.taskHash(task) != expectedTaskHash) return false;

            // Bind taskResponse to stored normalized hash (synced with validateAttestationDirect)
            bytes32 storedNormalizedResponseHash =
                INewtonProverTaskManager(taskManager).normalizedTaskResponseHash(taskId);
            if (
                storedNormalizedResponseHash == bytes32(0)
                    || keccak256(abi.encode(taskResponse)) != storedNormalizedResponseHash
            ) return false;

            uint32 storedExpiration = attestationExpirations[taskId];
            if (storedExpiration == 0) return false;

            // policyId comes from TaskResponse (generated by operators)
            NewtonMessage.Attestation memory constructedAttestation = NewtonMessage.Attestation(
                taskId,
                taskResponse.policyId,
                task.policyClient,
                storedExpiration,
                task.intent,
                task.intentSignature
            );
            bool result = isAttestationValid(client, constructedAttestation);

            return result;
        }

        // Optimistic fast path: validate via task response handler before on-chain task exists
        // Delegates to SourceTaskResponseHandler (BLS) ONLY because the DestinationTaskResponseHandler (certificate) caches state and doesn't allow for view calling
        // This prevents double spending across both regular and direct flows
        if (attestationExpirations[taskId] == ATTESTATION_SPENT_SENTINEL) return false;

        // Bind every Task field that overlaps with TaskResponse (synced with validateAttestationDirect)
        if (task.taskId != taskResponse.taskId) return false;
        if (task.policyClient != taskResponse.policyClient) return false;
        if (keccak256(abi.encode(task.intent)) != keccak256(abi.encode(taskResponse.intent))) {
            return false;
        }
        if (keccak256(task.intentSignature) != keccak256(taskResponse.intentSignature)) {
            return false;
        }
        if (task.initializationTimestamp != taskResponse.initializationTimestamp) return false;

        // can't stop this from reverting, but will pass if sigs are good
        ITaskResponseHandler(taskResponseHandler)
            .verifyTaskResponse(task, taskResponse, signatureData);

        uint32 referenceBlock = uint32(block.number);
        uint32 expiration = referenceBlock + taskResponse.policyConfig.expireAfter;

        NewtonMessage.Attestation memory attestationForHash = NewtonMessage.Attestation(
            taskId,
            taskResponse.policyId,
            task.policyClient,
            expiration,
            task.intent,
            task.intentSignature
        );

        TaskLib.sanityCheckAttestation(attestationForHash);
        if (uint32(block.number) >= expiration) return false;

        return true;
    }
}
