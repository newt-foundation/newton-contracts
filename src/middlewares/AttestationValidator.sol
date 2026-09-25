// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {INewtonPolicyClient} from "../interfaces/INewtonPolicyClient.sol";
import {INewtonAddressesProvider} from "../interfaces/INewtonAddressesProvider.sol";
import {AddressesProviderConsumer} from "../mixins/AddressesProviderConsumer.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";
import {TaskLib} from "../libraries/TaskLib.sol";
import {PolicyValidationLib} from "../libraries/PolicyValidationLib.sol";
import {TaskManagerErrors} from "../libraries/TaskManagerErrors.sol";
import {ITaskResponseHandler} from "../interfaces/ITaskResponseHandler.sol";
import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";

contract AttestationValidator is Initializable, OwnableUpgradeable, AddressesProviderConsumer {
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
    /// @notice Direct-path liveness state, populated by `validateAttestationDirect` and read by
    /// `isAttestationDirectLive`.
    /// @dev Kept separate from `attestationExpirations`, which `validateAttestationDirect`
    /// overwrites with `ATTESTATION_SPENT_SENTINEL` and so cannot answer "still live" afterwards.
    mapping(bytes32 => uint32) public directAttestationExpirations;
    /// - directAttestationApproved: the recorded policy decision (`taskResponse.allowed`) at
    ///   verification time. Without this, a liveness re-check of a directly-verified-but-DENIED
    ///   response would have no decision to consult and could report the denial as live.
    mapping(bytes32 => bool) public directAttestationApproved;
    /// - directAttestationBindings: `keccak256(abi.encode(client, intent, policyId))`
    ///   recorded at verification time, so a liveness check can bind a caller-supplied
    ///   `(client, intent)` pair against the ORIGINAL verified binding without resupplying the full
    ///   Task/TaskResponse/signatureData bundle. Including `policyId` means the binding itself
    ///   goes stale the moment the client configures a new policy set via `setPolicies` --
    ///   `isAttestationDirectValid` re-derives the same tuple from the client's LIVE value on every
    ///   read, so a reconfiguration invalidates every direct-path record for that client
    ///   immediately, instead of leaving them valid until their recorded expiration.
    mapping(bytes32 => bytes32) public directAttestationBindings;

    uint256[42] private __gap;

    /* MODIFIERS */
    modifier onlyTaskManager() {
        require(msg.sender == taskManager, OnlyTaskManager());
        _;
    }

    /* CONSTRUCTOR */
    constructor(
        INewtonAddressesProvider _provider
    ) AddressesProviderConsumer(_provider) {}

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

    function validateResponse(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        string calldata minPolicyVersion
    ) external view onlyTaskManager returns (uint32) {
        return PolicyValidationLib.validateResponse(task, taskResponse, minPolicyVersion);
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
        TaskLib.sanityCheckAttestation(attestation);

        if (attestationExpirations[attestation.taskId] == ATTESTATION_SPENT_SENTINEL) return false;
        // Also covers a taskId that was never created (`stored` defaults to bytes32(0)).
        if (attestations[attestation.taskId] != keccak256(abi.encode(attestation))) return false;
        if (uint32(block.number) >= attestation.expiration) return false;

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

    /// @dev Thin external wrappers around the revert-based validation helpers so the
    /// `isAttestationDirectValid` view sibling can convert reverts to `false` via
    /// staticcall + try/catch without duplicating validation logic. Each wraps exactly the
    /// call `validateAttestationDirect` makes, in the same order, so the two never diverge.
    function _checkPolicySnapshot(
        INewtonProverTaskManager.Task calldata task
    ) external view {
        PolicyValidationLib.requirePolicySnapshot(task);
        PolicyValidationLib.requireActiveFactory(
            task, INewtonProverTaskManager(taskManager).policyFactory()
        );
    }

    function _checkValidateResponse(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse
    ) external view returns (uint32) {
        return PolicyValidationLib.validateResponse(
            task, taskResponse, INewtonProverTaskManager(taskManager).minCompatiblePolicyVersion()
        );
    }

    function _checkSanityAttestation(
        NewtonMessage.Attestation calldata attestation
    ) external view {
        TaskLib.sanityCheckAttestation(attestation);
    }

    function _checkSanityTaskResponse(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        uint32 blockNumber,
        uint32 responseWindowBlock
    ) external pure {
        TaskLib.sanityCheckTaskResponse(task, taskResponse, blockNumber, responseWindowBlock);
    }

    // solhint-disable-next-line function-max-lines
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
            TaskManagerErrors.PolicyIdMismatch()
        );
        // The signed response commits only to policyId; bind the snapshot the caller hands us
        // back to it, or a caller could substitute a different policies array under a matching id.
        require(task.policyId == taskResponse.policyId, TaskManagerErrors.PolicyIdMismatch());
        PolicyValidationLib.requirePolicySnapshot(task);
        PolicyValidationLib.requireActiveFactory(
            task, INewtonProverTaskManager(taskManager).policyFactory()
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
            // This branch requires `attestations[taskId]`, which the regular flow only sets
            // for an APPROVE -- a DENY never reaches here.
            directAttestationExpirations[taskId] = storedExpiration;
            directAttestationApproved[taskId] = true;
            directAttestationBindings[taskId] =
                keccak256(abi.encode(task.policyClient, task.intent, taskResponse.policyId));
            emit INewtonProverTaskManager.DirectTaskResponded(taskId, task, taskResponse);

            return result;
        }

        // Optimistic fast path: validate via task response handler before on-chain task exists
        // Delegates to SourceTaskResponseHandler (BLS) or DestinationTaskResponseHandler (certificate)
        // Prevent double spending across both regular and direct flows
        require(
            attestationExpirations[taskId] != ATTESTATION_SPENT_SENTINEL, AttestationAlreadySpent()
        );

        // Sanity check the task parameters
        require(task.taskCreatedBlock < uint32(block.number), TaskLib.TaskCreatedBlockInFuture());

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

        TaskLib.sanityCheckTaskResponse(
            task,
            taskResponse,
            uint32(block.number),
            INewtonProverTaskManager(taskManager).taskResponseWindowBlock()
        );

        // Same PolicyValidationLib entry point respondToTask uses, so the direct path never
        // runs a duplicated (and divergent) copy of the version gate or per-policy checks.
        uint32 minExpireAfterBlocks = PolicyValidationLib.validateResponse(
            task, taskResponse, INewtonProverTaskManager(taskManager).minCompatiblePolicyVersion()
        );

        ITaskResponseHandler(taskResponseHandler)
            .verifyTaskResponse(task, taskResponse, signatureData);

        uint32 referenceBlock = uint32(block.number);
        uint32 expiration = referenceBlock + minExpireAfterBlocks;

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

        // Revert = invalid attestation; return value = policy decision
        bool decision = taskResponse.allowed;
        // Preserved separately from `attestationExpirations` (already clobbered by the spent
        // sentinel above) and recorded regardless of `decision`, so `isAttestationDirectValid`
        // can distinguish "directly verified but denied" from "never verified" instead of only
        // ever seeing an unconditional `true`.
        directAttestationExpirations[taskId] = expiration;
        directAttestationApproved[taskId] = decision;
        directAttestationBindings[taskId] =
            keccak256(abi.encode(task.policyClient, task.intent, taskResponse.policyId));
        emit INewtonProverTaskManager.DirectTaskResponded(taskId, task, taskResponse);

        return decision;
    }

    /// @notice Liveness check for a direct-path attestation, over state `validateAttestationDirect`
    /// already recorded -- never re-verifies BLS signatures or accepts an arbitrary caller-supplied
    /// Task/TaskResponse bundle. Mirrors `isAttestationValid`'s relationship to `validateAttestation`:
    /// a cheap re-check against a prior verification's committed state, not a second verification.
    /// For a pre-flight check on a bundle that has not been spent yet, use
    /// `isAttestationDirectValid`.
    /// @param client The policy client the attestation must have been verified for.
    /// @param taskId The direct-path task to check liveness of.
    /// @param intent The intent the attestation must have been verified against -- checked against
    /// `directAttestationBindings`, the compact commitment recorded at verification time.
    /// @dev The binding is re-derived from `client`'s LIVE `getPolicyId()` on every call, not just
    /// the caller-supplied `(client, intent)` pair -- so a `setPolicies` reconfiguration changes
    /// what this function re-derives and immediately invalidates every direct-path record still
    /// committed to the prior set, the same way `isAttestationValid`'s `TaskLib.
    /// sanityCheckAttestation` catches a rotation on the regular path.
    function isAttestationDirectLive(
        address client,
        bytes32 taskId,
        NewtonMessage.Intent calldata intent
    ) public view returns (bool) {
        if (!directlyVerifiedAttestations[taskId]) return false;
        if (!directAttestationApproved[taskId]) return false;
        if (uint32(block.number) >= directAttestationExpirations[taskId]) return false;

        // `client` is caller-supplied, so it need not be a contract at all, let alone an
        // `INewtonPolicyClient` -- reading its live policy must therefore degrade to `false`
        // rather than bubbling a raw revert, preserving this view's non-reverting contract for
        // every "this attestation isn't live for that client" case. A binding recorded by
        // `validateAttestationDirect` always committed to a nonzero policyId (response
        // validation there requires a non-empty policy set), so bytes32(0) is unambiguously
        // the "could not read" signal, never a valid live state that should compare equal.
        bytes32 livePolicyId = _tryGetLivePolicyId(client);
        if (livePolicyId == bytes32(0)) return false;

        if (
            directAttestationBindings[taskId] != keccak256(abi.encode(client, intent, livePolicyId))
        ) {
            return false;
        }
        return true;
    }

    /// @notice Pre-flight sibling of `validateAttestationDirect`: given a full
    /// `(task, taskResponse, signatureData)` bundle it answers "is this bundle good right now?"
    /// by verifying the response rather than reading recorded state -- which is what lets it
    /// answer before any on-chain task exists, and why it turns false once the attestation is
    /// spent. `isAttestationDirectLive` is the mirror image, answering only afterwards.
    /// @dev IMPORTANT: must be kept in sync with `validateAttestationDirect`. Every revert-based
    /// check there is reached through a `_check*` wrapper here so the two share one
    /// implementation and this view keeps its non-reverting contract.
    // solhint-disable-next-line function-max-lines
    function isAttestationDirectValid(
        address client,
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        bytes calldata signatureData
    ) public view returns (bool) {
        // Only the correct policy client may directly validate and spend the attestation
        if (client != task.policyClient || client != taskResponse.policyClient) return false;
        if (_tryGetLivePolicyId(client) != taskResponse.policyId) return false;
        // The signed response commits only to policyId; bind the snapshot the caller hands us
        // back to it, or a caller could substitute a different policies array under a matching id.
        if (task.policyId != taskResponse.policyId) return false;
        try this._checkPolicySnapshot(task) {}
        catch {
            return false;
        }

        bytes32 taskId = taskResponse.taskId;
        address taskResponseHandler = INewtonProverTaskManager(taskManager).taskResponseHandler();

        // If attestation already exists from regular flow, validate using it instead
        if (attestations[taskId] != bytes32(0)) {
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

            return isAttestationValid(
                client,
                NewtonMessage.Attestation(
                    taskId,
                    taskResponse.policyId,
                    task.policyClient,
                    storedExpiration,
                    task.intent,
                    task.intentSignature
                )
            );
        }

        // Optimistic fast path: validate via task response handler before an on-chain task
        // exists. Delegates to SourceTaskResponseHandler (BLS) or DestinationTaskResponseHandler
        // (certificate); both are view. Prevent double spending across regular and direct flows.
        if (attestationExpirations[taskId] == ATTESTATION_SPENT_SENTINEL) return false;

        // Sanity check the task parameters
        if (task.taskCreatedBlock >= uint32(block.number)) return false;

        // Bind every Task field that overlaps with TaskResponse (synced with
        // validateAttestationDirect)
        if (task.taskId != taskResponse.taskId) return false;
        if (task.policyClient != taskResponse.policyClient) return false;
        if (keccak256(abi.encode(task.intent)) != keccak256(abi.encode(taskResponse.intent))) {
            return false;
        }
        if (keccak256(task.intentSignature) != keccak256(taskResponse.intentSignature)) {
            return false;
        }
        if (task.initializationTimestamp != taskResponse.initializationTimestamp) return false;

        try this._checkSanityTaskResponse(
            task,
            taskResponse,
            uint32(block.number),
            INewtonProverTaskManager(taskManager).taskResponseWindowBlock()
        ) {}
        catch {
            return false;
        }

        uint32 minExpireAfterBlocks;
        try this._checkValidateResponse(task, taskResponse) returns (uint32 minExpireAfter) {
            minExpireAfterBlocks = minExpireAfter;
        } catch {
            return false;
        }

        try ITaskResponseHandler(taskResponseHandler)
            .verifyTaskResponse(task, taskResponse, signatureData) returns (
            bytes32
        ) {}
        catch {
            return false;
        }

        uint32 expiration = uint32(block.number) + minExpireAfterBlocks;
        try this._checkSanityAttestation(
            NewtonMessage.Attestation(
                taskId,
                taskResponse.policyId,
                task.policyClient,
                expiration,
                task.intent,
                task.intentSignature
            )
        ) {}
        catch {
            return false;
        }
        if (uint32(block.number) >= expiration) return false;

        // Return the decision, matching what validateAttestationDirect returns on this same path.
        // A denied response is verifiable but would not be accepted.
        return taskResponse.allowed;
    }

    /// @dev Reads `client`'s live policyId, returning `bytes32(0)` if `client` is not a contract
    /// or does not implement `INewtonPolicyClient`.
    function _tryGetLivePolicyId(
        address client
    ) private view returns (bytes32) {
        // Must precede the call below: for a target with no code, Solidity emits its
        // `extcodesize` check in THIS frame, so the resulting revert happens before any call is
        // made and `try/catch` (which only catches reverts from the callee) never sees it.
        if (client.code.length == 0) return bytes32(0);
        try INewtonPolicyClient(client).getPolicyId() returns (bytes32 policyId) {
            return policyId;
        } catch {
            return bytes32(0);
        }
    }
}
