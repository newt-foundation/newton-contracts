// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";
import {INewtonPolicyClient} from "../interfaces/INewtonPolicyClient.sol";
import {INewtonAddressesProvider} from "../interfaces/INewtonAddressesProvider.sol";
import {AddressesProviderConsumer} from "../mixins/AddressesProviderConsumer.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";
import {TaskLib} from "../libraries/TaskLib.sol";
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
    /// @notice Direct-path liveness state, populated once by `validateAttestationDirect` and read
    /// repeatedly by `isAttestationDirectValid` -- so a liveness re-check never re-verifies BLS
    /// signatures or accepts an arbitrary caller-supplied Task/TaskResponse bundle, mirroring how
    /// `isAttestationValid` re-checks the regular path against `attestations`/`attestationExpirations`
    /// rather than re-validating a fresh signature each call.
    /// - directAttestationExpirations: preserved separately from `attestationExpirations`, which
    ///   `validateAttestationDirect` always overwrites with `ATTESTATION_SPENT_SENTINEL` regardless
    ///   of the underlying expiration -- that overwrite means `attestationExpirations` alone cannot
    ///   answer "is this direct attestation still live" after the spending call.
    mapping(bytes32 => uint32) public directAttestationExpirations;
    /// - directAttestationApproved: the recorded policy decision (`evaluationResult`) at
    ///   verification time. Without this, a liveness re-check of a directly-verified-but-DENIED
    ///   response would have no decision to consult and could report the denial as live.
    mapping(bytes32 => bool) public directAttestationApproved;
    /// - directAttestationBindings: `keccak256(abi.encode(client, intent, policyAddress, policyId))`
    ///   recorded at verification time, so a liveness check can bind a caller-supplied
    ///   `(client, intent)` pair against the ORIGINAL verified binding without resupplying the full
    ///   Task/TaskResponse/signatureData bundle. Including `policyAddress`/`policyId` means the
    ///   binding itself goes stale the moment the client rotates its policy via `setPolicy` (new
    ///   `policyId`, same address) or `setPolicyAddress` (new address, `policyId` cleared to zero) --
    ///   `isAttestationDirectValid` re-derives the same tuple from the client's LIVE values on every
    ///   read, so a rotation invalidates every direct-path record for that client immediately,
    ///   instead of leaving them valid until their recorded expiration.
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

    // IMPORTANT: must be kept in sync with validateAttestation -- same check order as
    // _validateAttestation, so a multi-invalid attestation fails for the same reason
    // (revert vs `false`) on both paths.
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
            TaskLib.InvalidPolicyId()
        );
        // Bind policyAddress to the client's real policy. The respondToTask path enforces this
        // via getPolicyAddress() (NewtonProverTaskManagerShared); the direct path must too, or a
        // response could name an attacker-controlled contract whose getPolicyCodeHash() matches
        // crafted policy bytes while keeping the real client's policyId.
        require(
            taskResponse.policyAddress == INewtonPolicyClient(caller).getPolicyAddress(),
            TaskLib.InvalidPolicyAddress()
        );
        require(
            keccak256(taskResponse.policyTaskData.policy)
                == INewtonPolicy(taskResponse.policyAddress).getPolicyCodeHash(),
            TaskLib.TaskResponseMismatch()
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
            // Entering this branch requires `attestations[taskId]` to have been set by
            // `createAttestationHash`, which the regular flow only calls for an APPROVE
            // (see `NewtonProverTaskManagerShared.respondToTask`) -- a DENY never reaches here.
            directAttestationExpirations[taskId] = storedExpiration;
            directAttestationApproved[taskId] = true;
            directAttestationBindings[taskId] = keccak256(
                abi.encode(
                    task.policyClient,
                    task.intent,
                    taskResponse.policyAddress,
                    taskResponse.policyId
                )
            );
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

        TaskLib.validateTaskResponsePolicyData(taskResponse);
        TaskLib.sanityCheckTaskResponse(
            task,
            taskResponse,
            uint32(block.number),
            INewtonProverTaskManager(taskManager).taskResponseWindowBlock()
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

        // Revert = invalid attestation; return value = policy decision
        bool decision = TaskLib.evaluateResult(taskResponse.evaluationResult);
        // Preserved separately from `attestationExpirations` (already clobbered by the spent
        // sentinel above) and recorded regardless of `decision`, so `isAttestationDirectValid`
        // can distinguish "directly verified but denied" from "never verified" instead of only
        // ever seeing an unconditional `true`.
        directAttestationExpirations[taskId] = expiration;
        directAttestationApproved[taskId] = decision;
        directAttestationBindings[taskId] = keccak256(
            abi.encode(
                task.policyClient, task.intent, taskResponse.policyAddress, taskResponse.policyId
            )
        );
        emit INewtonProverTaskManager.DirectTaskResponded(taskId, task, taskResponse);

        return decision;
    }

    /// @notice Liveness check for a direct-path attestation, over state `validateAttestationDirect`
    /// already recorded -- never re-verifies BLS signatures or accepts an arbitrary caller-supplied
    /// Task/TaskResponse bundle. Mirrors `isAttestationValid`'s relationship to `validateAttestation`:
    /// a cheap re-check against a prior verification's committed state, not a second verification.
    /// @param client The policy client the attestation must have been verified for.
    /// @param taskId The direct-path task to check liveness of.
    /// @param intent The intent the attestation must have been verified against -- checked against
    /// `directAttestationBindings`, the compact commitment recorded at verification time.
    /// @dev The binding is re-derived from `client`'s LIVE `getPolicyAddress()`/`getPolicyId()` on
    /// every call, not just the caller-supplied `(client, intent)` pair -- so a policy rotation via
    /// `setPolicy` (fresh `policyId`) or `setPolicyAddress` (fresh address, `policyId` cleared to
    /// zero) changes what this function re-derives and immediately invalidates every direct-path
    /// record still committed to the pre-rotation policy, the same way `isAttestationValid`'s
    /// `TaskLib.sanityCheckAttestation` catches a rotation on the regular path.
    function isAttestationDirectValid(
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
        // every "this attestation isn't live for that client" case.
        (address livePolicyAddress, bytes32 livePolicyId) = _tryGetLivePolicy(client);
        if (livePolicyAddress == address(0) && livePolicyId == bytes32(0)) return false;

        if (
            directAttestationBindings[taskId]
                != keccak256(abi.encode(client, intent, livePolicyAddress, livePolicyId))
        ) {
            return false;
        }
        return true;
    }

    /// @dev Reads `client`'s live `(policyAddress, policyId)` pair, returning `(address(0),
    /// bytes32(0))` if `client` is not a contract or does not implement `INewtonPolicyClient`.
    /// A genuine client mid-setup can legitimately report `policyId == bytes32(0)` (e.g. right
    /// after `setPolicyAddress` clears it), but never alongside `policyAddress == address(0)` --
    /// and a binding recorded by `validateAttestationDirect` always committed to a nonzero
    /// `policyAddress`, since that path requires `taskResponse.policyAddress ==
    /// client.getPolicyAddress()` and then dereferences it. So the all-zero pair is unambiguously
    /// the "could not read" signal, never a valid live state that should compare equal.
    function _tryGetLivePolicy(
        address client
    ) private view returns (address, bytes32) {
        // Must precede the calls below: for a target with no code, Solidity emits its
        // `extcodesize` check in THIS frame, so the resulting revert happens before any call is
        // made and `try/catch` (which only catches reverts from the callee) never sees it.
        if (client.code.length == 0) return (address(0), bytes32(0));
        try INewtonPolicyClient(client).getPolicyAddress() returns (address policyAddress) {
            try INewtonPolicyClient(client).getPolicyId() returns (bytes32 policyId) {
                return (policyAddress, policyId);
            } catch {
                return (address(0), bytes32(0));
            }
        } catch {
            return (address(0), bytes32(0));
        }
    }
}
