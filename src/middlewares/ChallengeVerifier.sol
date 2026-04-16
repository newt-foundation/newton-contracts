// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {TaskLib} from "../libraries/TaskLib.sol";
import {TaskManagerErrors} from "../libraries/TaskManagerErrors.sol";
import {ChallengeLib} from "../libraries/ChallengeLib.sol";
import {AttestationValidator} from "./AttestationValidator.sol";
import {ITaskResponseHandler} from "../interfaces/ITaskResponseHandler.sol";
import {
    IBLSSignatureChecker,
    IBLSSignatureCheckerTypes
} from "@eigenlayer-middleware/src/interfaces/IBLSSignatureChecker.sol";
import "@eigenlayer-middleware/src/libraries/BN254.sol";
import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@openzeppelin-upgrades/contracts/security/ReentrancyGuardUpgradeable.sol";
import {RegoVerifier} from "./RegoVerifier.sol";
import {IRegoVerifier} from "../interfaces/IRegoVerifier.sol";
import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";

contract ChallengeVerifier is Initializable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
    /* CUSTOM ERRORS */
    error ChallengeNotEnabled();
    error NotChallengable();
    error ChallengePeriodExpired();
    error OnlyTaskManager();
    error ChallengeFailed();
    error OnlySourceChain();
    error UnregisteredDestinationChain(uint256 chainId);
    error CrossChainChallengeAlreadyProcessed(uint256 destChainId, bytes32 taskId);
    /// @notice Proof-supplied `policyCodeHash` does not match the on-chain policy deployment
    /// @dev Without this check an attacker could supply divergent policy bytes in the zkVM
    ///      and slash an operator for a "violation" the real policy never could have produced
    error PolicyCodeHashMismatch(bytes32 expected, bytes32 actual);

    /* EVENTS */
    event ChallengeEnabled(bool indexed isChallengeEnabled);
    event DestinationChainRegistered(uint256 indexed chainId, bool indexed registered);
    event CrossChainChallengeRelayed(
        uint256 indexed destChainId, bytes32 indexed taskId, address challenger
    );

    /* STORAGE */
    address public immutable taskManager;
    address public immutable serviceManager;
    address public immutable registryCoordinator;
    address public immutable blsApkRegistry;
    address public immutable allocationManager;
    address public immutable instantSlasher;
    address public immutable regoVerifier;
    address public immutable attestationValidator;
    address public immutable operatorRegistry;
    address public immutable operatorStateRetriever;

    bool public isChallengeEnabled;
    uint32 public taskChallengeWindowBlock;
    uint32 public taskResponseWindowBlock;

    mapping(bytes32 => bool) public taskSuccesfullyChallenged;
    mapping(bytes32 => bytes32) public allTaskHashes;
    mapping(bytes32 => bytes32) public allTaskResponses;

    /// @notice Tracks cross-chain challenges to prevent double-slashing
    /// @dev Key: keccak256(abi.encode(taskHash, responseHash)) — content-addressed
    ///      to prevent replay with different destChainId values
    mapping(bytes32 => bool) public crossChainChallenged;

    /// @notice Whitelisted destination chain IDs for cross-chain challenge relay
    mapping(uint256 => bool) public registeredDestinationChains;

    uint256[45] private __gap;

    /* MODIFIERS */
    modifier onlyTaskManager() {
        require(msg.sender == taskManager, OnlyTaskManager());
        _;
    }

    /* CONSTRUCTOR */
    constructor(
        address _serviceManager,
        address _taskManager,
        address _registryCoordinator,
        address _blsApkRegistry,
        address _allocationManager,
        address _instantSlasher,
        address _regoVerifier,
        address _attestationValidator,
        address _operatorRegistry,
        address _operatorStateRetriever
    ) {
        taskManager = _taskManager;
        serviceManager = _serviceManager;
        registryCoordinator = _registryCoordinator;
        blsApkRegistry = _blsApkRegistry;
        allocationManager = _allocationManager;
        instantSlasher = _instantSlasher;
        regoVerifier = _regoVerifier;
        attestationValidator = _attestationValidator;
        operatorRegistry = _operatorRegistry;
        operatorStateRetriever = _operatorStateRetriever;
    }

    /* INITIALIZER */
    function initialize(
        bool _isChallengeEnabled,
        uint32 _taskChallengeWindowBlock,
        uint32 _taskResponseWindowBlock,
        address _owner
    ) public initializer {
        __Ownable_init();
        __ReentrancyGuard_init();
        _transferOwnership(_owner);
        isChallengeEnabled = _isChallengeEnabled;
        taskChallengeWindowBlock = _taskChallengeWindowBlock;
        taskResponseWindowBlock = _taskResponseWindowBlock;
    }

    /* EXTERNAL FUNCTIONS */
    // solhint-disable-next-line function-max-lines
    function raiseAndResolveChallenge(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        INewtonProverTaskManager.ResponseCertificate calldata responseCertificate,
        INewtonProverTaskManager.ChallengeData calldata challenge,
        BN254.G1Point[] calldata pubkeysOfNonSigningOperators
    ) external onlyTaskManager nonReentrant returns (bool) {
        require(isChallengeEnabled, ChallengeNotEnabled());
        require(
            TaskLib.taskHash(task) == allTaskHashes[taskResponse.taskId],
            TaskLib.TaskMismatch(allTaskHashes[taskResponse.taskId], TaskLib.taskHash(task))
        );
        require(
            _isChallengable(task, taskResponse, responseCertificate, challenge), NotChallengable()
        );
        require(
            uint32(block.number) < responseCertificate.referenceBlock + taskChallengeWindowBlock,
            ChallengePeriodExpired()
        );

        // Use taskResponse.policyTaskData (operators now generate policyTaskData independently)
        INewtonPolicy policy = INewtonPolicy(taskResponse.policyTaskData.policyAddress);
        require(policy.isPolicyVerified(), TaskLib.PolicyNotVerified());

        // Verify the rego proof. Reverts if the proof is invalid.
        IRegoVerifier.RegoContext memory context =
            RegoVerifier(regoVerifier).verifyRegoProof(challenge.data, challenge.proof);
        // make sure that proof public values match the task and task response.
        // Circuit also checks if task and task response are correct.
        require(
            TaskLib.taskHash(context.task) == allTaskHashes[taskResponse.taskId],
            TaskLib.TaskMismatch(allTaskHashes[taskResponse.taskId], TaskLib.taskHash(context.task))
        );
        // Compare proof's taskResponse against the caller-supplied taskResponse
        // (not against allTaskResponses, which includes the certificate).
        // The _isChallengable precondition already validated the caller-supplied
        // (taskResponse, responseCertificate) against the stored response+certificate hash.
        require(
            keccak256(abi.encode(context.taskResponse)) == keccak256(abi.encode(taskResponse)),
            TaskLib.TaskResponseMismatch()
        );
        require(
            keccak256(abi.encode(policy.getEntrypoint()))
                == keccak256(abi.encode(context.entrypoint)),
            TaskLib.EntrypointMismatch()
        );

        // Bind proof's policyCodeHash to the on-chain policy deployment.
        // The SP1 circuit commits keccak256 of the raw policy bytes it actually
        // executed. Without this check, a challenger could supply divergent policy
        // bytes in the zkVM and slash for a "violation" the real policy never could
        // have produced.
        bytes32 onchainPolicyCodeHash = policy.getPolicyCodeHash();
        require(
            context.policyCodeHash == onchainPolicyCodeHash,
            PolicyCodeHashMismatch(onchainPolicyCodeHash, context.policyCodeHash)
        );

        bool challengeSuccess = keccak256(abi.encode(context.evaluation))
            != keccak256(abi.encode(taskResponse.evaluationResult));

        require(challengeSuccess, ChallengeFailed());

        // Record challenge success before external calls (CEI: reentrancy safety).
        taskSuccesfullyChallenged[taskResponse.taskId] = true;

        // Gate non-signer processing and slashing behind source-chain check.
        // On destination chains blsApkRegistry == address(0), so processNonSigners would
        // revert on the external call to a zero address.
        if (serviceManager != address(0)) {
            // Process non-signing operators and validate
            (
                bytes32[] memory hashesOfPubkeysOfNonSigningOperators,
                address[] memory addressOfNonSigningOperators
            ) = ChallengeLib.processNonSigners(pubkeysOfNonSigningOperators, blsApkRegistry);

            ChallengeLib.validateSignatoryRecord(
                task.taskCreatedBlock,
                hashesOfPubkeysOfNonSigningOperators,
                responseCertificate.hashOfNonSigners
            );

            // Slash signing operators only on source chains (where serviceManager is set)
            // Destination chains don't have slashing capability
            ChallengeLib.ChallengeContext memory ctx = ChallengeLib.ChallengeContext({
                blsApkRegistry: blsApkRegistry,
                operatorStateRetriever: operatorStateRetriever,
                registryCoordinator: registryCoordinator,
                allocationManager: allocationManager,
                instantSlasher: instantSlasher,
                serviceManager: serviceManager
            });

            ChallengeLib.slashSigningOperators(
                ctx, task.quorumNumbers, task.taskCreatedBlock, addressOfNonSigningOperators
            );
        }

        return true;
    }

    /// @notice Slash operators for a challenge proven on a destination chain
    /// @dev Re-executes ZK proof on source chain independently. Does not require the task
    ///      to exist in allTaskHashes since dest-chain tasks are never registered on source.
    ///      Binds proof outputs to caller-supplied inputs and verifies BLS certificate to
    ///      prevent arbitrary operator slashing.
    /// @param destChainId The destination chain where the task was created and challenged
    /// @param task The original task from the destination chain
    /// @param taskResponse The task response being challenged
    /// @param challenge ZK proof data proving the response was incorrect
    /// @param signatureData Encoded BLS signature data for certificate verification
    /// @param pubkeysOfNonSigningOperators BLS G1 pubkeys of non-signing operators (from BN254Certificate)
    /// @param _taskResponseHandler Address of the task response handler for BLS verification
    // solhint-disable-next-line function-max-lines
    function slashForCrossChainChallenge(
        uint256 destChainId,
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        INewtonProverTaskManager.ChallengeData calldata challenge,
        bytes calldata signatureData,
        BN254.G1Point[] calldata pubkeysOfNonSigningOperators,
        address _taskResponseHandler
    ) external onlyTaskManager nonReentrant returns (bool) {
        require(isChallengeEnabled, ChallengeNotEnabled());
        require(serviceManager != address(0), OnlySourceChain());
        require(registeredDestinationChains[destChainId], UnregisteredDestinationChain(destChainId));

        // Prevent double-slashing for the same cross-chain challenge.
        // Key is content-addressed (task + response hash) rather than using caller-supplied
        // destChainId, which would allow replay by passing different registered chain IDs.
        bytes32 taskHashVal = TaskLib.taskHash(task);
        bytes32 responseHash = keccak256(abi.encode(taskResponse));
        bytes32 crossChainKey = keccak256(abi.encode(taskHashVal, responseHash));
        require(
            !crossChainChallenged[crossChainKey],
            CrossChainChallengeAlreadyProcessed(destChainId, challenge.taskId)
        );

        // Verify the policy is valid
        INewtonPolicy policy = INewtonPolicy(taskResponse.policyTaskData.policyAddress);
        require(policy.isPolicyVerified(), TaskLib.PolicyNotVerified());

        // Re-verify the ZK proof on source chain (trust-minimized: no bridge dependency)
        IRegoVerifier.RegoContext memory context =
            RegoVerifier(regoVerifier).verifyRegoProof(challenge.data, challenge.proof);

        // Bind proof public values to caller-supplied inputs — prevents using
        // a valid proof from an unrelated task/response pair for targeted slashing
        require(
            TaskLib.taskHash(context.task) == taskHashVal,
            TaskLib.TaskMismatch(taskHashVal, TaskLib.taskHash(context.task))
        );
        require(
            keccak256(abi.encode(context.taskResponse)) == responseHash,
            TaskLib.TaskResponseMismatch()
        );
        require(
            keccak256(abi.encode(policy.getEntrypoint()))
                == keccak256(abi.encode(context.entrypoint)),
            TaskLib.EntrypointMismatch()
        );

        // Bind proof's policyCodeHash to the on-chain policy deployment (same
        // defense as raiseAndResolveChallenge). Particularly important on
        // cross-chain paths where the dest-chain caller supplies all inputs.
        bytes32 onchainPolicyCodeHash = policy.getPolicyCodeHash();
        require(
            context.policyCodeHash == onchainPolicyCodeHash,
            PolicyCodeHashMismatch(onchainPolicyCodeHash, context.policyCodeHash)
        );

        // Verify proof output mismatches the task response (challenge is valid)
        bool challengeSuccess = keccak256(abi.encode(context.evaluation))
            != keccak256(abi.encode(taskResponse.evaluationResult));
        require(challengeSuccess, ChallengeFailed());

        // Verify BLS certificate on source chain — the task response handler validates
        // operator signatures and returns the cryptographically-derived hashOfNonSigners.
        // This ensures the non-signer list is authentic, not attacker-supplied.
        bytes32 hashOfNonSigners = ITaskResponseHandler(_taskResponseHandler)
            .verifyTaskResponse(task, taskResponse, signatureData);

        // Process non-signing operators and validate against the verified certificate
        (
            bytes32[] memory hashesOfPubkeysOfNonSigningOperators,
            address[] memory addressOfNonSigningOperators
        ) = ChallengeLib.processNonSigners(pubkeysOfNonSigningOperators, blsApkRegistry);

        ChallengeLib.validateSignatoryRecord(
            task.taskCreatedBlock, hashesOfPubkeysOfNonSigningOperators, hashOfNonSigners
        );

        // Record challenge success before external calls (CEI: reentrancy safety)
        crossChainChallenged[crossChainKey] = true;
        emit CrossChainChallengeRelayed(destChainId, challenge.taskId, msg.sender);

        ChallengeLib.ChallengeContext memory ctx = ChallengeLib.ChallengeContext({
            blsApkRegistry: blsApkRegistry,
            operatorStateRetriever: operatorStateRetriever,
            registryCoordinator: registryCoordinator,
            allocationManager: allocationManager,
            instantSlasher: instantSlasher,
            serviceManager: serviceManager
        });

        ChallengeLib.slashSigningOperators(
            ctx, task.quorumNumbers, task.taskCreatedBlock, addressOfNonSigningOperators
        );
        return true;
    }

    function _isChallengable(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        INewtonProverTaskManager.ResponseCertificate calldata responseCertificate,
        INewtonProverTaskManager.ChallengeData calldata challenge
    ) internal view returns (bool) {
        bytes32 taskId = taskResponse.taskId;
        return task.taskId == taskId && allTaskResponses[taskId] != bytes32(0)
            && allTaskResponses[taskId] == keccak256(abi.encode(taskResponse, responseCertificate))
            && !taskSuccesfullyChallenged[taskId]
            && uint32(block.number) < responseCertificate.responseExpireBlock
            && challenge.taskId == taskId;
    }

    /* SETTER FUNCTIONS FOR COMPOSITION */
    function setTaskHashesAndResponses(
        bytes32 taskId,
        bytes32 taskHash,
        bytes32 taskResponseHash
    ) external onlyTaskManager {
        allTaskHashes[taskId] = taskHash;
        allTaskResponses[taskId] = taskResponseHash;
    }

    function isTaskChallenged(
        bytes32 taskId
    ) external view returns (bool) {
        return taskSuccesfullyChallenged[taskId];
    }

    /* OWNER FUNCTIONS */
    function setIsChallengeEnabled(
        bool _isChallengeEnabled
    ) external onlyOwner {
        isChallengeEnabled = _isChallengeEnabled;
        emit ChallengeEnabled(_isChallengeEnabled);
    }

    function updateTaskChallengeWindowBlock(
        uint32 _taskChallengeWindowBlock
    ) external onlyOwner {
        taskChallengeWindowBlock = _taskChallengeWindowBlock;
    }

    function updateTaskResponseWindowBlock(
        uint32 _taskResponseWindowBlock
    ) external onlyOwner {
        taskResponseWindowBlock = _taskResponseWindowBlock;
    }

    /// @notice Register or unregister a destination chain for cross-chain challenge relay
    /// @param chainId The destination chain ID
    /// @param registered Whether the chain should be registered
    function setRegisteredDestinationChain(
        uint256 chainId,
        bool registered
    ) external onlyOwner {
        registeredDestinationChains[chainId] = registered;
        emit DestinationChainRegistered(chainId, registered);
    }

    function challengeDirectlyVerifiedAttestation(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        bytes calldata signatureData,
        address _taskResponseHandler
    ) external onlyTaskManager nonReentrant {
        bytes32 taskId = taskResponse.taskId;

        require(!taskSuccesfullyChallenged[taskId], NotChallengable());

        // Verify attestation was directly verified
        require(
            AttestationValidator(attestationValidator).isDirectlyVerified(taskId),
            TaskManagerErrors.NotDirectlyVerified()
        );

        // Verify taskResponseWindow has passed
        require(
            uint32(block.number) > task.taskCreatedBlock + taskResponseWindowBlock,
            TaskLib.TaskResponseWindowNotPassed(
                uint32(block.number), task.taskCreatedBlock, taskResponseWindowBlock
            )
        );

        // Verify respondToTask was never called (check TaskManager's taskResponseHash mapping)
        bytes32 taskResponseHash = INewtonProverTaskManager(taskManager).taskResponseHash(taskId);
        require(taskResponseHash == bytes32(0), TaskLib.TaskAlreadyResponded(taskResponseHash));

        // Verify task hash matches the one stored in TaskManager
        bytes32 expectedTaskHash = INewtonProverTaskManager(taskManager).taskHash(taskId);
        require(
            TaskLib.taskHash(task) == expectedTaskHash,
            TaskLib.TaskMismatch(expectedTaskHash, TaskLib.taskHash(task))
        );

        // Re-verify signatures via task response handler to confirm validity
        // Source chains: BLS signature verification, Destination chains: certificate verification
        ITaskResponseHandler(_taskResponseHandler)
            .verifyTaskResponse(task, taskResponse, signatureData);

        // Record challenge success before external calls (CEI: reentrancy safety)
        taskSuccesfullyChallenged[taskId] = true;
        AttestationValidator(attestationValidator).invalidateAttestation(taskId);

        // Slashing only available on source chains (where blsApkRegistry is set)
        if (blsApkRegistry != address(0)) {
            // Decode NonSignerStakesAndSignature to extract non-signer pubkeys for slashing
            IBLSSignatureCheckerTypes.NonSignerStakesAndSignature memory
                nonSignerStakesAndSignature =
                abi.decode(signatureData, (IBLSSignatureCheckerTypes.NonSignerStakesAndSignature));

            // Extract non-signer addresses from pubkeys
            (
                bytes32[] memory hashesOfPubkeysOfNonSigningOperators,
                address[] memory addressOfNonSigningOperators
            ) = ChallengeLib.processNonSigners(
                nonSignerStakesAndSignature.nonSignerPubkeys, blsApkRegistry
            );

            // Create challenge context
            ChallengeLib.ChallengeContext memory ctx = ChallengeLib.ChallengeContext({
                blsApkRegistry: blsApkRegistry,
                operatorStateRetriever: operatorStateRetriever,
                registryCoordinator: registryCoordinator,
                allocationManager: allocationManager,
                instantSlasher: instantSlasher,
                serviceManager: serviceManager
            });

            // Slash signing operators
            ChallengeLib.slashSigningOperators(
                ctx, task.quorumNumbers, task.taskCreatedBlock, addressOfNonSigningOperators
            );
        }
    }

    /// @notice Invalidate a direct-path attestation whose stored hashes do not match
    /// the canonical (regular-path) task / response hashes.
    ///
    /// This function never slashes. A hash divergence between the direct path
    /// and the regular path does NOT by itself prove operator misbehavior — the direct path may have recorded a bad hash
    /// while operators signed the correct canonical response. Slashing on this
    /// condition is unsafe. Instead, the function simply invalidates the direct-path
    /// attestation so downstream consumers cannot rely on its tainted hashes, and
    /// marks the task as challenged to prevent replay. Operator slashing for
    /// incorrect responses is handled by `raiseAndResolveChallenge` (and its
    /// cross-chain counterpart), which re-executes the policy and produces a ZK
    /// proof of misbehavior.
    function challengeDirectlyVerifiedMismatch(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse
    ) external onlyTaskManager nonReentrant {
        require(isChallengeEnabled, ChallengeNotEnabled());

        bytes32 taskId = taskResponse.taskId;

        // Prevent repeated invalidation for the same task
        require(!taskSuccesfullyChallenged[taskId], NotChallengable());

        // 1. Verify attestation was directly verified
        require(
            AttestationValidator(attestationValidator).isDirectlyVerified(taskId),
            TaskManagerErrors.NotDirectlyVerified()
        );

        // 2. Time bound: challenge must be within the challenge window.
        // Uses task.taskCreatedBlock as the anchor since the direct path may
        // have been set before the regular path's responseCertificate exists.
        require(
            uint32(block.number) < task.taskCreatedBlock + taskChallengeWindowBlock,
            ChallengePeriodExpired()
        );

        // 3. Bind caller-supplied task to on-chain task hash — prevents crafted
        // tasks with modified fields (e.g., wasmArgs) from forcing a mismatch
        bytes32 regularTaskHash = INewtonProverTaskManager(taskManager).taskHash(taskId);
        require(
            regularTaskHash != bytes32(0) && TaskLib.taskHash(task) == regularTaskHash,
            TaskLib.TaskMismatch(regularTaskHash, TaskLib.taskHash(task))
        );

        // 4. Get direct hashes from AttestationValidator
        bytes32 directTaskHash = AttestationValidator(attestationValidator).directTaskHashes(taskId);
        bytes32 directResponseHash =
            AttestationValidator(attestationValidator).directTaskResponseHashes(taskId);

        // 5. Use the stored normalized response hash from TaskManager
        // instead of recomputing from caller-supplied input. This prevents an attacker
        // from altering attestation fields (zeroed by computeConsensusDigest) to fabricate
        // a mismatch that would otherwise block the invalidation check.
        bytes32 normalizedRegularResponseHash =
            INewtonProverTaskManager(taskManager).normalizedTaskResponseHash(taskId);
        require(normalizedRegularResponseHash != bytes32(0), NotChallengable());

        // 6. Challenge succeeds if EITHER task hash or response hash mismatches
        // (using compatible encodings for the response hash comparison)
        bool taskHashMismatch = directTaskHash != bytes32(0) && directTaskHash != regularTaskHash;
        bool responseHashMismatch =
            directResponseHash != bytes32(0) && directResponseHash != normalizedRegularResponseHash;
        require(taskHashMismatch || responseHashMismatch, ChallengeFailed());

        // 7. Mark challenged and invalidate the tainted direct-path attestation.
        // CEI: record state before the external call.
        taskSuccesfullyChallenged[taskId] = true;
        AttestationValidator(attestationValidator).invalidateAttestation(taskId);

        // Silence unused-variable warning for `taskResponse` while keeping the
        // parameter in the public ABI. `taskResponse.taskId` is used above as `taskId`.
    }
}
