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

    /* EVENTS */
    event ChallengeEnabled(bool indexed isChallengeEnabled);

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

    bool public isChallengeEnabled;
    uint32 public taskChallengeWindowBlock;
    uint32 public taskResponseWindowBlock;

    mapping(bytes32 => bool) public taskSuccesfullyChallenged;
    mapping(bytes32 => bytes32) public allTaskHashes;
    mapping(bytes32 => bytes32) public allTaskResponses;

    uint256[47] private __gap;

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
        address _operatorRegistry
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
        require(
            keccak256(abi.encode(context.taskResponse)) == allTaskResponses[taskResponse.taskId],
            TaskLib.TaskResponseMismatch()
        );
        require(
            keccak256(abi.encode(policy.getEntrypoint()))
                == keccak256(abi.encode(context.entrypoint)),
            TaskLib.EntrypointMismatch()
        );

        bool challengeSuccess = keccak256(abi.encode(context.evaluation))
            != keccak256(abi.encode(taskResponse.evaluationResult));

        require(challengeSuccess, ChallengeFailed());

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
        if (serviceManager != address(0)) {
            ChallengeLib.ChallengeContext memory ctx = ChallengeLib.ChallengeContext({
                blsApkRegistry: blsApkRegistry,
                operatorStateRetriever: taskManager, // task manager is the operator state retriever
                registryCoordinator: registryCoordinator,
                allocationManager: allocationManager,
                instantSlasher: instantSlasher,
                serviceManager: serviceManager
            });

            ChallengeLib.slashSigningOperators(
                ctx, task.quorumNumbers, task.taskCreatedBlock, addressOfNonSigningOperators
            );
        }

        taskSuccesfullyChallenged[taskResponse.taskId] = true;
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

    function challengeDirectlyVerifiedAttestation(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        bytes calldata signatureData,
        address _taskResponseHandler
    ) external onlyTaskManager {
        bytes32 taskId = taskResponse.taskId;

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
                operatorStateRetriever: taskManager,
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

        // Invalidate attestation
        AttestationValidator(attestationValidator).invalidateAttestation(taskId);
    }

    // solhint-disable-next-line function-max-lines
    function challengeDirectlyVerifiedMismatch(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        bytes calldata signatureData,
        address _taskResponseHandler
    ) external onlyTaskManager {
        bytes32 taskId = taskResponse.taskId;

        // 1. Verify attestation was directly verified
        require(
            AttestationValidator(attestationValidator).isDirectlyVerified(taskId),
            TaskManagerErrors.NotDirectlyVerified()
        );

        // 2. Get direct hashes from AttestationValidator
        bytes32 directTaskHash = AttestationValidator(attestationValidator).directTaskHashes(taskId);
        bytes32 directResponseHash =
            AttestationValidator(attestationValidator).directTaskResponseHashes(taskId);

        // 3. Get regular hashes from TaskManager
        bytes32 regularTaskHash = INewtonProverTaskManager(taskManager).taskHash(taskId);
        bytes32 regularResponseHash = INewtonProverTaskManager(taskManager).taskResponseHash(taskId);

        // 4. Regular path must have been completed (both hashes must be non-zero)
        require(
            regularTaskHash != bytes32(0) && regularResponseHash != bytes32(0), NotChallengable()
        );

        // 5. Challenge succeeds if EITHER task hash or response hash mismatches
        bool taskHashMismatch = directTaskHash != bytes32(0) && directTaskHash != regularTaskHash;
        bool responseHashMismatch =
            directResponseHash != bytes32(0) && directResponseHash != regularResponseHash;
        require(taskHashMismatch || responseHashMismatch, ChallengeFailed());

        // 6. Re-verify signatures via task response handler
        ITaskResponseHandler(_taskResponseHandler)
            .verifyTaskResponse(task, taskResponse, signatureData);

        // 7. Slash signing operators (only on source chains where blsApkRegistry is set)
        if (blsApkRegistry != address(0)) {
            IBLSSignatureCheckerTypes.NonSignerStakesAndSignature memory
                nonSignerStakesAndSignature =
                abi.decode(signatureData, (IBLSSignatureCheckerTypes.NonSignerStakesAndSignature));

            (
                bytes32[] memory hashesOfPubkeysOfNonSigningOperators,
                address[] memory addressOfNonSigningOperators
            ) = ChallengeLib.processNonSigners(
                nonSignerStakesAndSignature.nonSignerPubkeys, blsApkRegistry
            );

            ChallengeLib.ChallengeContext memory ctx = ChallengeLib.ChallengeContext({
                blsApkRegistry: blsApkRegistry,
                operatorStateRetriever: taskManager,
                registryCoordinator: registryCoordinator,
                allocationManager: allocationManager,
                instantSlasher: instantSlasher,
                serviceManager: serviceManager
            });

            ChallengeLib.slashSigningOperators(
                ctx, task.quorumNumbers, task.taskCreatedBlock, addressOfNonSigningOperators
            );
        }

        // 8. Mark as challenged and invalidate direct attestation
        taskSuccesfullyChallenged[taskId] = true;
        AttestationValidator(attestationValidator).invalidateAttestation(taskId);
    }
}
