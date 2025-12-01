// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {TaskLib} from "../libraries/TaskLib.sol";
import {ChallengeLib} from "../libraries/ChallengeLib.sol";
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

    bool public isChallengeEnabled;
    uint32 public taskChallengeWindowBlock;

    mapping(bytes32 => bool) public taskSuccesfullyChallenged;
    mapping(bytes32 => bytes32) public allTaskHashes;
    mapping(bytes32 => bytes32) public allTaskResponses;

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
        address _regoVerifier
    ) {
        taskManager = _taskManager;
        serviceManager = _serviceManager;
        registryCoordinator = _registryCoordinator;
        blsApkRegistry = _blsApkRegistry;
        allocationManager = _allocationManager;
        instantSlasher = _instantSlasher;
        regoVerifier = _regoVerifier;
    }

    /* INITIALIZER */
    function initialize(
        bool _isChallengeEnabled,
        uint32 _taskChallengeWindowBlock,
        address _owner
    ) public initializer {
        __Ownable_init();
        __ReentrancyGuard_init();
        _transferOwnership(_owner);
        isChallengeEnabled = _isChallengeEnabled;
        taskChallengeWindowBlock = _taskChallengeWindowBlock;
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
            TaskLib.taskHash(task) == allTaskHashes[taskResponse.taskId], TaskLib.TaskMismatch()
        );
        require(
            _isChallengable(task, taskResponse, responseCertificate, challenge), NotChallengable()
        );
        require(
            uint32(block.number) < responseCertificate.referenceBlock + taskChallengeWindowBlock,
            ChallengePeriodExpired()
        );

        INewtonPolicy policy = INewtonPolicy(task.policyTaskData.policyAddress);
        require(policy.isPolicyVerified(), TaskLib.PolicyNotVerified());

        // Verify the rego proof. Reverts if the proof is invalid.
        IRegoVerifier.RegoContext memory context =
            RegoVerifier(regoVerifier).verifyRegoProof(challenge.data, challenge.proof);
        // make sure that proof public values match the task and task response.
        // Circuit also checks if task and task response are correct.
        require(
            TaskLib.taskHash(context.task) == allTaskHashes[taskResponse.taskId],
            TaskLib.TaskMismatch()
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

        // Slash signing operators
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
}
