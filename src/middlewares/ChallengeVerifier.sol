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
import "@openzeppelin-upgrades/contracts/security/ReentrancyGuardUpgradeable.sol";
import {RegoVerifier} from "./RegoVerifier.sol";
import {IRegoVerifier} from "../interfaces/IRegoVerifier.sol";
import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";
import {INewtonPolicyClient} from "../interfaces/INewtonPolicyClient.sol";
import {IIdentityRegistry} from "../interfaces/IIdentityRegistry.sol";
import {IConfidentialDataRegistry} from "../interfaces/IConfidentialDataRegistry.sol";
import {IAttestationProofVerifier} from "../interfaces/IAttestationProofVerifier.sol";
import {INewtonAddressesProvider} from "../interfaces/INewtonAddressesProvider.sol";
import {EnclaveVersionRegistry} from "../core/EnclaveVersionRegistry.sol";
import {IEnclaveVersionRegistry} from "../interfaces/IEnclaveVersionRegistry.sol";
import {AddressesProviderConsumer} from "../mixins/AddressesProviderConsumer.sol";
import {OperatorVerifierLib} from "../libraries/OperatorVerifierLib.sol";
import {
    IBN254CertificateVerifierTypes
} from "@eigenlayer/contracts/interfaces/IBN254CertificateVerifier.sol";
import {AdminMixin} from "../mixins/AdminMixin.sol";

contract ChallengeVerifier is
    Initializable,
    AdminMixin,
    ReentrancyGuardUpgradeable,
    AddressesProviderConsumer
{
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
    /// @notice The task is not a privacy task — TEE attestation challenge not applicable
    error NotPrivacyTask(bytes32 taskId);
    /// @notice Attestation is present — missing-attestation challenge does not apply
    error AttestationNotMissing(bytes32 taskId);
    /// @notice AttestationProofVerifier not configured or proof data empty
    error AttestationProofNotProvided(bytes32 taskId);
    /// @notice BN254CertificateVerifier address has not been configured
    error CertVerifierNotSet();

    /* EVENTS */
    event ChallengeEnabled(bool indexed isChallengeEnabled);
    event DestinationChainRegistered(uint256 indexed chainId, bool indexed registered);
    event CrossChainChallengeRelayed(
        uint256 indexed destChainId, bytes32 indexed taskId, address challenger
    );
    event TeeAttestationChallenged(bytes32 indexed taskId, address challenger);
    event IdentityRegistrySet(address indexed identityRegistry);
    event ConfidentialDataRegistrySet(address indexed confidentialDataRegistry);
    event AttestationProofVerifierSet(address indexed attestationProofVerifier);

    /* STORAGE — source-chain-only immutables (address(0) on dest chains) */
    address public immutable registryCoordinator;
    address public immutable blsApkRegistry;
    address public immutable allocationManager;
    address public immutable instantSlasher;
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

    /// @notice IdentityRegistry address for privacy task detection
    address public identityRegistry;
    /// @notice ConfidentialDataRegistry address for privacy task detection
    address public confidentialDataRegistry;
    /// @notice AttestationProofVerifier for Type 2b challenges (invalid attestation with ZK proof)
    address public attestationProofVerifier;

    uint256[42] private __gap;

    /* MODIFIERS */
    modifier onlyTaskManager() {
        require(msg.sender == taskManager, OnlyTaskManager());
        _;
    }

    /* CONSTRUCTOR */
    constructor(
        INewtonAddressesProvider _provider,
        address _registryCoordinator,
        address _blsApkRegistry,
        address _allocationManager,
        address _instantSlasher,
        address _operatorStateRetriever
    ) AddressesProviderConsumer(_provider) {
        // Source-chain-only deps passed directly (address(0) on dest chains)
        registryCoordinator = _registryCoordinator;
        blsApkRegistry = _blsApkRegistry;
        allocationManager = _allocationManager;
        instantSlasher = _instantSlasher;
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

    function initializeV2(
        address admin
    ) external onlyOwner reinitializer(2) {
        _initializeAdmin(admin);
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

        // Source handler expects NSS, cross-chain relays forward BN254Certificate.
        // Fall through only on format-mismatch; propagate real validation failures.
        bytes32 hashOfNonSigners;
        try ITaskResponseHandler(_taskResponseHandler)
            .verifyTaskResponse(task, taskResponse, signatureData) returns (
            bytes32 h
        ) {
            hashOfNonSigners = h;
        } catch (bytes memory reason) {
            bytes4 selector;
            if (reason.length >= 4) {
                assembly {
                    selector := mload(add(reason, 0x20))
                }
            }
            if (selector != ITaskResponseHandler.InvalidTaskResponse.selector) {
                assembly {
                    revert(add(reason, 0x20), mload(reason))
                }
            }
            if (address(viewBN254CertificateVerifier) == address(0)) revert CertVerifierNotSet();
            IBN254CertificateVerifierTypes.BN254Certificate memory cert =
                abi.decode(signatureData, (IBN254CertificateVerifierTypes.BN254Certificate));
            hashOfNonSigners = OperatorVerifierLib.verifyTaskResponseCertificate(
                task, taskResponse, cert, viewBN254CertificateVerifier, serviceManager
            );
        }

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

    /* ADMIN FUNCTIONS */
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
    ) external onlyAdmin {
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

    /* TEE ATTESTATION CHALLENGE (Type 2) */

    /// @notice Challenge a privacy task response that is missing TEE attestation.
    ///         Anyone can call this (permissionless). If the task is a privacy task
    ///         and allTaskAttestations[taskId] is empty, the response is slashable.
    ///         This is the "missing attestation" case — the simplest slashable condition.
    ///         Handles both missing attestation (no proof needed) and invalid attestation
    ///         (SP1 proof required via AttestationProofVerifier).
    /// @param task The task being challenged
    /// @param taskResponse The task response being challenged
    /// @param responseCertificate The response certificate (for challenge window check)
    /// @param attestationProofData ABI-encoded public values from SP1 attestation circuit (empty for missing attestation)
    /// @param attestationProofBytes SP1 Groth16 proof bytes (empty for missing attestation)
    /// @param pubkeysOfNonSigningOperators BLS G1 pubkeys of non-signing operators
    function challengeInvalidTeeAttestation(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        INewtonProverTaskManager.ResponseCertificate calldata responseCertificate,
        bytes calldata attestationProofData,
        bytes calldata attestationProofBytes,
        BN254.G1Point[] calldata pubkeysOfNonSigningOperators
    ) external nonReentrant {
        require(isChallengeEnabled, ChallengeNotEnabled());
        bytes32 taskId = taskResponse.taskId;

        // 1. Task must exist and not already challenged
        require(
            TaskLib.taskHash(task) == allTaskHashes[taskId],
            TaskLib.TaskMismatch(allTaskHashes[taskId], TaskLib.taskHash(task))
        );
        require(!taskSuccesfullyChallenged[taskId], NotChallengable());

        // 2. Response must match stored hash
        require(
            allTaskResponses[taskId] == keccak256(abi.encode(taskResponse, responseCertificate)),
            NotChallengable()
        );

        // 3. Must be within challenge window
        require(
            uint32(block.number) < responseCertificate.referenceBlock + taskChallengeWindowBlock,
            ChallengePeriodExpired()
        );

        // 4. Verify SP1 proof (proves both privacy classification and attestation validity)
        require(attestationProofVerifier != address(0), AttestationProofNotProvided(taskId));
        require(attestationProofData.length > 0, AttestationProofNotProvided(taskId));

        IAttestationProofVerifier.AttestationContext memory ctx = IAttestationProofVerifier(
                attestationProofVerifier
            ).verifyAttestationProof(attestationProofData, attestationProofBytes);

        // 5. Bind proof outputs to on-chain state
        require(ctx.taskId == taskId, ChallengeFailed());
        require(ctx.responseDigest == keccak256(abi.encode(taskResponse)), ChallengeFailed());

        // 6. Circuit must prove this is a privacy policy (from Rego source scan)
        require(ctx.isPrivacyPolicy, NotPrivacyTask(taskId));

        // 7. Verify policyCodeHash matches on-chain policy.
        //    try/catch guards against malformed policyClient (EOA, non-standard) —
        //    challenger pre-screens off-chain via isPrivacyTask() before proving.
        {
            try INewtonPolicyClient(taskResponse.policyClient).getPolicyAddress() returns (
                address policyAddr
            ) {
                require(
                    ctx.policyCodeHash == INewtonPolicy(policyAddr).getPolicyCodeHash(),
                    ChallengeFailed()
                );
            } catch {
                revert ChallengeFailed();
            }
        }

        // 8. Determine challenge type: missing vs invalid attestation
        bytes32 attestationHash = INewtonProverTaskManager(taskManager).allTaskAttestations(taskId);

        if (attestationHash == bytes32(0)) {
            // Type 2a: Missing attestation — circuit proved this is a privacy policy,
            // and no attestation was submitted. Slash.
        } else {
            // Type 2b: Attestation present but invalid
            require(ctx.attestationHash == attestationHash, ChallengeFailed());
            require(!ctx.isValid, ChallengeFailed());

            // Verify root CA trust anchor matches on-chain registry
            address evr = INewtonAddressesProvider(addressesProvider).getEnclaveVersionRegistry();
            require(
                ctx.rootCertHash == EnclaveVersionRegistry(evr).rootCertHash(), ChallengeFailed()
            );

            // Verify PCR0 is not in the active whitelist (unapproved enclave binary)
            if (ctx.failureReason == 2) {
                require(
                    !IEnclaveVersionRegistry(evr).isActiveVersion(ctx.pcr0Hash), ChallengeFailed()
                );
            }
        }

        // 6. Record challenge success before external calls (CEI)
        taskSuccesfullyChallenged[taskId] = true;
        emit TeeAttestationChallenged(taskId, msg.sender);

        // 7. Slash signing operators (source chain only)
        if (serviceManager != address(0)) {
            (
                bytes32[] memory hashesOfPubkeysOfNonSigningOperators,
                address[] memory addressOfNonSigningOperators
            ) = ChallengeLib.processNonSigners(pubkeysOfNonSigningOperators, blsApkRegistry);

            ChallengeLib.validateSignatoryRecord(
                task.taskCreatedBlock,
                hashesOfPubkeysOfNonSigningOperators,
                responseCertificate.hashOfNonSigners
            );

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
    }

    /// @notice Check whether a policy client's task requires TEE attestation.
    /// @dev Returns true if the policy client has linked identity domains or granted
    ///      confidential data domains (user PII threshold decryption paths).
    ///      Secrets-bearing WASM plugins (secretsSchemaCid) execute in TEE but are
    ///      NOT privacy tasks for on-chain attestation — their attestation is
    ///      verified off-chain by the gateway/operator during Prepare phase.
    ///      Challengers call this off-chain to determine if a task is challengeable
    ///      for missing/invalid attestation before submitting on-chain.
    /// @param policyClient The policy client address from the task response
    function isPrivacyTask(
        address policyClient
    ) public view returns (bool) {
        if (
            identityRegistry != address(0)
                && IIdentityRegistry(identityRegistry).hasLinkedIdentity(policyClient)
        ) {
            return true;
        }
        if (
            confidentialDataRegistry != address(0)
                && IConfidentialDataRegistry(confidentialDataRegistry)
                    .hasGrantedDomains(policyClient)
        ) {
            return true;
        }
        // Note: secretsSchemaCid (WASM plugin secrets like API keys) is NOT a privacy
        // task for attestation purposes. Secrets execute in TEE for confidentiality of
        // the keys, but don't involve user PII threshold decryption. The gateway/operator
        // verifies Prepare-phase TEE attestation off-chain for secrets; on-chain
        // challengeInvalidTeeAttestation only covers identity/confidential/ephemeral.

        // Inline ephemeral privacy (wasmArgs._newton.privacy[]) cannot be checked
        // on-chain cheaply — it requires parsing calldata. Deferred to the challenger
        // off-chain, which submits the challenge only when it detects inline privacy.
        return false;
    }

    /// @notice Set the IdentityRegistry address for privacy task detection
    function setIdentityRegistry(
        address _identityRegistry
    ) external onlyOwner {
        identityRegistry = _identityRegistry;
        emit IdentityRegistrySet(_identityRegistry);
    }

    /// @notice Set the ConfidentialDataRegistry address for privacy task detection
    function setConfidentialDataRegistry(
        address _confidentialDataRegistry
    ) external onlyOwner {
        confidentialDataRegistry = _confidentialDataRegistry;
        emit ConfidentialDataRegistrySet(_confidentialDataRegistry);
    }

    function setAttestationProofVerifier(
        address _attestationProofVerifier
    ) external onlyOwner {
        attestationProofVerifier = _attestationProofVerifier;
        emit AttestationProofVerifierSet(_attestationProofVerifier);
    }
}
