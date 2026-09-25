// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@eigenlayer/contracts/permissions/Pausable.sol";
import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";
import {BLSSignatureChecker} from "@eigenlayer-middleware/src/BLSSignatureChecker.sol";
import {
    ISlashingRegistryCoordinator
} from "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import "@eigenlayer-middleware/src/libraries/BN254.sol";
import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {AdminMixin} from "../mixins/AdminMixin.sol";

/**
 * @title Unified TaskManagerStorage for both source and destination chains
 * @dev Contains common storage fields for both chain types
 */
abstract contract TaskManagerStorage is
    Initializable,
    AdminMixin,
    Pausable,
    INewtonProverTaskManager
{
    using BN254 for BN254.G1Point;

    /**
     *
     *                            CONSTANTS AND IMMUTABLES
     *
     */

    uint8 public constant PAUSED_CREATE_TASK = 0;
    uint8 public constant PAUSED_RESPOND_TASK = 1;
    uint8 public constant PAUSED_CHALLENGE = 2;
    uint8 public constant PAUSED_ATTESTATION = 3;
    uint8 public constant PAUSED_SLASHING = 4;

    /// @notice The threshold denominator for quorum calculations
    uint256 internal constant _THRESHOLD_DENOMINATOR = 100;

    /// @notice Flag indicating if this is a destination chain contract
    /// @dev Source chains use stake registry verification, destination chains use certificate verification
    bool public immutable isDestinationChain;

    /**
     *
     *                                    STATE
     *
     */

    /// @notice DEPRECATED: Previously used for task sequencing. Do not remove - required for upgrade safety.
    /// @dev This field is kept for storage layout compatibility. Use taskCreatedBlock for ordering.
    /// Replay protection is now handled by taskId uniqueness check in createNewTask.
    uint32 public nonce;

    /// @notice Core entity addresses
    /// @dev For source chains: serviceManager is set to local AVS, certificateVerifier is address(0)
    ///      For destination chains: serviceManager is set to source chain AVS, certificateVerifier is set
    address public serviceManager;
    /// @notice DEPRECATED: Previously used for aggregator access control. Do not remove - required for upgrade safety.
    /// @dev This field is kept for storage layout compatibility. Access control now uses onlyTaskGenerator.
    address public aggregator;
    address public certificateVerifier;

    /// @notice Operator registry contract
    address public operatorRegistry;

    /// @notice Task response handler contract
    /// @dev For source chains: SourceTaskResponseHandler
    ///      For destination chains: DestinationTaskResponseHandler
    address public taskResponseHandler;

    /// @notice taskId => keccak256(TaskLib.taskHash(task))
    mapping(bytes32 => bytes32) public allTaskHashes;

    /// @notice taskId => keccak256(abi.encode(taskResponse, responseCertificate))
    /// @dev Stores the task response bundled with its response certificate. This hash
    ///      is NOT directly comparable to direct-path hashes, which exclude the certificate.
    ///      For mismatch comparisons with direct-path hashes, use `allNormalizedTaskResponses`
    ///      (response-only) via `normalizedTaskResponseHash()`.
    mapping(bytes32 => bytes32) public allTaskResponses;

    /// @notice Challenge verifier contract address
    address public challengeVerifier;

    /// @notice Attestation validator contract address
    address public attestationValidator;

    /// @notice The task response window block
    uint32 public taskResponseWindowBlock;

    /// @notice DEPRECATED: Previously held the epoch length (NEWT-1175 collapses this to a
    ///         single source of truth on `OperatorRegistry`). Do not remove - required for
    ///         upgrade safety. Use the explicit `epochBlocks()` getter below, which delegates
    ///         to `IOperatorRegistry(operatorRegistry).epochDurationBlocks()`.
    /// @dev    `internal` visibility suppresses the auto-generated public getter so the
    ///         delegating function below can take its place without an ABI clash. The 4-byte
    ///         storage slot is preserved at the same offset; `__deprecated_epochBlocks` is
    ///         never read or written after this change.
    uint32 internal __deprecated_epochBlocks;

    /// @notice The maximum allowed age (in blocks) of taskCreatedBlock when creating a task
    /// @dev This limits how far in the past the offchain estimated block can be.
    ///      Default is 2 blocks to allow for minimal transaction propagation delay.
    uint32 public taskCreationBufferWindow;

    /// @notice Minimum compatible factory version (SemVer, e.g., "0.1.0")
    /// @dev Empty string disables enforcement (default after upgrade).
    ///      Used for both policy and policy data factory version checks.
    string public minCompatiblePolicyVersion;

    /// @notice DEPRECATED: Previously separate from minCompatiblePolicyVersion. Do not remove - required for upgrade safety.
    /// @dev This field is kept for storage layout compatibility. Use minCompatiblePolicyVersion for all version checks.
    string public minCompatiblePolicyDataVersion;

    /// @notice Stores keccak256(abi.encode(taskResponse)) for each task (response-only, no certificate)
    /// @dev Used by ChallengeVerifier to bind mismatch comparisons to canonical data
    ///      instead of recomputing from caller-supplied input.
    mapping(bytes32 => bytes32) public allNormalizedTaskResponses;

    /// @notice Stores keccak256(attestation_data) for each task that provided TEE attestation.
    /// @dev For privacy tasks, operators include a Nitro attestation document (~3 KB CBOR)
    ///      with user_data = keccak256(task_id || response_digest). The hash is stored
    ///      on-chain for challenger verification (ChallengeVerifier Type 2). Empty bytes32
    ///      means no attestation was provided — permissible for non-privacy tasks.
    mapping(bytes32 => bytes32) public allTaskAttestations;

    /// @notice The active epoch length, in blocks, of the source-chain operator-set governance cycle.
    /// @dev Delegates to `OperatorRegistry.epochDurationBlocks()` — the single source of truth post
    ///      NEWT-1175. Returning zero means OperatorRegistry has not yet had `OperatorRegistryEpochGovernance.initializeEpochs(uint32)`
    ///      called on it (bootstrap phase). The function is `public` (not `external`) so internal
    ///      Solidity readers (e.g., legacy ABI consumers, future TaskManager logic) can call it
    ///      with the same syntax as the previous public state variable. Satisfies the
    ///      `epochBlocks()` declaration on `INewtonProverTaskManager`.
    function epochBlocks() public view returns (uint32) {
        return IOperatorRegistry(operatorRegistry).epochDurationBlocks();
    }

    // Conditional inheritance based on chain type
    // Source chains extend BLSSignatureChecker for stake registry verification
    // Destination chains do not extend these (they use certificate verification instead)
    modifier onlySourceChain() {
        require(
            !isDestinationChain, "TaskManagerStorage: Operation only available on source chains"
        );
        _;
    }

    constructor(
        IOperatorRegistry _operatorRegistry,
        IPauserRegistry _pauserRegistry,
        bool _isDestinationChain
    ) Pausable(_pauserRegistry) {
        operatorRegistry = address(_operatorRegistry);
        isDestinationChain = _isDestinationChain;
        taskResponseWindowBlock = 30; // default to 30 blocks
        taskCreationBufferWindow = 2; // default to 2 blocks for task creation buffer
        // NOTE: epochBlocks is no longer stored here — it delegates to
        // `IOperatorRegistry(operatorRegistry).epochDurationBlocks()`. See `epochBlocks()` below.
    }

    // storage gap for upgradeability
    // slither-disable-next-line shadowing-state
    uint256[45] private __GAP;
}

/**
 * @title SourceTaskManagerStorage
 * @dev Storage contract for source chains that extends BLSSignatureChecker for BLS signature verification
 */
abstract contract SourceTaskManagerStorage is TaskManagerStorage, BLSSignatureChecker {
    constructor(
        ISlashingRegistryCoordinator _operatorRegistry,
        IPauserRegistry _pauserRegistry
    )
        TaskManagerStorage(IOperatorRegistry(address(_operatorRegistry)), _pauserRegistry, false)
        BLSSignatureChecker(_operatorRegistry)
    {}
}

/**
 * @title DestinationTaskManagerStorage
 * @dev Storage contract for destination chains (no BLSSignatureChecker, uses certificates)
 */
abstract contract DestinationTaskManagerStorage is TaskManagerStorage {
    constructor(
        IOperatorRegistry _operatorRegistry,
        IPauserRegistry _pauserRegistry
    ) TaskManagerStorage(_operatorRegistry, _pauserRegistry, true) {}
}
