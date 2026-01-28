// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@eigenlayer/contracts/permissions/Pausable.sol";
import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";
import {OperatorStateRetriever} from "@eigenlayer-middleware/src/OperatorStateRetriever.sol";
import {BLSSignatureChecker} from "@eigenlayer-middleware/src/BLSSignatureChecker.sol";
import {
    ISlashingRegistryCoordinator
} from "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import "@eigenlayer-middleware/src/libraries/BN254.sol";
import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";

/**
 * @title Unified TaskManagerStorage for both source and destination chains
 * @dev Contains common storage fields for both chain types
 */
abstract contract TaskManagerStorage is
    Initializable,
    OwnableUpgradeable,
    Pausable,
    INewtonProverTaskManager
{
    using BN254 for BN254.G1Point;

    /**
     *
     *                            CONSTANTS AND IMMUTABLES
     *
     */

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

    /// @notice Task-related mappings
    mapping(bytes32 => bytes32) public allTaskHashes;
    mapping(bytes32 => bytes32) public allTaskResponses;

    /// @notice Challenge verifier contract address
    address public challengeVerifier;

    /// @notice Attestation validator contract address
    address public attestationValidator;

    /// @notice The task response window block
    uint32 public taskResponseWindowBlock;

    /// @notice The epoch time in number of blocks
    uint32 public epochBlocks;

    // Conditional inheritance based on chain type
    // Source chains extend BLSSignatureChecker and OperatorStateRetriever for stake registry verification
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
        epochBlocks = 7200; // default to 7200 blocks (matches current hardcoded value)
    }

    // storage gap for upgradeability
    // slither-disable-next-line shadowing-state
    uint256[50] private __GAP;
}

/**
 * @title SourceTaskManagerStorage
 * @dev Storage contract for source chains that extends BLSSignatureChecker for BLS signature verification
 */
abstract contract SourceTaskManagerStorage is
    TaskManagerStorage,
    BLSSignatureChecker,
    OperatorStateRetriever
{
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
