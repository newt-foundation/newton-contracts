// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IEpochRegistry} from "../interfaces/IEpochRegistry.sol";
import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";

import {Initializable} from "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";

/// @title EpochRegistry
///
/// @notice On-chain registry for privacy epoch lifecycle. Stores epoch commitments
///         (threshold MPK, operator set hash, threshold parameters) registered by
///         the gateway after each PSS refresh ceremony. Manages epoch state
///         transitions with epoch-count-based grace periods.
///
/// @dev Deployed behind a TransparentUpgradeableProxy. The implementation constructor
///      sets immutables and disables initializers. All mutable state is set via
///      initialize().
///
///      Epochs start at ID 1 (not 0), so currentEpochId == 0 unambiguously means
///      "no epochs registered yet."
///
///      Storage layout (per epoch): 3 slots
///        slot 0: mpk (bytes32)
///        slot 1: operatorSetHash (bytes32)
///        slot 2: epochId (uint64) + startBlock (uint64) + threshold (uint8) + committeeSize (uint8)
contract EpochRegistry is Initializable, OwnableUpgradeable, IEpochRegistry {
    // -------------------------------------------------------------------------
    // Immutables
    // -------------------------------------------------------------------------

    /// @notice OperatorRegistry used to validate task generator authorization.
    IOperatorRegistry public immutable operatorRegistry;

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------

    /// @notice Epoch metadata indexed by epoch ID.
    mapping(uint64 => EpochInfo) internal _epochs;

    /// @notice The current (latest) epoch ID. Zero means no epochs registered.
    uint64 public override currentEpochId;

    /// @notice Number of past epochs that remain active after a new epoch registers.
    uint256 public override gracePeriodEpochs;

    /// @notice Whether an emergency rotation has been requested but not yet fulfilled.
    bool public override emergencyRotationRequested;

    // -------------------------------------------------------------------------
    // Constructor (implementation only)
    // -------------------------------------------------------------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        address _operatorRegistry
    ) {
        require(_operatorRegistry != address(0), InvalidOperatorRegistryAddress());
        operatorRegistry = IOperatorRegistry(_operatorRegistry);
        _disableInitializers();
    }

    // -------------------------------------------------------------------------
    // Initializer (proxy)
    // -------------------------------------------------------------------------

    /// @notice Initialize the registry with an owner and default grace period.
    /// @param owner Initial contract owner (typically the deployer or Safe multisig).
    /// @param _gracePeriodEpochs Number of past epochs to keep active (default: 2).
    function initialize(
        address owner,
        uint256 _gracePeriodEpochs
    ) external initializer {
        __Ownable_init();
        _transferOwnership(owner);
        gracePeriodEpochs = _gracePeriodEpochs;
    }

    // -------------------------------------------------------------------------
    // Task Generator Functions
    // -------------------------------------------------------------------------

    /// @inheritdoc IEpochRegistry
    function registerEpoch(
        bytes32 mpk,
        bytes32 operatorSetHash,
        uint8 threshold,
        uint8 committeeSize
    ) external override {
        require(operatorRegistry.isTaskGenerator(msg.sender), NotTaskGenerator());
        require(mpk != bytes32(0), InvalidMpk());
        require(committeeSize >= 2, InvalidCommitteeSize());
        require(threshold >= 2 && threshold <= committeeSize, InvalidThreshold());

        uint64 nextEpochId = currentEpochId + 1;

        // MPK immutability: after the first epoch, MPK must match
        if (currentEpochId > 0) {
            require(mpk == _epochs[currentEpochId].mpk, MpkMismatch());
        }

        _epochs[nextEpochId] = EpochInfo({
            mpk: mpk,
            operatorSetHash: operatorSetHash,
            epochId: nextEpochId,
            startBlock: uint64(block.number),
            threshold: threshold,
            committeeSize: committeeSize
        });
        currentEpochId = nextEpochId;

        if (emergencyRotationRequested) {
            emergencyRotationRequested = false;
            emit EmergencyRotationCleared(nextEpochId);
        }

        emit EpochRegistered(nextEpochId, mpk, threshold, committeeSize);
    }

    // -------------------------------------------------------------------------
    // View Functions
    // -------------------------------------------------------------------------

    /// @inheritdoc IEpochRegistry
    function getCurrentEpoch() external view override returns (EpochInfo memory) {
        return _epochs[currentEpochId];
    }

    /// @inheritdoc IEpochRegistry
    function getEpoch(
        uint64 epochId
    ) external view override returns (EpochInfo memory) {
        return _epochs[epochId];
    }

    /// @inheritdoc IEpochRegistry
    function isEpochActive(
        uint64 epochId
    ) external view override returns (bool) {
        if (currentEpochId == 0) return false;
        if (epochId == 0 || epochId > currentEpochId) return false;
        return currentEpochId - epochId <= gracePeriodEpochs;
    }

    // -------------------------------------------------------------------------
    // Admin Functions
    // -------------------------------------------------------------------------

    /// @inheritdoc IEpochRegistry
    function triggerEmergencyRotation() external override onlyOwner {
        emergencyRotationRequested = true;
        emit EmergencyRotationTriggered(currentEpochId, msg.sender);
    }

    /// @inheritdoc IEpochRegistry
    function setGracePeriodEpochs(
        uint256 _gracePeriodEpochs
    ) external override onlyOwner {
        gracePeriodEpochs = _gracePeriodEpochs;
        emit GracePeriodUpdated(_gracePeriodEpochs);
    }
}
