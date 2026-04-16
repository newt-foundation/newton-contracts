// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

/// @title IEpochRegistry
///
/// @notice On-chain registry for privacy epoch lifecycle management. Stores epoch
///         commitments (threshold MPK, operator set hash, threshold parameters) and
///         manages epoch state transitions with grace-period-based expiry.
///
/// @dev The gateway's EpochManager calls registerEpoch after each successful PSS
///      refresh ceremony. The PrivacySlasher references isEpochActive and getEpoch
///      for slashing claim validation.
interface IEpochRegistry {
    // -------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------

    /// @notice Metadata for a single threshold key epoch.
    /// @dev Packed into 3 storage slots:
    ///      slot 0: mpk (bytes32)
    ///      slot 1: operatorSetHash (bytes32)
    ///      slot 2: epochId (uint64) + startBlock (uint64) + threshold (uint8) + committeeSize (uint8)
    struct EpochInfo {
        /// Compressed Edwards Y of the threshold master public key (32 bytes).
        bytes32 mpk;
        /// keccak256(abi.encodePacked(sorted operator addresses)) of the participating set.
        bytes32 operatorSetHash;
        /// Monotonically increasing epoch identifier. First epoch is 0.
        uint64 epochId;
        /// block.number at which this epoch was registered.
        uint64 startBlock;
        /// Threshold (t) — minimum co-signers for threshold decryption.
        uint8 threshold;
        /// Committee size (n) — total operators in this epoch.
        uint8 committeeSize;
    }

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /// @notice Caller is not an authorized task generator.
    error NotTaskGenerator();

    /// @notice Epoch ID is not the expected next value (must be currentEpochId + 1,
    ///         or 0 for the first epoch).
    error InvalidEpochId();

    /// @notice Master public key does not match the existing MPK. PSS refresh and
    ///         resharing must preserve the MPK established at epoch 0.
    error MpkMismatch();

    /// @notice Invalid operator registry address (zero address).
    error InvalidOperatorRegistryAddress();

    /// @notice Threshold must be >= 2 and <= committeeSize.
    error InvalidThreshold();

    /// @notice Committee size must be >= 2.
    error InvalidCommitteeSize();

    /// @notice Master public key must not be zero.
    error InvalidMpk();

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when a new epoch is registered after a PSS refresh or DKG ceremony.
    event EpochRegistered(
        uint64 indexed epochId, bytes32 mpk, uint8 threshold, uint8 committeeSize
    );

    /// @notice Emitted when the admin requests an emergency key rotation.
    event EmergencyRotationTriggered(uint64 indexed epochId, address triggeredBy);

    /// @notice Emitted when the grace period configuration is updated.
    event GracePeriodUpdated(uint256 gracePeriodEpochs);

    /// @notice Emitted when a pending emergency rotation is cleared by a new epoch registration.
    event EmergencyRotationCleared(uint64 indexed epochId);

    // -------------------------------------------------------------------------
    // Task Generator Functions
    // -------------------------------------------------------------------------

    /// @notice Register a new epoch after a successful PSS refresh or DKG ceremony.
    /// @param mpk Compressed Edwards Y of the threshold master public key (32 bytes).
    ///            Must match the MPK established at epoch 1 for all subsequent epochs.
    /// @param operatorSetHash keccak256(abi.encodePacked(sorted operator addresses)).
    /// @param threshold Threshold (t) for this epoch. Must be >= 2 and <= committeeSize.
    /// @param committeeSize Committee size (n). Must be >= 2.
    function registerEpoch(
        bytes32 mpk,
        bytes32 operatorSetHash,
        uint8 threshold,
        uint8 committeeSize
    ) external;

    // -------------------------------------------------------------------------
    // View Functions
    // -------------------------------------------------------------------------

    /// @notice Get the metadata for the current active epoch.
    function getCurrentEpoch() external view returns (EpochInfo memory);

    /// @notice Get the metadata for a specific epoch by ID.
    function getEpoch(
        uint64 epochId
    ) external view returns (EpochInfo memory);

    /// @notice Check whether an epoch is still active (current or within grace period).
    /// @param epochId The epoch to check.
    /// @return True if the epoch is the current epoch or within gracePeriodEpochs of it.
    function isEpochActive(
        uint64 epochId
    ) external view returns (bool);

    /// @notice The current epoch ID.
    function currentEpochId() external view returns (uint64);

    /// @notice Number of past epochs that remain active after a new epoch registers.
    function gracePeriodEpochs() external view returns (uint256);

    /// @notice Whether an emergency rotation has been requested but not yet fulfilled.
    function emergencyRotationRequested() external view returns (bool);

    // -------------------------------------------------------------------------
    // Admin Functions
    // -------------------------------------------------------------------------

    /// @notice Request an emergency key rotation. Emits EmergencyRotationTriggered.
    ///         The gateway watches for this event and triggers an immediate PSS refresh.
    ///         The flag is cleared when the next epoch is registered.
    function triggerEmergencyRotation() external;

    /// @notice Update the number of past epochs that remain active.
    function setGracePeriodEpochs(
        uint256 _gracePeriodEpochs
    ) external;
}
