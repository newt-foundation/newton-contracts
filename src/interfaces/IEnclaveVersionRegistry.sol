// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

/// @title IEnclaveVersionRegistry
/// @notice On-chain registry for whitelisted Nitro Enclave image measurements (PCR0 hashes).
///         Operators must run an enclave whose PCR0 matches a whitelisted version.
///         The SP1 attestation circuit (NEWT-994, future work) will use this registry as a public input.
interface IEnclaveVersionRegistry {
    /// @notice An enclave version entry (pcr0Hash is the mapping key, not stored in the struct)
    struct EnclaveVersion {
        /// Block number when this version was activated
        uint64 activatedAt;
        /// Block number when this version was deprecated (0 if still active)
        uint64 deprecatedAt;
        /// Human-readable label (e.g., "v0.3.0", "v0.3.1-hotfix")
        string label;
    }

    // Events

    /// @notice Emitted when a new enclave version is whitelisted
    event EnclaveVersionActivated(bytes32 indexed pcr0Hash, string label);

    /// @notice Emitted when an enclave version is deprecated
    event EnclaveVersionDeprecated(bytes32 indexed pcr0Hash);

    // Errors

    /// @notice The PCR0 hash is already registered
    error VersionAlreadyRegistered(bytes32 pcr0Hash);

    /// @notice The PCR0 hash is not registered
    error VersionNotRegistered(bytes32 pcr0Hash);

    /// @notice The PCR0 hash is already deprecated
    error VersionAlreadyDeprecated(bytes32 pcr0Hash);

    /// @notice Zero bytes32 is not a valid PCR0 hash
    error InvalidPcr0Hash();

    /// @notice Caller is not a task generator
    error NotTaskGenerator();

    /// @notice Zero address is not a valid operator
    error InvalidOperator();

    /// @notice Zero bytes32 is not a valid enclave pubkey
    error InvalidPubkey();

    /// @notice Emitted when an operator's enclave ephemeral pubkey is registered
    event EnclaveKeyRegistered(address indexed operator, bytes32 pubkey);

    // Functions

    /// @notice Register an operator's enclave ephemeral X25519 public key.
    ///         Called by the gateway (task generator) after verifying the operator's
    ///         attestation document off-chain. Ephemeral because Nitro Enclaves have
    ///         no persistent storage — key is regenerated on every enclave boot.
    ///         Provides forward secrecy: old encrypted partial DH blobs become
    ///         undecryptable after reboot.
    /// @param operator The operator address whose enclave pubkey is being registered
    /// @param pubkey The enclave's ephemeral X25519 public key (32 bytes)
    function registerEnclaveKey(
        address operator,
        bytes32 pubkey
    ) external;

    /// @notice Get an operator's registered enclave ephemeral public key.
    /// @param operator The operator address
    /// @return The enclave pubkey (bytes32(0) if not registered)
    function getEnclaveKey(
        address operator
    ) external view returns (bytes32);

    /// @notice Register a new whitelisted enclave version.
    ///         Only callable by task generators (gateway operators).
    /// @param pcr0Hash keccak256 of the 48-byte SHA-384 PCR0 measurement
    /// @param label Human-readable version label
    function activateVersion(
        bytes32 pcr0Hash,
        string calldata label
    ) external;

    /// @notice Deprecate an enclave version. Operators running this version
    ///         must upgrade within the grace window or their attestations
    ///         will be rejected.
    /// @param pcr0Hash keccak256 of the PCR0 to deprecate
    function deprecateVersion(
        bytes32 pcr0Hash
    ) external;

    /// @notice Check whether a PCR0 hash is currently whitelisted (active, not deprecated).
    /// @param pcr0Hash keccak256 of the PCR0 to check
    /// @return True if the version is active
    function isActiveVersion(
        bytes32 pcr0Hash
    ) external view returns (bool);

    /// @notice Return the full version entry for a PCR0 hash.
    /// @param pcr0Hash keccak256 of the PCR0 to look up
    /// @return The EnclaveVersion struct
    function getVersion(
        bytes32 pcr0Hash
    ) external view returns (EnclaveVersion memory);

    /// @notice Return the number of currently active (non-deprecated) versions.
    /// @return Count of active versions
    function activeVersionCount() external view returns (uint256);
}
