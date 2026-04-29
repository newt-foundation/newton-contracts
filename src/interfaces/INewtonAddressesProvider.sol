// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

/// @title INewtonAddressesProvider
///
/// @notice On-chain directory for all Newton Protocol contract addresses on a given chain.
///         Single source of truth — operators, challengers, and other contracts discover
///         addresses through this provider instead of relying on off-chain deployment JSONs.
///
/// @dev Modeled after Aave V3's PoolAddressesProvider. Typed getters for core contracts
///      that are always present, plus a generic getAddress(bytes32) for extensibility.
///      Each chain (source and destination) deploys its own provider instance.
///
///      Migration path:
///        Phase 0 — Deploy provider, populate addresses. Rust reads from provider on-chain,
///                  falls back to deployment JSON. Zero contract changes needed.
///        Phase 1 — New contracts take INewtonAddressesProvider in constructor instead of
///                  individual addresses.
///        Phase 2 — On contract upgrades, swap individual immutable refs for provider ref.
interface INewtonAddressesProvider {
    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when any address is updated
    event AddressSet(bytes32 indexed id, address indexed oldAddress, address indexed newAddress);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /// @notice Zero address provided for a required contract
    error ZeroAddress(bytes32 id);

    /// @notice Address has no deployed code
    error NoContractCode(bytes32 id, address addr);

    // -------------------------------------------------------------------------
    // Core protocol — typed getters (always present on every chain)
    // -------------------------------------------------------------------------

    /// @notice Main task lifecycle contract
    function getTaskManager() external view returns (address);

    /// @notice BLS signature verification and challenge resolution
    function getChallengeVerifier() external view returns (address);

    /// @notice Attestation validation for task responses
    function getAttestationValidator() external view returns (address);

    /// @notice Whitelisted operator management and BLS key registry
    function getOperatorRegistry() external view returns (address);

    /// @notice Policy client registration and ERC-165 validation
    function getPolicyClientRegistry() external view returns (address);

    /// @notice High-throughput batched task creation and response
    function getBatchTaskManager() external view returns (address);

    /// @notice EigenLayer AVS entry point
    function getServiceManager() external view returns (address);

    /// @notice Deploys NewtonPolicy instances with version stamping
    function getPolicyFactory() external view returns (address);

    /// @notice Deploys NewtonPolicyData instances with version stamping
    function getPolicyDataFactory() external view returns (address);

    // -------------------------------------------------------------------------
    // Private data storage — typed getters
    // -------------------------------------------------------------------------

    /// @notice Unified per-chain JMT state-root registry for PDS namespaces
    ///         (identity `0x01`, confidential `0x02`, secrets `0x03`). Anchors
    ///         120s BLS-gated `commitStateRoot` and disaster-recovery sealed
    ///         snapshots via `IStateRootCommittable`.
    /// @dev NEWT-1036 — supersedes `IdentityRegistry` and
    ///      `ConfidentialDataRegistry`. Registered so
    ///      `AddressesProviderConsumer`-derived contracts can resolve the
    ///      registry at deploy time rather than constructor-injecting it.
    function getStateCommitRegistry() external view returns (address);

    // -------------------------------------------------------------------------
    // Privacy layer — typed getters (may be address(0) if not deployed)
    // -------------------------------------------------------------------------

    /// @notice Identity data references and policy client linkages
    /// @dev @deprecated NEWT-1036 — scheduled for deletion; identity data relocates
    ///      to the unified `StateCommitRegistry` under namespace `0x01`. Callers
    ///      should migrate to signed-RPC reads against the operator state tree.
    function getIdentityRegistry() external view returns (address);

    /// @notice Provider-managed versioned confidential data with per-client grants
    /// @dev @deprecated NEWT-1036 — scheduled for deletion; confidential data
    ///      relocates to the unified `StateCommitRegistry` under namespace `0x02`.
    ///      Callers should migrate to signed-RPC reads against the operator state tree.
    function getConfidentialDataRegistry() external view returns (address);

    /// @notice Privacy epoch lifecycle and threshold MPK commitments
    function getEpochRegistry() external view returns (address);

    // -------------------------------------------------------------------------
    // TEE layer — typed getters (may be address(0) if not deployed)
    // -------------------------------------------------------------------------

    /// @notice PCR0 whitelist governance for enclave version management
    function getEnclaveVersionRegistry() external view returns (address);

    // -------------------------------------------------------------------------
    // Verification — typed getters
    // -------------------------------------------------------------------------

    /// @notice SP1 Rego policy proof verification
    function getRegoVerifier() external view returns (address);

    /// @notice Stateless BN254 BLS certificate verifier. Used by StateCommitRegistry
    ///         (and other view-call paths) to verify aggregated operator signatures
    ///         without the SSTORE cache that EigenLayer's BN254CertificateVerifier
    ///         uses — making EIP-1271 isValidSignature view-compatible on destination
    ///         chains.
    /// @dev NEWT-1036 forward use — this getter is registered ahead of its main
    ///      consumer (`StateCommitRegistry`, B2 task NEWT-1051) so the consumer can
    ///      resolve the verifier through `AddressesProviderConsumer` at deploy time
    ///      rather than constructor-injecting the address. Populate via
    ///      `setViewBN254CertificateVerifier` on the per-chain provider before any
    ///      mixin consumer is deployed.
    function getViewBN254CertificateVerifier() external view returns (address);

    // -------------------------------------------------------------------------
    // Cross-chain — typed getters (chain-role dependent)
    // -------------------------------------------------------------------------

    /// @notice Operator network address mapping
    function getSocketRegistry() external view returns (address);

    // -------------------------------------------------------------------------
    // Generic — extensible key-value directory
    // -------------------------------------------------------------------------

    /// @notice Look up any contract address by its identifier
    /// @param id keccak256 of the contract name (e.g., keccak256("TASK_MANAGER"))
    /// @return The registered address, or address(0) if not set
    function getAddress(
        bytes32 id
    ) external view returns (address);

    // -------------------------------------------------------------------------
    // Admin — owner-only setters
    // -------------------------------------------------------------------------

    function setTaskManager(
        address addr
    ) external;
    function setChallengeVerifier(
        address addr
    ) external;
    function setAttestationValidator(
        address addr
    ) external;
    function setOperatorRegistry(
        address addr
    ) external;
    function setPolicyClientRegistry(
        address addr
    ) external;
    function setBatchTaskManager(
        address addr
    ) external;
    function setServiceManager(
        address addr
    ) external;
    function setPolicyFactory(
        address addr
    ) external;
    function setPolicyDataFactory(
        address addr
    ) external;
    function setStateCommitRegistry(
        address addr
    ) external;
    /// @dev @deprecated NEWT-1036 — see `getIdentityRegistry` deprecation note.
    function setIdentityRegistry(
        address addr
    ) external;
    /// @dev @deprecated NEWT-1036 — see `getConfidentialDataRegistry` deprecation note.
    function setConfidentialDataRegistry(
        address addr
    ) external;
    function setEpochRegistry(
        address addr
    ) external;
    function setEnclaveVersionRegistry(
        address addr
    ) external;
    function setSocketRegistry(
        address addr
    ) external;
    function setRegoVerifier(
        address addr
    ) external;
    function setViewBN254CertificateVerifier(
        address addr
    ) external;

    /// @notice Register any address by its identifier
    /// @param id keccak256 of the contract name
    /// @param addr The contract address (validated for deployed code)
    function setAddress(
        bytes32 id,
        address addr
    ) external;
}
