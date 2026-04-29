// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

/// @title IStateRootCommittable
///
/// @notice Interface for the per-chain StateCommitRegistry — exactly one
///         contract per chain anchors a single unified Jellyfish Merkle Tree
///         covering all three private-data namespaces (identity, confidential,
///         secrets) routed internally via leaf_key[0]. See
///         docs/PRIVATE_DATA_STORAGE.md §5, §6.3, §7.1. One commitStateRoot tx
///         lands every 120s per chain and advances the single unified root.
///
/// @dev Phase 1 MVP scope. Spec §7.2 is a clean pre-mainnet cutover: the V1
///      IdentityRegistry, ConfidentialDataRegistry, and SecretsRegistry
///      contracts are deleted in full and their state relocates to JMT leaves
///      under the unified root. The gateway's StateCommitAggregator builds a
///      CommitProposalV1 (off-chain wire format, spec §6.6), operators
///      validate it and BLS-sign keccak256(abi.encode(commit)), and the
///      aggregated certificate is submitted here. Struct layout here is the
///      BLS signing digest's preimage — reorder at your peril.
interface IStateRootCommittable {
    // -------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------

    /// @notice Per-chain state commit proposal carrying the new Merkle root
    ///         and its provenance.
    /// @dev Field order matters. The off-chain CommitProposalV1::commit_digest()
    ///      hashes keccak256(abi.encode(commit)) to derive the BLS signing
    ///      digest, so reordering here silently invalidates every operator
    ///      signature.
    struct StateCommit {
        /// ABI format version for this struct layout. Must equal STATE_COMMIT_V1
        /// (see StateCommitRegistry). Encoded at field position 0 so future-schema
        /// readers can identify the layout before decoding later fields. Bumping
        /// this constant at the registry invalidates old-version commits (no silent
        /// fallback) unless a future phase adds migration or dual-read support.
        /// The version is the only field readers can decode without first agreeing
        /// on the schema; pinning it at the registry freezes the BLS signing-digest
        /// preimage so a bumped constant cannot silently re-interpret prior signed
        /// digests under a new layout.
        uint8 version;
        /// Monotonically increasing sequence number. Must equal prior + 1, or 0 for genesis.
        uint64 sequenceNo;
        /// Merkle root committed in the preceding tx (or 0x00 at genesis).
        bytes32 prevStateRoot;
        /// New Merkle root being committed. Must differ from prevStateRoot.
        bytes32 newStateRoot;
        /// Gateway's block.timestamp at proposal time. Must strictly exceed
        /// the prior commit's timestamp.
        uint64 timestamp;
        /// keccak256 of the EigenDA certificate carrying the delta blob that
        /// produced newStateRoot. Used by the challenger to re-fetch the blob.
        bytes32 daCertHash;
        /// Operator's running enclave PCR0 hash (spec §F.9); MUST be non-zero
        /// (InvalidPcr0Commitment). Off-chain observers cross-check against
        /// EnclaveVersionRegistry.wasPcr0WhitelistedAt(pcr0Commitment, timestamp)
        /// and emit StateTreeAnomalyDetected on mismatch.
        bytes32 pcr0Commitment;
    }

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /// @notice sequenceNo did not equal prior sequenceNo + 1 (or 0 at genesis).
    error SequenceGap(uint64 expected, uint64 got);

    /// @notice prevStateRoot in the proposal did not match the stored root.
    error StateRootMismatch(bytes32 expected, bytes32 got);

    /// @notice timestamp did not strictly exceed the prior commit's timestamp.
    error TimestampRegression(uint64 last, uint64 got);

    /// @notice pcr0Commitment is zero, which would disable challenger
    ///         re-derivation of the active PCR0 whitelist.
    error InvalidPcr0Commitment();

    /// @notice newStateRoot is zero, which cannot represent any legitimate
    ///         JMT root. The empty Jellyfish Merkle Tree hashes to a known
    ///         non-zero placeholder, so a zero newStateRoot is structurally
    ///         malformed input — guarded explicitly to prevent the registry
    ///         from advancing into a sentinel value that downstream consumers
    ///         cannot distinguish from "uninitialized".
    error InvalidNewStateRoot();

    /// @notice The commit's version field did not match the registry's
    ///         expected STATE_COMMIT_V1. Prevents silent decoding of a
    ///         future-schema commit against current-schema slashing
    ///         invariants. Bumping the registry constant requires either
    ///         a migration or explicit dual-read support, never fallback.
    error UnsupportedStateCommitVersion(uint8 expected, uint8 got);

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted on every successful commitStateRoot.
    /// @dev sequenceNo, newStateRoot, and pcr0Commitment are indexed so the
    ///      bootnode can replay per-chain history via eth_getLogs filters
    ///      (spec §7.1).
    event StateRootCommitted(
        uint64 indexed sequenceNo,
        bytes32 prevStateRoot,
        bytes32 indexed newStateRoot,
        uint64 timestamp,
        bytes32 daCertHash,
        bytes32 indexed pcr0Commitment
    );

    // -------------------------------------------------------------------------
    // Mutating Functions
    // -------------------------------------------------------------------------

    /// @notice Commit a new state root.
    /// @dev Validates (sequenceNo, prevStateRoot, timestamp, pcr0Commitment),
    ///      verifies the BLS certificate against the active operator set,
    ///      then persists the new root and emits StateRootCommitted.
    /// @param commit The per-chain state commit proposal.
    /// @param blsCertificate Operator BLS aggregate certificate over
    ///                       keccak256(abi.encode(commit)). Verification is
    ///                       delegated to the ViewBN254CertificateVerifier.
    function commitStateRoot(
        StateCommit calldata commit,
        bytes calldata blsCertificate
    ) external;

    // -------------------------------------------------------------------------
    // View Functions
    // -------------------------------------------------------------------------

    /// @notice The most recently committed Merkle root (0x00 if none).
    function getStateRoot() external view returns (bytes32);

    /// @notice The most recently committed sequence number (0 if none).
    function getSequenceNo() external view returns (uint64);
}
