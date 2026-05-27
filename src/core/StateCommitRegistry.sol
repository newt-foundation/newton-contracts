// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {IStateRootCommittable} from "../interfaces/IStateRootCommittable.sol";
import {INewtonAddressesProvider} from "../interfaces/INewtonAddressesProvider.sol";
import {AddressesProviderConsumer} from "../mixins/AddressesProviderConsumer.sol";
import {IViewBN254CertificateVerifier} from "../interfaces/IViewBN254CertificateVerifier.sol";
import {
    IBN254CertificateVerifierTypes
} from "@eigenlayer/contracts/interfaces/IBN254CertificateVerifier.sol";
import {OperatorSet} from "@eigenlayer/contracts/libraries/OperatorSetLib.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @notice Unified state-commit registry for all PDS namespaces (identity, confidential, secrets).
/// One instance per chain — accepts one BLS-certified commit per 120s per chain, covering all
/// three logical namespaces under one unified JMT root (spec §6.3, §7.1).
/// @dev `Ownable` is inherited for future proxy-admin wiring; no function currently uses
/// `onlyOwner`. DR injection is gated by `SNAPSHOT_INJECTOR_ROLE` via AccessControl, so
/// proxy-upgrade authority can rotate independently from snapshot-injection authority.
contract StateCommitRegistry is
    IStateRootCommittable,
    AddressesProviderConsumer,
    Ownable,
    AccessControl
{
    /// @notice Operator set ID used for BLS certificate verification.
    /// Fixed at zero for Phase 1 MVP per spec §R.5 — NOT admin-settable; a mis-set value would
    /// permit a rogue set to commit state roots, bypassing slashing. Future phases may introduce
    /// per-namespace operator sets via a different interface.
    uint32 public constant OPERATOR_SET_ID = 0;

    uint16 public constant BPS_DENOMINATOR = 10000;

    /// @notice Minimum signed-stake quorum (basis points) required per strategy for state commits.
    /// Configurable via `setMinQuorumBps` to avoid requiring a contract upgrade for tuning.
    uint16 public stateCommitMinQuorumBps;

    /// @notice Current StateCommit struct version the registry will accept. Bumped in
    /// lockstep with any change to the StateCommit layout; old versions become immediately
    /// invalid (no dual-read) unless a future phase adds migration machinery. Freezes the
    /// preimage schema of the BLS signing digest — operators signed
    /// keccak256(abi.encode(commit)) under this layout, so any schema change without a
    /// version bump would silently re-interpret prior signed digests.
    uint8 public constant STATE_COMMIT_V1 = 1;

    /// @notice Role granted to the address(es) authorized to inject sealed disaster-recovery
    /// snapshots via `injectSealedSnapshot` (spec NEWT-1078). Operationally distinct from
    /// `owner()` so snapshot-injection authority can rotate without touching proxy-upgrade
    /// authority. Grant via `grantRole` post-deploy.
    bytes32 public constant SNAPSHOT_INJECTOR_ROLE = keccak256("SNAPSHOT_INJECTOR_ROLE");

    /// @notice Raised when the provided quorum BPS is out of the valid range (1–10000).
    error InvalidQuorumBps(uint16 provided);

    /// @notice Raised when the signed-stake array is empty (no strategies returned from cert verification).
    error EmptySignedStakes();

    /// @notice Raised when the signed-stake array length does not match the total weights array.
    error ArrayLenMismatch();

    /// @notice Raised when a strategy's signed stake does not meet the minimum quorum threshold.
    error InsufficientQuorum(uint256 strategyIndex, uint256 signedStake, uint256 requiredStake);

    /// @notice Raised when a strategy reports zero total weight, which would make quorum vacuous.
    error ZeroTotalWeight(uint256 strategyIndex);

    /// @notice Raised when `injectSealedSnapshot` receives a malformed `snapshotRef` or
    /// empty `signature` payload (NEWT-1078). Distinct from `InvalidPcr0Commitment`.
    error InvalidSealedSnapshot();

    /// @notice The BLS certificate's `messageHash` does not equal the computed
    /// `keccak256(abi.encode(c))` of the StateCommit. Without this binding the
    /// verifier would accept a cert that was validly signed over a different
    /// digest (same operator set, same stake weights) — silently committing a
    /// StateCommit nobody actually signed. The certificate authenticates
    /// "operators agreed to commit X"; binding it to the exact bytes-level
    /// digest of the on-chain `StateCommit` ensures X cannot be substituted
    /// for any other proposal those signatures were not built against
    /// (spec §6.3).
    error CertificateMessageHashMismatch(bytes32 expected, bytes32 actual);

    /// @dev Storage slots for the interface-defined accessors. The auto-generated
    /// getter is named `currentStateRoot()` / `currentSequenceNo()`, which does NOT
    /// match the interface's `getStateRoot()` / `getSequenceNo()` names — so no
    /// `override` clause here. The explicit override lives on the function wrappers
    /// below (`getStateRoot`, `getSequenceNo`).
    bytes32 public currentStateRoot;
    uint64 public currentSequenceNo;
    uint64 public lastCommitTimestamp;

    /// @notice Distinct tracking slots for the latest sealed-snapshot injection (spec §S.19, §7.1).
    /// These are NOT overwritten by regular `commitStateRoot` calls, so replicas can detect
    /// whether the live root descends from a disaster-recovery anchor and reconcile accordingly.
    /// Auto-exposed as view functions via `public` visibility: `latestSnapshotRoot()`,
    /// `latestSnapshotSeq()`, `latestSnapshotTimestamp()`.
    bytes32 public latestSnapshotRoot;
    uint64 public latestSnapshotSeq;
    uint64 public latestSnapshotTimestamp;

    /// @dev Emits the keccak256 digest of the `snapshotRef` payload (NEWT-1078). The full
    /// manifest (seq/root/timestamp) is reconciled by indexers via post-injection view calls
    /// (`latestSnapshotRoot()`, `latestSnapshotSeq()`, `latestSnapshotTimestamp()`).
    event SealedSnapshotInjected(bytes32 indexed snapshotRefDigest);

    /// @dev Emitted when admin updates the minimum quorum threshold. Security-critical
    /// parameter — off-chain monitoring tracks this to detect unauthorized weakening of
    /// state-commit quorum enforcement.
    event MinQuorumBpsUpdated(uint16 oldBps, uint16 newBps);

    /// @dev OpenZeppelin v4 (bundled by eigenlayer-middleware) `Ownable` has a zero-arg
    /// constructor that auto-transfers ownership to `msg.sender` — do NOT invoke it with
    /// an argument here or Solidity will raise "Wrong argument count for modifier invocation".
    constructor(
        address addressesProvider,
        address initialSnapshotInjector,
        uint16 initialMinQuorumBps
    ) AddressesProviderConsumer(INewtonAddressesProvider(addressesProvider)) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        if (initialSnapshotInjector != address(0)) {
            _grantRole(SNAPSHOT_INJECTOR_ROLE, initialSnapshotInjector);
        }
        if (initialMinQuorumBps == 0 || initialMinQuorumBps > BPS_DENOMINATOR) {
            revert InvalidQuorumBps(initialMinQuorumBps);
        }
        stateCommitMinQuorumBps = initialMinQuorumBps;
    }

    function commitStateRoot(
        StateCommit calldata c,
        bytes calldata blsCertificate
    ) external override {
        require(
            c.version == STATE_COMMIT_V1, UnsupportedStateCommitVersion(STATE_COMMIT_V1, c.version)
        );
        require(c.pcr0Commitment != bytes32(0), InvalidPcr0Commitment());
        require(c.newStateRoot != bytes32(0), InvalidNewStateRoot());
        require(
            c.sequenceNo == currentSequenceNo + 1, SequenceGap(currentSequenceNo + 1, c.sequenceNo)
        );
        require(
            c.prevStateRoot == currentStateRoot,
            StateRootMismatch(currentStateRoot, c.prevStateRoot)
        );
        require(
            c.timestamp > lastCommitTimestamp, TimestampRegression(lastCommitTimestamp, c.timestamp)
        );

        bytes32 messageHash = keccak256(abi.encode(c));

        // Decode the BLS certificate into its typed form. The cert carries its own
        // `messageHash` field — we bind it to our computed hash below so the caller
        // cannot reuse a valid cert from a different message.
        IBN254CertificateVerifierTypes.BN254Certificate memory cert =
            abi.decode(blsCertificate, (IBN254CertificateVerifierTypes.BN254Certificate));

        require(
            cert.messageHash == messageHash,
            CertificateMessageHashMismatch(messageHash, cert.messageHash)
        );

        // Compose the operator set for verification. `serviceManager` comes from the
        // `AddressesProviderConsumer` mixin and is the AVS address for this chain.
        OperatorSet memory operatorSet = OperatorSet({avs: serviceManager, id: OPERATOR_SET_ID});

        uint256[] memory signedStakes =
            viewBN254CertificateVerifier.verifyCertificate(operatorSet, cert);
        IBN254CertificateVerifierTypes.BN254OperatorSetInfo memory info =
            viewBN254CertificateVerifier.getOperatorSetInfo(operatorSet, cert.referenceTimestamp);

        uint256 signedStakeLen = signedStakes.length;
        uint256 totalWeightsLen = info.totalWeights.length;
        require(signedStakeLen > 0, EmptySignedStakes());
        require(signedStakeLen == totalWeightsLen, ArrayLenMismatch());

        for (uint256 i = 0; i < signedStakeLen; ++i) {
            uint256 totalWeight = info.totalWeights[i];
            require(totalWeight > 0, ZeroTotalWeight(i));
            uint256 requiredStake = totalWeight * uint256(stateCommitMinQuorumBps);
            require(
                signedStakes[i] * uint256(BPS_DENOMINATOR) >= requiredStake,
                InsufficientQuorum(i, signedStakes[i] * BPS_DENOMINATOR, requiredStake)
            );
        }

        currentStateRoot = c.newStateRoot;
        currentSequenceNo = c.sequenceNo;
        lastCommitTimestamp = c.timestamp;

        emit StateRootCommitted(
            c.sequenceNo,
            c.prevStateRoot,
            c.newStateRoot,
            c.timestamp,
            c.daCertHash,
            c.pcr0Commitment
        );
    }

    function getStateRoot() external view override returns (bytes32) {
        return currentStateRoot;
    }

    function getSequenceNo() external view override returns (uint64) {
        return currentSequenceNo;
    }

    /// @notice Returns the unix timestamp after which operator-specific fragments become
    /// GC-eligible (spec §S.14, §7.1). Reads from EigenLayer delegation / withdrawal state.
    /// Phase 1 MVP stub — always returns uint64.max (no operator eligible for GC).
    /// TODO: wire to DelegationManager withdrawal completion + grace period.
    function gc_eligible_after(
        address /* operator */
    ) external pure returns (uint64) {
        return type(uint64).max;
    }

    /// @notice Update the minimum quorum threshold (basis points) for state commits.
    function setMinQuorumBps(
        uint16 newMinQuorumBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newMinQuorumBps == 0 || newMinQuorumBps > BPS_DENOMINATOR) {
            revert InvalidQuorumBps(newMinQuorumBps);
        }
        uint16 oldMinQuorumBps = stateCommitMinQuorumBps;
        stateCommitMinQuorumBps = newMinQuorumBps;
        emit MinQuorumBpsUpdated(oldMinQuorumBps, newMinQuorumBps);
    }

    /// @notice Admin escape hatch for disaster recovery (spec §S.19, §7.1, NEWT-1078). Injects a
    /// multi-sig-attested state snapshot, bypassing the normal sequence continuity check. Use
    /// only when the live replica has diverged from ground truth and a coordinated re-anchor
    /// is required.
    /// @dev Access is role-gated by `SNAPSHOT_INJECTOR_ROLE` (operationally distinct from
    ///      `owner()`). `snapshotRef` carries an abi-encoded `StateCommit` in Phase 1 MVP —
    ///      future phases may substitute a content-addressed pointer (digest/CID) referencing
    ///      an off-chain manifest with richer metadata. `signature` is an N-of-M trusted-signer
    ///      attestation over `keccak256(snapshotRef)`; full verification is stubbed for Phase 1
    ///      MVP (accepts non-empty signature) and lands with operational rollout.
    function injectSealedSnapshot(
        bytes calldata snapshotRef,
        bytes calldata signature
    ) external onlyRole(SNAPSHOT_INJECTOR_ROLE) {
        if (signature.length == 0) {
            revert InvalidSealedSnapshot();
        }
        // Phase 1 MVP: snapshotRef is abi.encode(StateCommit). A malformed payload reverts
        // inside the ABI coder, which is acceptable for the MVP stub. Implementation detail
        // for NEWT-1078 landing: if the test matrix requires a typed revert, wrap in a
        // try/catch and rethrow InvalidSealedSnapshot.
        StateCommit memory snapshot = abi.decode(snapshotRef, (StateCommit));
        if (snapshot.version != STATE_COMMIT_V1) {
            revert UnsupportedStateCommitVersion(STATE_COMMIT_V1, snapshot.version);
        }
        if (snapshot.pcr0Commitment == bytes32(0)) {
            revert InvalidPcr0Commitment();
        }
        if (snapshot.newStateRoot == bytes32(0)) {
            revert InvalidNewStateRoot();
        }

        currentStateRoot = snapshot.newStateRoot;
        currentSequenceNo = snapshot.sequenceNo;
        lastCommitTimestamp = snapshot.timestamp;
        latestSnapshotRoot = snapshot.newStateRoot;
        latestSnapshotSeq = snapshot.sequenceNo;
        latestSnapshotTimestamp = snapshot.timestamp;

        emit SealedSnapshotInjected(keccak256(snapshotRef));
    }
}
