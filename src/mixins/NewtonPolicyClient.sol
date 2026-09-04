// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {INewtonPolicyClient} from "../interfaces/INewtonPolicyClient.sol";
import {ISemVerMixin} from "../interfaces/ISemVerMixin.sol";
import {SemVerMixin} from "./SemVerMixin.sol";
import {NewtonPolicy} from "../core/NewtonPolicy.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";
import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";
import {VersionLib} from "../libraries/VersionLib.sol";
import {PROTOCOL_VERSION} from "../libraries/ProtocolVersion.sol";

abstract contract NewtonPolicyClient is INewtonPolicyClient, SemVerMixin {
    /// @notice Stamps the implementation with the protocol version it was compiled
    ///         against so inheriting clients (e.g. vaults) expose `version()`. This
    ///         lets off-chain tooling detect a client/protocol version drift; a
    ///         client built before this change reverts on `version()`, which is
    ///         itself the drift signal. No constructor argument, so existing
    ///         inheritors require no change.
    constructor() SemVerMixin(PROTOCOL_VERSION) {}

    /// @notice Function to check if a contract implements an interface
    /// @param interfaceId The interface identifier to check
    /// @return True if the contract implements the interface, false otherwise
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId // 0x01ffc9a7
            || interfaceId == type(INewtonPolicyClient).interfaceId;
    }

    // error for when a call is made by an account other than the owner
    error OnlyPolicyClientOwner();

    // error for when policy address has not been set yet
    error PolicyNotSet();

    // error for when the policy factory version is incompatible
    error IncompatiblePolicyVersion(string actual, string minimum);

    // error for when a bound client with a non-zero rebindDelay uses an immediate setter
    error RebindRequiresTimelock();

    // error for when no update is queued
    error NoPendingUpdate();

    // error for when the queued update has not reached executableFrom yet
    error UpdateNotMatured(uint64 executableFrom);

    // error for when the queued update passed expiresAt
    error UpdateExpired(uint64 expiresAt);

    // error for when the execute arguments do not match what was queued
    error UpdateMismatch();

    // error for when an update is already queued
    error UpdateAlreadyPending(bytes32 pendingHash);

    /// @notice Emitted when a policy rebind is queued.
    /// @param newPolicy The policy address that will be bound at execute.
    /// @param pendingHash Commitment to the queued update.
    /// @param executableFrom Timestamp the queued rebind becomes executable.
    /// @param expiresAt Timestamp it stops being executable; 0 when it never expires.
    /// @param config The policy config that will be applied at execute.
    event PolicyRebindQueued(
        address indexed newPolicy,
        bytes32 indexed pendingHash,
        uint64 executableFrom,
        uint64 expiresAt,
        INewtonPolicy.PolicyConfig config
    );

    /// @notice Emitted when an update to `rebindDelay` is queued.
    /// @param pendingHash Commitment to the queued update.
    /// @param newDelay The delay that will be written at execute.
    /// @param executableFrom Timestamp the queued update becomes executable.
    /// @param expiresAt Timestamp it stops being executable; 0 when it never expires.
    event RebindDelayUpdateQueued(
        bytes32 indexed pendingHash, uint64 newDelay, uint64 executableFrom, uint64 expiresAt
    );

    /// @notice Emitted when an update to `rebindGracePeriod` is queued.
    /// @param pendingHash Commitment to the queued update.
    /// @param newGracePeriod The grace period that will be written at execute.
    /// @param executableFrom Timestamp the queued update becomes executable.
    /// @param expiresAt Timestamp it stops being executable; 0 when it never expires.
    event RebindGracePeriodUpdateQueued(
        bytes32 indexed pendingHash, uint64 newGracePeriod, uint64 executableFrom, uint64 expiresAt
    );

    /// @notice Emitted when a queued update is cancelled.
    /// @param pendingHash The commitment that was cancelled.
    event PendingUpdateCancelled(bytes32 indexed pendingHash);

    /// @notice Emitted when `rebindDelay` changes.
    /// @param previousDelay The delay before this write.
    /// @param newDelay The delay after this write.
    event RebindDelaySet(uint64 previousDelay, uint64 newDelay);

    /// @notice Emitted when `rebindGracePeriod` changes.
    /// @param previousGracePeriod The grace period before this write.
    /// @param newGracePeriod The grace period after this write.
    event RebindGracePeriodSet(uint64 previousGracePeriod, uint64 newGracePeriod);

    /// @notice Emitted whenever the bound policy ADDRESS ($.policy) is written -
    ///         the init/birth bind and any later rebind, including a re-set to the
    ///         same value (emit-on-write, not emit-on-change) - so an indexer can
    ///         reconstruct a client's full policy-address history from events alone.
    /// @param previousPolicy The policy address before this write (address(0) at birth).
    /// @param newPolicy The policy address after this write.
    event PolicyAddressUpdated(address indexed previousPolicy, address indexed newPolicy);

    /// @notice Emitted whenever the bound policy ID ($.policyId) is written, via
    ///         setPolicy (including a re-set to the same value, emit-on-write) or
    ///         via a policy-address rotation clearing it back to zero (see
    ///         `_setPolicyAddress`).
    /// @param policy The policy contract the id was set on ($.policy at call time).
    /// @param policyId The new policyId -- `NewtonPolicy.setPolicy`'s return value,
    ///        or `bytes32(0)` when cleared by a policy-address rotation.
    event PolicyIdUpdated(address indexed policy, bytes32 indexed policyId);

    // modifier to restrict functions to only the owner
    modifier onlyPolicyClientOwner() {
        require(
            msg.sender == _getNewtonPolicyClientStorage().policyClientOwner, OnlyPolicyClientOwner()
        );
        _;
    }

    /// @notice Struct to contain stateful values for NewtonPolicyClient-type contracts
    /// @custom:storage-location erc7201:newton.storage.NewtonPolicyClient
    struct NewtonPolicyClientStorage {
        INewtonProverTaskManager policyTaskManager;
        address policy;
        bytes32 policyId;
        address policyClientOwner;
        uint64 rebindDelay;
        uint64 rebindGracePeriod;
        mapping(UpdateKind => PendingUpdate) pendingUpdates;
    }

    /// @notice A single queued update. One entry is held per UpdateKind, so a rebind, a
    ///         delay update and a grace-period update can be in flight at the same time.
    struct PendingUpdate {
        uint64 executableFrom;
        uint64 expiresAt;
        bytes32 pendingHash;
    }

    /// @notice Enum used for hashing queued updates
    enum UpdateKind {
        None,
        Rebind,
        SetDelay,
        SetGracePeriod
    }

    /// @notice EIP-1967 proxy storage slot for the NewtonPolicyClientStorage struct
    /// @dev keccak256(abi.encode(uint256(keccak256("newton.storage.NewtonPolicyClient")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _NEWTON_POLICY_CLIENT_STORAGE_SLOT =
        0xaa6954ac1e404d8f79e6eba698b90c3c7071936d683ce65dd13ddf463ffbcb00;

    function _getNewtonPolicyClientStorage()
        private
        pure
        returns (NewtonPolicyClientStorage storage $)
    {
        assembly {
            $.slot := _NEWTON_POLICY_CLIENT_STORAGE_SLOT
        }
    }

    function _initNewtonPolicyClient(
        address policyTaskManager,
        address policyClientOwner
    ) internal {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        $.policyTaskManager = INewtonProverTaskManager(policyTaskManager);
        $.policyClientOwner = policyClientOwner;
    }

    /**
     * @notice Only callable by the owner. Used for external policy configuration.
     * @param policyClientOwner The new policy client owner.
     */
    function setPolicyClientOwner(
        address policyClientOwner
    ) public onlyPolicyClientOwner {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        $.policyClientOwner = policyClientOwner;
    }

    /**
     * @notice Internal setter for the policy contract address.
     * @dev Writes then emits, with NO version gate: the TaskManager version check
     *      lives in the public `setPolicyAddress` wrapper, not here. Callers that bind
     *      the policy directly (e.g. an initializer) therefore emit PolicyAddressUpdated
     *      without a version check - the event is still truthful (the address was
     *      bound); an incompatible initial policy simply fails later at task creation.
     * @param policy The address of the NewtonPolicy contract.
     * @dev Clears the cached `$.policyId` back to zero whenever `policy` actually changes.
     *      `$.policyId` is only ever refreshed by `_setPolicy` (a separate call), so without
     *      this, rotating `$.policy` alone would leave `$.policyId` pointing at the OLD
     *      policy's id -- every attestation/task-response check that compares against
     *      `getPolicyId()` (`TaskLib.sanityCheckAttestation`, `_validateAttestation`,
     *      `_validateAttestationDirect`, `AttestationValidator.validateAttestationDirect`/
     *      `isAttestationDirectValid`) would then keep accepting stale, already-evaluated
     *      credentials issued under the old policy until they naturally expire, instead of
     *      requiring a fresh `_setPolicy` under the new one first.
     */
    function _setPolicyAddress(
        address policy
    ) internal {
        _requireImmediateChangeAllowed();
        _writePolicyAddress(policy);
    }

    /**
     * @notice The unguarded write behind `_setPolicyAddress`.
     * @param policy The address of the NewtonPolicy contract.
     * @dev `private`, so an inheritor cannot reach it and the timelock cannot be routed
     *      around; `executeRebind` is the only other caller.
     */
    function _writePolicyAddress(
        address policy
    ) private {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        address previous = $.policy;
        $.policy = policy;
        if (previous != policy) {
            $.policyId = bytes32(0);
            emit PolicyIdUpdated(policy, bytes32(0));
        }
        emit PolicyAddressUpdated(previous, policy);
    }

    /**
     * @notice Gates the immediate, non-queued policy writes.
     * @dev Permitted while the client is unbound -- `policyId == 0`, the birth window --
     *      or while `rebindDelay == 0`, meaning this client has not adopted the timelock.
     *      Keyed on `policyId` rather than `policy` because binding is a two-transaction
     *      operation downstream: an initializer sets the address, and the config arrives
     *      in a later transaction. Keying on `policy` would reject that second call.
     *
     *      This is safe only because `executeRebind` applies both writes in ONE
     *      transaction, so `policyId == 0` is never observable between transactions after
     *      birth. A bare address change therefore cannot be used to manufacture the birth
     *      window and then set arbitrary params for free.
     */
    function _requireImmediateChangeAllowed() private view {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        require($.policyId == bytes32(0) || $.rebindDelay == 0, RebindRequiresTimelock());
    }

    /**
     * @notice Runtime version gate, shared by the immediate setter and by queue/execute.
     * @param policy The address of the NewtonPolicy contract to check.
     * @dev Reads the minimum from the TaskManager, which is mutable and authoritative.
     */
    function _checkPolicyVersion(
        address policy
    ) private view {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        address taskManager = address($.policyTaskManager);
        if (taskManager == address(0)) {
            return;
        }
        address factory = INewtonPolicy(policy).factory();
        string memory factoryVersion = ISemVerMixin(factory).version();
        string memory tmMinVersion =
            INewtonProverTaskManager(taskManager).minCompatiblePolicyVersion();
        if (bytes(tmMinVersion).length > 0) {
            require(
                VersionLib.isCompatible(factoryVersion, tmMinVersion),
                IncompatiblePolicyVersion(factoryVersion, tmMinVersion)
            );
        }
    }

    /**
     * @notice Only callable by the owner. Sets the policy contract address for deferred setup.
     * @param policy The address of the NewtonPolicy contract.
     * @dev Validates that the policy's factory version is compatible with the TaskManager's
     *      minimum required policy version. This is a runtime check (not compile-time) so that
     *      existing policy clients can upgrade to newer policy versions without redeployment.
     *      The TaskManager gate is the authoritative version check, matching the canonical
     *      check_compatibility() logic used by newton-cli.
     */
    function setPolicyAddress(
        address policy
    ) public onlyPolicyClientOwner {
        // Runtime version check: read minimum from TaskManager (mutable, authoritative)
        // Fails fast at configuration time rather than at task creation time
        _checkPolicyVersion(policy);
        _setPolicyAddress(policy);
    }

    /**
     * @notice Sets a policy for the calling address to the policyID from on chain.
     * @param policyConfig The policy configuration.
     * @return policyId The policyID associated with the calling address.
     * @dev This function enables clients to define execution rules or parameters for tasks they submit.
     *      The policy governs how tasks submitted by the caller are executed, ensuring compliance with predefined rules.
     */
    function _setPolicy(
        INewtonPolicy.PolicyConfig memory policyConfig
    ) internal returns (bytes32) {
        _requireImmediateChangeAllowed();
        return _writePolicy(policyConfig);
    }

    /**
     * @notice The unguarded write behind `_setPolicy`.
     * @param policyConfig The policy configuration.
     * @return policyId The policyID associated with the calling address.
     * @dev `private` for the same reason as `_writePolicyAddress`.
     */
    function _writePolicy(
        INewtonPolicy.PolicyConfig memory policyConfig
    ) private returns (bytes32) {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        require($.policy != address(0), PolicyNotSet());
        bytes32 policyId = NewtonPolicy($.policy).setPolicy(policyConfig);
        $.policyId = policyId;
        emit PolicyIdUpdated($.policy, policyId);
        return policyId;
    }

    /**
     * @notice Same as _setPolicy, but only callable by the owner. Used for external policy configuration.
     * @param policyConfig The policy configuration.
     * @return policyId The policyID associated with the calling address.
     */
    function setPolicy(
        INewtonPolicy.PolicyConfig memory policyConfig
    ) external onlyPolicyClientOwner returns (bytes32) {
        return _setPolicy(policyConfig);
    }

    function getPolicyAddress() external view returns (address) {
        return _getPolicyAddress();
    }

    function _getPolicyAddress() internal view returns (address) {
        return _getNewtonPolicyClientStorage().policy;
    }

    function getPolicyConfig() external view returns (INewtonPolicy.PolicyConfig memory) {
        return _getPolicyConfig();
    }

    function _getPolicyConfig() internal view returns (INewtonPolicy.PolicyConfig memory) {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        require($.policy != address(0), PolicyNotSet());
        return NewtonPolicy($.policy).getPolicyConfig(_getPolicyId());
    }

    function getPolicyId() external view returns (bytes32) {
        return _getPolicyId();
    }

    function _getPolicyId() internal view returns (bytes32) {
        return _getNewtonPolicyClientStorage().policyId;
    }

    function getNewtonPolicyTaskManager() external view returns (address) {
        return _getNewtonPolicyTaskManager();
    }

    function _getNewtonPolicyTaskManager() internal view returns (address) {
        return address(_getNewtonPolicyClientStorage().policyTaskManager);
    }

    function getOwner() external view returns (address) {
        return _getOwner();
    }

    function _getOwner() internal view returns (address) {
        return _getNewtonPolicyClientStorage().policyClientOwner;
    }

    /* REBIND TIMELOCK */

    /**
     * @notice Returns the seconds a queued update must wait before it may execute.
     * @return The configured rebind delay. Zero is legal and means no delay.
     * @dev Public and unauthenticated by design: the exit window a client actually
     *      offers must be readable on chain, including when it is zero.
     */
    function rebindDelay() external view returns (uint64) {
        return _getNewtonPolicyClientStorage().rebindDelay;
    }

    /**
     * @notice Returns the seconds a matured update stays executable.
     * @return The configured grace period. Zero means a matured update never expires.
     */
    function rebindGracePeriod() external view returns (uint64) {
        return _getNewtonPolicyClientStorage().rebindGracePeriod;
    }

    /**
     * @notice Returns the update queued for a given kind, if any.
     * @param kind Which kind of update to read.
     * @return pendingHash Commitment to the queued update; zero when nothing is queued.
     * @return executableFrom Timestamp it becomes executable.
     * @return expiresAt Timestamp it stops being executable; zero when it never expires.
     */
    function pendingUpdate(
        UpdateKind kind
    ) external view returns (bytes32 pendingHash, uint64 executableFrom, uint64 expiresAt) {
        PendingUpdate storage p = _getNewtonPolicyClientStorage().pendingUpdates[kind];
        return (p.pendingHash, p.executableFrom, p.expiresAt);
    }

    /**
     * @notice Only callable by the owner. Queues any kind of timelocked update.
     * @param kind Which kind of update to queue.
     * @param payload The ABI-encoded arguments for that kind: `(address policy,
     *        INewtonPolicy.PolicyConfig config)` for a rebind, `(uint64)` for a delay or
     *        grace-period update. `encodeRebind` and `encodeValue` build these.
     * @return executableFrom Timestamp the queued update becomes executable.
     * @dev One entry point rather than one per kind, so the commitment rule is written
     *      once: the hash covers `(kind, payload)`, which is exactly what execute must
     *      supply again. Reverts when an update is already queued -- use `cancelUpdate`
     *      or `replaceUpdate`, so queueing can never silently discard an entry the caller
     *      did not know about.
     *
     *      For a rebind the address and config are committed TOGETHER and applied in one
     *      transaction. Queueing them separately would let an owner serve the delay for
     *      the address, land it, and then set an arbitrary config for free -- `policyParams`
     *      being precisely the permissive knob. The resulting policyId is not committed:
     *      `NewtonPolicy.setPolicy` derives it from `block.timestamp` among other inputs,
     *      so the queue commits the INPUTS.
     */
    function queueUpdate(
        UpdateKind kind,
        bytes calldata payload
    ) external onlyPolicyClientOwner returns (uint64 executableFrom) {
        return _queue(kind, payload);
    }

    /**
     * @notice Only callable by the owner. Executes a matured update of any kind.
     * @param kind Which kind of update to execute; must match what was queued.
     * @param payload The ABI-encoded arguments, byte-identical to what was queued.
     * @return policyId The policyID minted under the newly bound policy for a rebind, and
     *         `bytes32(0)` for a delay or grace-period update.
     * @dev A rebind applies the policy address and config in a single transaction. Its
     *      version gate runs again here because this is the authoritative check: a policy
     *      compatible at queue time may have been made incompatible since by a
     *      `minCompatiblePolicyVersion()` bump.
     */
    function executeUpdate(
        UpdateKind kind,
        bytes calldata payload
    ) external onlyPolicyClientOwner returns (bytes32 policyId) {
        _consume(kind, _updateHash(kind, payload));

        if (kind == UpdateKind.Rebind) {
            (address policy, INewtonPolicy.PolicyConfig memory config) =
                abi.decode(payload, (address, INewtonPolicy.PolicyConfig));
            _checkPolicyVersion(policy);
            _writePolicyAddress(policy);
            return _writePolicy(config);
        }

        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        uint64 value = abi.decode(payload, (uint64));
        if (kind == UpdateKind.SetDelay) {
            uint64 previous = $.rebindDelay;
            if (previous != value) {
                $.rebindDelay = value;
                emit RebindDelaySet(previous, value);
            }
        } else {
            uint64 previous = $.rebindGracePeriod;
            if (previous != value) {
                $.rebindGracePeriod = value;
                emit RebindGracePeriodSet(previous, value);
            }
        }
        return bytes32(0);
    }

    /**
     * @notice Only callable by the owner. Cancels any queued update and queues a new one in
     *         its place, in one transaction.
     * @param kind Which kind of update to queue.
     * @param payload The ABI-encoded arguments for that kind.
     * @return executableFrom Timestamp the queued update becomes executable.
     * @dev The explicit form of what `queueUpdate` refuses to do implicitly. The
     *      replacement acts only on the entry for `kind`, so replacing a queued delay
     *      update never disturbs a pending rebind. It serves a FULL delay computed from
     *      this proposal and never inherits the superseded entry's elapsed time. Queues
     *      normally when nothing of that kind is pending.
     */
    function replaceUpdate(
        UpdateKind kind,
        bytes calldata payload
    ) external onlyPolicyClientOwner returns (uint64 executableFrom) {
        PendingUpdate storage p = _getNewtonPolicyClientStorage().pendingUpdates[kind];
        if (p.pendingHash != bytes32(0)) {
            _cancelPending(p);
        }
        return _queue(kind, payload);
    }

    /**
     * @notice Only callable by the owner. Clears the update queued for a given kind.
     * @param kind Which kind of update to cancel.
     * @dev Works before maturity, after it, and after expiry. Reverts when nothing of that
     *      kind is queued so a scripted cancel cannot silently no-op. Leaves the other
     *      kinds' entries untouched.
     */
    function cancelUpdate(
        UpdateKind kind
    ) external onlyPolicyClientOwner {
        PendingUpdate storage p = _getNewtonPolicyClientStorage().pendingUpdates[kind];
        require(p.pendingHash != bytes32(0), NoPendingUpdate());
        _cancelPending(p);
    }

    /**
     * @notice Builds the payload for a rebind update.
     * @param policy The address of the NewtonPolicy contract to bind at execute.
     * @param policyConfig The policy configuration to apply at execute.
     * @return The ABI-encoded payload for `UpdateKind.Rebind`.
     */
    function encodeRebind(
        address policy,
        INewtonPolicy.PolicyConfig calldata policyConfig
    ) external pure returns (bytes memory) {
        return abi.encode(policy, policyConfig);
    }

    /**
     * @notice Builds the payload for a delay or grace-period update.
     * @param value The new delay or grace period, in seconds.
     * @return The ABI-encoded payload for `UpdateKind.SetDelay` or `UpdateKind.SetGracePeriod`.
     */
    function encodeValue(
        uint64 value
    ) external pure returns (bytes memory) {
        return abi.encode(value);
    }

    /**
     * @notice Writes the pending entry and announces it.
     * @param kind Which kind of update is being queued.
     * @param payload The ABI-encoded arguments for that kind.
     * @return executableFrom Timestamp the queued update becomes executable.
     * @dev One entry per kind, so the three kinds can be in flight in parallel; a second
     *      update of the SAME kind is refused. Both timestamps are computed from the delay
     *      and grace period in force NOW, so a replacement always serves a full, current
     *      window and never inherits or partially credits the superseded entry's elapsed
     *      time -- and an already-queued entry keeps its own window even if the delay or
     *      grace period is later updated. The payload is decoded here only to emit a typed
     *      event; the commitment is over the raw `(kind, payload)`.
     */
    function _queue(
        UpdateKind kind,
        bytes calldata payload
    ) private returns (uint64 executableFrom) {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        PendingUpdate storage p = $.pendingUpdates[kind];
        require(p.pendingHash == bytes32(0), UpdateAlreadyPending(p.pendingHash));

        bytes32 updateHash = _updateHash(kind, payload);
        executableFrom = uint64(block.timestamp) + $.rebindDelay;
        uint64 expiresAt = $.rebindGracePeriod == 0 ? 0 : executableFrom + $.rebindGracePeriod;

        p.pendingHash = updateHash;
        p.executableFrom = executableFrom;
        p.expiresAt = expiresAt;

        if (kind == UpdateKind.Rebind) {
            (address policy, INewtonPolicy.PolicyConfig memory config) =
                abi.decode(payload, (address, INewtonPolicy.PolicyConfig));
            // Fails fast for the operator; re-checked authoritatively at execute.
            _checkPolicyVersion(policy);
            emit PolicyRebindQueued(policy, updateHash, executableFrom, expiresAt, config);
        } else if (kind == UpdateKind.SetDelay) {
            emit RebindDelayUpdateQueued(
                updateHash, abi.decode(payload, (uint64)), executableFrom, expiresAt
            );
        } else if (kind == UpdateKind.SetGracePeriod) {
            emit RebindGracePeriodUpdateQueued(
                updateHash, abi.decode(payload, (uint64)), executableFrom, expiresAt
            );
        } else {
            revert UpdateMismatch();
        }
    }

    /**
     * @notice Validates a matured, matching entry for one kind and clears it.
     * @param kind Which kind of update is being executed.
     * @param updateHash Commitment to the update being executed, its kind included.
     * @dev Cleared BEFORE the caller makes any external call, so a reentrant policy cannot
     *      replay a matured entry. Identity is checked before timing, deliberately:
     *      executing a superseded or wrong-kind entry would otherwise report
     *      `UpdateNotMatured` against the timestamp of whatever else happens to be queued,
     *      an error about a different update than the caller asked for.
     */
    function _consume(
        UpdateKind kind,
        bytes32 updateHash
    ) private {
        PendingUpdate storage p = _getNewtonPolicyClientStorage().pendingUpdates[kind];
        uint64 executableFrom = p.executableFrom;
        require(executableFrom != 0, NoPendingUpdate());
        require(p.pendingHash == updateHash, UpdateMismatch());
        require(block.timestamp >= executableFrom, UpdateNotMatured(executableFrom));
        uint64 expiresAt = p.expiresAt;
        require(expiresAt == 0 || block.timestamp <= expiresAt, UpdateExpired(expiresAt));
        _clearPending(p);
    }

    /**
     * @notice Clears the pending entry and announces the withdrawal.
     * @param p The queued entry.
     * @dev Announcing matters on a replace: a watcher tracking the superseded entry learns
     *      it was withdrawn in the same transaction it learns what replaced it.
     */
    function _cancelPending(
        PendingUpdate storage p
    ) private {
        emit PendingUpdateCancelled(p.pendingHash);
        _clearPending(p);
    }

    /**
     * @notice Clears the pending entry without emitting.
     * @param p The queued entry.
     * @dev Callers that need an event emit it themselves: `cancel()` announces a
     *      withdrawal, while an execute is already recorded by its own `PolicyIdUpdated`,
     *      `RebindDelaySet` or `RebindGracePeriodSet` event.
     */
    function _clearPending(
        PendingUpdate storage p
    ) private {
        p.pendingHash = bytes32(0);
        p.executableFrom = 0;
        p.expiresAt = 0;
    }

    /**
     * @notice Computes the commitment for a queued update.
     * @param kind Which kind of update this is.
     * @param payload The ABI-encoded arguments for that kind.
     * @return The commitment, with the update kind bound into the preimage so an entry can
     *         only ever be executed by the kind that queued it.
     */
    function _updateHash(
        UpdateKind kind,
        bytes calldata payload
    ) private pure returns (bytes32) {
        return keccak256(abi.encode(kind, payload));
    }

    /**
     * @notice Validates the transaction by checking the policy evaluation task response.
     * @param attestation the attestation to validate
     * @return true if the attestation is valid, false otherwise
     * @dev This function validates the attestation by checking the policy ID and the intent sender.
     *      NOTE: Attestation is valid if the policy ID matches and the intent sender is the caller.
     *      If either of the conditions is not met, the function reverts with an Unauthorized error.
     */
    function _validateAttestation(
        NewtonMessage.Attestation memory attestation
    ) internal returns (bool) {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        require(
            attestation.policyId == $.policyId,
            NewtonMessage.Unauthorized("Policy ID does not match")
        );
        require(
            attestation.intent.from == msg.sender,
            NewtonMessage.Unauthorized("Not authorized intent sender")
        );
        require(
            attestation.intent.chainId == block.chainid,
            NewtonMessage.Unauthorized("Chain ID does not match")
        );
        return $.policyTaskManager.validateAttestation(attestation);
    }

    /**
     * @notice Validates an attestation directly by verifying signatures without waiting for respondToTask.
     * @param task the task to validate
     * @param taskResponse the task response containing policy evaluation result
     * @param signatureData ABI-encoded signature data (NonSignerStakesAndSignature or BN254Certificate)
     * @return true if the attestation is valid, false otherwise
     * @dev This function validates the attestation directly by checking the policy ID, intent sender, chain ID,
     *      and verifying signatures on-chain. Use this when you need immediate validation without waiting
     *      for the aggregator to call respondToTask.
     */
    function _validateAttestationDirect(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        bytes calldata signatureData
    ) internal returns (bool) {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        require(
            taskResponse.policyId == $.policyId,
            NewtonMessage.Unauthorized("Policy ID does not match")
        );
        require(
            taskResponse.intent.from == msg.sender,
            NewtonMessage.Unauthorized("Not authorized intent sender")
        );
        require(
            taskResponse.intent.chainId == block.chainid,
            NewtonMessage.Unauthorized("Chain ID does not match")
        );
        return $.policyTaskManager.validateAttestationDirect(task, taskResponse, signatureData);
    }
}
