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

    /// @notice A bound client with a non-zero `rebindDelay` must route changes through
    ///         queue/execute; the immediate setters are unavailable to it.
    error RebindRequiresTimelock();

    /// @notice No update is queued.
    error NoPendingUpdate();

    /// @notice The queued update has not reached `executableFrom` yet.
    error UpdateNotMatured(uint64 executableFrom);

    /// @notice The queued update passed `expiresAt` and must be re-queued.
    error UpdateExpired(uint64 expiresAt);

    /// @notice The arguments supplied to execute do not match what was queued -- a
    ///         different value, or the wrong kind of change entirely.
    error UpdateMismatch();

    /// @notice The kind of change a queued entry represents. Encoded into `pendingHash`
    ///         so an entry can only ever be executed by the call that queued it.
    enum UpdateKind {
        None,
        Rebind,
        SetDelay,
        SetGracePeriod
    }

    /// @notice Emitted when a policy rebind is queued. Carries the FULL `PolicyConfig`,
    ///         not just its hash: advance notice is the point, so a watcher must be able
    ///         to simulate exactly what will land from the event alone.
    event PolicyRebindQueued(
        address indexed newPolicy,
        bytes32 indexed pendingHash,
        uint64 executableFrom,
        uint64 expiresAt,
        INewtonPolicy.PolicyConfig config
    );

    /// @notice Emitted when a change to `rebindDelay` is queued.
    event RebindDelayUpdateQueued(
        bytes32 indexed pendingHash, uint64 newDelay, uint64 executableFrom, uint64 expiresAt
    );

    /// @notice Emitted when a change to `rebindGracePeriod` is queued.
    event RebindGracePeriodUpdateQueued(
        bytes32 indexed pendingHash, uint64 newGracePeriod, uint64 executableFrom, uint64 expiresAt
    );

    /// @notice Emitted when a queued update is cleared -- explicitly via `cancel()`, or
    ///         implicitly because a new queue call replaced it.
    event PendingUpdateCancelled(bytes32 indexed pendingHash);

    /// @notice Emitted when `rebindDelay` actually changes.
    event RebindDelaySet(uint64 previousDelay, uint64 newDelay);

    /// @notice Emitted when `rebindGracePeriod` actually changes.
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
    /// @dev The trailing five fields are appended by the rebind timelock. Appending is
    ///      safe: this struct lives in a dedicated ERC-7201 namespaced region, so no
    ///      inheritor's layout shifts and no `__gap` is required. The four `uint64`s
    ///      pack into a single slot; `pendingHash` takes the next.
    struct NewtonPolicyClientStorage {
        INewtonProverTaskManager policyTaskManager;
        address policy;
        bytes32 policyId;
        address policyClientOwner;
        // ---- rebind timelock ----
        /// @dev Seconds a queued update must wait. 0 is legal and means "no delay",
        ///      reproducing the pre-timelock behaviour exactly.
        uint64 rebindDelay;
        /// @dev Seconds a matured change stays executable. 0 means "never expires".
        uint64 rebindGracePeriod;
        /// @dev Timestamp the queued update becomes executable. 0 => nothing queued.
        uint64 executableFrom;
        /// @dev Timestamp the queued update stops being executable. 0 => no expiry.
        ///      Captured at queue time from the grace period then in force, so a later
        ///      grace-period change never retroactively moves an existing entry.
        uint64 expiresAt;
        /// @dev Commitment to the queued update, its kind included. 0 => nothing queued.
        bytes32 pendingHash;
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

    /// @dev The unguarded write. `private`, so an inheritor cannot reach it and the
    ///      timelock cannot be routed around; `executeRebind` is the only other caller.
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

    /// @notice Gate on the immediate (non-queued) policy writes.
    /// @dev Permitted while the client is unbound -- `policyId == 0`, the birth window --
    ///      or while `rebindDelay == 0`, meaning this client has not adopted the timelock.
    ///      Keyed on `policyId` rather than `policy` because binding is a two-transaction
    ///      operation downstream: an initializer sets the address, and the config arrives
    ///      in a later transaction. Keying on `policy` would reject that second call.
    ///
    ///      This is safe only because `executeRebind` applies both writes in ONE
    ///      transaction: `policyId == 0` is therefore never observable between
    ///      transactions after birth, so a bare address change cannot be used to
    ///      manufacture the birth window and then set arbitrary params for free.
    function _requireImmediateChangeAllowed() private view {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        require(
            $.policyId == bytes32(0) || $.rebindDelay == 0, RebindRequiresTimelock()
        );
    }

    /// @dev Runtime version gate, shared by the immediate setter and by queue/execute.
    ///      Read from the TaskManager, which is mutable and authoritative.
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

    /// @dev The unguarded write. `private` for the same reason as `_writePolicyAddress`.
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

    /* ------------------------------------------------------------------ *
     *                          REBIND TIMELOCK                            *
     *                                                                     *
     * Changing which policy governs a client is otherwise the fastest     *
     * privileged path in the system. These functions put a queue -> delay *
     * -> execute cycle in front of it, sealed at the internal writes so   *
     * an inheritor cannot expose a faster path.                           *
     *                                                                     *
     * `rebindDelay` and `rebindGracePeriod` are themselves governed the   *
     * same way: a change to either is queued and serves the delay and     *
     * grace period in force at the time it was proposed. There is no      *
     * immediate setter for either, in both directions -- an asymmetric    *
     * rule would let a compromised owner raise the delay to years in one  *
     * transaction and freeze the client, including the change needed to   *
     * undo it.                                                            *
     *                                                                     *
     * Only one change may be queued at a time. Queueing while another is  *
     * pending cancels it first, and the replacement serves a FULL delay   *
     * computed from its own proposal -- it never inherits or partially    *
     * credits the superseded entry's elapsed time.                        *
     * ------------------------------------------------------------------ */

    /// @notice The seconds a queued update must wait before it may execute.
    /// @dev Public and unauthenticated by design: the exit window a client actually
    ///      offers must be readable on-chain, including when it is zero.
    function rebindDelay() external view returns (uint64) {
        return _getNewtonPolicyClientStorage().rebindDelay;
    }

    /// @notice The seconds a matured change stays executable. 0 means it never expires.
    function rebindGracePeriod() external view returns (uint64) {
        return _getNewtonPolicyClientStorage().rebindGracePeriod;
    }

    /// @notice The currently queued update, if any.
    /// @return pendingHash Commitment to the queued update; 0 when nothing is queued.
    /// @return executableFrom Timestamp it becomes executable.
    /// @return expiresAt Timestamp it stops being executable; 0 when it never expires.
    function pendingUpdate()
        external
        view
        returns (bytes32 pendingHash, uint64 executableFrom, uint64 expiresAt)
    {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        return ($.pendingHash, $.executableFrom, $.expiresAt);
    }

    /// @notice Queue a rebind of the policy address and its config together.
    /// @dev Address and config are committed as ONE hash and applied in ONE transaction
    ///      at execute. Queueing them separately would let an owner serve the delay for
    ///      the address, land it, and then set arbitrary params for free -- `policyParams`
    ///      being precisely the permissive knob.
    /// @return executableFrom Timestamp the queued rebind becomes executable.
    function queueRebind(
        address policy,
        INewtonPolicy.PolicyConfig calldata policyConfig
    ) external onlyPolicyClientOwner returns (uint64 executableFrom) {
        // Fail fast for the operator; re-checked authoritatively at execute.
        _checkPolicyVersion(policy);
        return _queue(_rebindHash(policy, policyConfig), UpdateKind.Rebind, policy, policyConfig, 0);
    }

    /// @notice Execute a matured rebind. Applies address and config in one transaction.
    /// @return policyId The fresh policyId minted under the newly bound policy.
    function executeRebind(
        address policy,
        INewtonPolicy.PolicyConfig calldata policyConfig
    ) external onlyPolicyClientOwner returns (bytes32 policyId) {
        _consume(_rebindHash(policy, policyConfig));
        // Authoritative version gate: a policy compatible at queue time may not be now.
        _checkPolicyVersion(policy);
        _writePolicyAddress(policy);
        return _writePolicy(policyConfig);
    }

    /// @notice Queue a change to `rebindDelay`, in either direction.
    /// @return executableFrom Timestamp the queued update becomes executable.
    function queueRebindDelay(
        uint64 newDelay
    ) external onlyPolicyClientOwner returns (uint64 executableFrom) {
        return _queue(
            _valueHash(UpdateKind.SetDelay, newDelay),
            UpdateKind.SetDelay,
            address(0),
            _emptyConfig(),
            newDelay
        );
    }

    /// @notice Execute a matured change to `rebindDelay`.
    function executeRebindDelay(
        uint64 newDelay
    ) external onlyPolicyClientOwner {
        _consume(_valueHash(UpdateKind.SetDelay, newDelay));
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        uint64 previous = $.rebindDelay;
        if (previous != newDelay) {
            $.rebindDelay = newDelay;
            emit RebindDelaySet(previous, newDelay);
        }
    }

    /// @notice Queue a change to `rebindGracePeriod`, in either direction.
    /// @return executableFrom Timestamp the queued update becomes executable.
    function queueRebindGracePeriod(
        uint64 newGracePeriod
    ) external onlyPolicyClientOwner returns (uint64 executableFrom) {
        return _queue(
            _valueHash(UpdateKind.SetGracePeriod, newGracePeriod),
            UpdateKind.SetGracePeriod,
            address(0),
            _emptyConfig(),
            newGracePeriod
        );
    }

    /// @notice Execute a matured change to `rebindGracePeriod`.
    function executeRebindGracePeriod(
        uint64 newGracePeriod
    ) external onlyPolicyClientOwner {
        _consume(_valueHash(UpdateKind.SetGracePeriod, newGracePeriod));
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        uint64 previous = $.rebindGracePeriod;
        if (previous != newGracePeriod) {
            $.rebindGracePeriod = newGracePeriod;
            emit RebindGracePeriodSet(previous, newGracePeriod);
        }
    }

    /// @notice Clear the queued update, whatever kind it is.
    /// @dev Works before maturity, after it, and after expiry. Reverts when nothing is
    ///      queued, so a scripted cancel cannot silently no-op.
    function cancel() external onlyPolicyClientOwner {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        bytes32 pendingHash = $.pendingHash;
        require(pendingHash != bytes32(0), NoPendingUpdate());
        emit PendingUpdateCancelled(pendingHash);
        _clearPending($);
    }

    /* ----------------------------- internals ---------------------------- */

    /// @dev Writes the pending entry, cancelling and announcing any entry it replaces.
    ///      `executableFrom` and `expiresAt` are both computed from the delay and grace
    ///      period in force NOW, so a replacement always serves a full, current window.
    function _queue(
        bytes32 updateHash,
        UpdateKind kind,
        address policy,
        INewtonPolicy.PolicyConfig memory policyConfig,
        uint64 value
    ) private returns (uint64 executableFrom) {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();

        // Replace == cancel + queue, announced as both so a watcher tracking the
        // superseded entry learns it was withdrawn in the same transaction.
        if ($.pendingHash != bytes32(0)) {
            emit PendingUpdateCancelled($.pendingHash);
        }

        executableFrom = uint64(block.timestamp) + $.rebindDelay;
        uint64 expiresAt =
            $.rebindGracePeriod == 0 ? 0 : executableFrom + $.rebindGracePeriod;

        $.pendingHash = updateHash;
        $.executableFrom = executableFrom;
        $.expiresAt = expiresAt;

        if (kind == UpdateKind.Rebind) {
            emit PolicyRebindQueued(policy, updateHash, executableFrom, expiresAt, policyConfig);
        } else if (kind == UpdateKind.SetDelay) {
            emit RebindDelayUpdateQueued(updateHash, value, executableFrom, expiresAt);
        } else {
            emit RebindGracePeriodUpdateQueued(updateHash, value, executableFrom, expiresAt);
        }
    }

    /// @dev Validates a matured, matching entry and clears it. Cleared BEFORE any caller
    ///      makes an external call, so a reentrant policy cannot replay the entry.
    function _consume(
        bytes32 updateHash
    ) private {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        uint64 executableFrom = $.executableFrom;
        require(executableFrom != 0, NoPendingUpdate());
        // Identity is checked BEFORE timing, deliberately. Executing a superseded or
        // wrong-kind entry otherwise reports UpdateNotMatured against the timestamp of
        // whatever else happens to be queued -- an error about a different change than
        // the caller asked for. A hash mismatch also covers the wrong KIND, since the
        // kind is part of every preimage.
        require($.pendingHash == updateHash, UpdateMismatch());
        require(block.timestamp >= executableFrom, UpdateNotMatured(executableFrom));
        uint64 expiresAt = $.expiresAt;
        require(expiresAt == 0 || block.timestamp <= expiresAt, UpdateExpired(expiresAt));
        _clearPending($);
    }

    /// @dev Silent clear. Callers that need an event emit it themselves -- `cancel()`
    ///      announces a withdrawal, while an execute is already recorded by its own
    ///      `PolicyIdUpdated` / `RebindDelaySet` / `RebindGracePeriodSet` event.
    function _clearPending(
        NewtonPolicyClientStorage storage $
    ) private {
        $.pendingHash = bytes32(0);
        $.executableFrom = 0;
        $.expiresAt = 0;
    }

    /// @dev The resulting policyId cannot be committed: `NewtonPolicy.setPolicy` derives
    ///      it from `block.timestamp` among other inputs. The queue commits the INPUTS.
    function _rebindHash(
        address policy,
        INewtonPolicy.PolicyConfig memory policyConfig
    ) private pure returns (bytes32) {
        return keccak256(
            abi.encode(UpdateKind.Rebind, policy, keccak256(abi.encode(policyConfig)))
        );
    }

    function _valueHash(UpdateKind kind, uint64 value) private pure returns (bytes32) {
        return keccak256(abi.encode(kind, value));
    }

    function _emptyConfig() private pure returns (INewtonPolicy.PolicyConfig memory) {
        return INewtonPolicy.PolicyConfig({policyParams: "", expireAfter: 0});
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
