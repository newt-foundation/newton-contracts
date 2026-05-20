// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Initializable} from "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import {
    ISlashingRegistryCoordinatorTypes
} from "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {AdminMixin} from "../mixins/AdminMixin.sol";

/// @notice Sibling-contract callback interface implemented by `OperatorRegistry`.
///         The governance contract drives all mutations to the registry's
///         whitelist + task-generator EnumerableSets through `applyMutations`
///         and reads operator-registration status through `getOperatorStatus`
///         (inherited by `OperatorRegistry` from EigenLayer's
///         `SlashingRegistryCoordinator`) for the `queueDeregister` admission
///         gate. Whitelist membership is reachable via `isOperatorWhitelisted`
///         for off-chain consumers.
interface IOperatorRegistryEpochSync {
    function applyMutations(
        address[] calldata whitelistAdditions,
        address[] calldata whitelistRemovals,
        address[] calldata taskGeneratorAdditions,
        address[] calldata taskGeneratorRemovals
    ) external;

    function isOperatorWhitelisted(
        address operator
    ) external view returns (bool);

    function getOperatorStatus(
        address operator
    ) external view returns (ISlashingRegistryCoordinatorTypes.OperatorStatus);
}

/// @title OperatorRegistryEpochGovernance
/// @notice Sibling middleware to `OperatorRegistry` that owns the
///         epoch-bounded mutation queue, the operator self-deregister
///         approval map, and the per-epoch state machine.
///
/// @dev    SPLIT MOTIVATION
///
///         `OperatorRegistry` inherits the EigenLayer middleware
///         `SlashingRegistryCoordinator` (~20 KB runtime) and adds the
///         operator/task-generator whitelist sets — alone that is already
///         most of the EIP-170 24,576-byte budget. The Newton epoch
///         governance machinery (NEWT-1175) does not need to live on the
///         same contract: nothing in the governance state is read by
///         EigenLayer's register/deregister flows except the operator's
///         current deregister approval. We therefore extract the queue
///         storage and mutators here and let `OperatorRegistry` keep only
///         (a) the EigenLayer-coupled register/dereg hooks, (b) the
///         whitelist + task-generator sets, and (c) the cross-contract
///         glue that lets governance mutate those sets.
///
///         The same pattern is used elsewhere in this codebase
///         (`RegoVerifier`, `ChallengeVerifier`, `BN254TableCalculator`,
///         `ECDSAOperatorTableUpdater`).
///
/// @dev    DEPLOYMENT ORDER
///
///         1. Deploy `OperatorRegistry` (initialize from EigenLayer middleware).
///         2. Deploy `OperatorRegistryEpochGovernance` with `initialize(...)`
///            that pins the `OperatorRegistry` address.
///         3. Call `OperatorRegistry.setEpochGovernance(governance)` once.
///         4. Bootstrap initial whitelist + task-generator membership via
///            `addToWhitelist` / `addTaskGenerator` etc. on this contract.
///            Each call routes through `OperatorRegistry.applyMutations` so
///            the actual EnumerableSet writes happen on the registry.
///         5. Call `initializeEpochs(uint32)` to flip out of the bootstrap
///            phase. From this point onward bootstrap mutators revert with
///            `BootstrapPhaseEnded` and admins must use the `queue*` family.
///
/// @dev    EJECTOR BYPASS
///
///         The EigenLayer-inherited `ejector` role on `OperatorRegistry`
///         bypasses the deregister gate; that stays on the registry side
///         (the only place that knows about `ejector`). On destination
///         chains the `ejector` is `address(0)` by deploy convention so
///         the gate is unbypassable there.
contract OperatorRegistryEpochGovernance is Initializable, AdminMixin {
    /* CUSTOM ERRORS */
    error InvalidAddress();
    error InvalidEpochDuration();
    error EpochNotReady(uint64 startBlock, uint32 durationBlocks, uint256 currentBlock);
    error AlreadyQueuedForDeregister(address operator);
    error DeregisterNotApproved(address operator);
    error DeregisterEpochNotReached(address operator, uint32 currentEpoch, uint32 approvedEpoch);
    error BootstrapPhaseEnded();
    error OnlyOperatorRegistry();
    error OperatorRegistryUnset();
    /// @dev `applyPendingChanges` rejects no-op advances. The check uses a
    ///      per-epoch dereg counter (`pendingDeregistersForEpoch[newEpoch]`)
    ///      that auto-clears on advance, so an operator who queues dereg and
    ///      then ghosts cannot keep `EpochAdvanced` firing past the epoch
    ///      their approval matures in.
    error NoPendingChanges();
    /// @dev `queueDeregister` requires the caller to be currently registered
    ///      with EigenLayer's `OperatorStatus.REGISTERED` (queried through the
    ///      sibling `OperatorRegistry`). This admits operators who were once
    ///      whitelisted then removed (so they can self-dereg) while still
    ///      rejecting random EOAs that would inflate the per-epoch counter.
    error NotRegistered(address operator);

    /* EVENTS */
    event EpochAdvanced(uint32 indexed epoch, uint64 startBlock, uint32 durationBlocks);
    event WhitelistAdditionQueued(address indexed operator, uint32 indexed effectiveEpoch);
    event WhitelistRemovalQueued(address indexed operator, uint32 indexed effectiveEpoch);
    event TaskGeneratorAdditionQueued(address indexed generator, uint32 indexed effectiveEpoch);
    event TaskGeneratorRemovalQueued(address indexed generator, uint32 indexed effectiveEpoch);
    event OperatorDeregistrationQueued(address indexed operator, uint32 indexed effectiveEpoch);
    event EpochDurationBlocksQueued(uint32 newDuration, uint32 indexed effectiveEpoch);

    /* STORAGE */

    /// @notice Sibling registry receiving all mutations. Set once at
    ///         `initialize`; not upgradeable in place — replace by deploying
    ///         a fresh governance contract and re-pointing the registry.
    IOperatorRegistryEpochSync public operatorRegistry;

    /// @notice Current epoch number; epoch 0 is the bootstrap state until
    ///         `initializeEpochs` runs.
    uint32 public currentEpoch;

    /// @notice Block at which the current epoch started.
    uint64 public epochStartBlock;

    /// @notice Duration of the current epoch in blocks. Zero before
    ///         `initializeEpochs`; non-zero gates `BootstrapPhaseEnded` on
    ///         bootstrap-only mutators.
    uint32 public epochDurationBlocks;

    /// @notice Pending epoch-duration change applied at the next advance;
    ///         zero means no change.
    uint32 public pendingEpochDurationBlocks;

    /// @notice Operators queued for whitelist addition at the given effective epoch.
    mapping(uint32 => address[]) private _pendingWhitelistAdditions;
    /// @notice Operators queued for whitelist removal at the given effective epoch.
    mapping(uint32 => address[]) private _pendingWhitelistRemovals;
    /// @notice Task generators queued for addition at the given effective epoch.
    mapping(uint32 => address[]) private _pendingTaskGeneratorAdditions;
    /// @notice Task generators queued for removal at the given effective epoch.
    mapping(uint32 => address[]) private _pendingTaskGeneratorRemovals;

    /// @notice First epoch at which the given operator is allowed to deregister.
    /// @dev Zero means "not approved." Cleared on successful dereg by
    ///      `consumeDeregisterApproval`, callable only from `operatorRegistry`.
    mapping(address => uint32) private _approvedDeregisterEpoch;

    /// @notice Count of pending dereg approvals indexed by the epoch they
    ///         mature in. The empty-advance guard in `applyPendingChanges`
    ///         consults `pendingDeregistersForEpoch[newEpoch]` (the bucket
    ///         for the epoch we're about to advance into); buckets for past
    ///         epochs are cleared on advance, so an abandoned approval does
    ///         not perpetually defeat the guard.
    /// @dev    Incremented in `queueDeregister` (bucket for `currentEpoch+1`),
    ///         cleared via `delete` in `applyPendingChanges` once the epoch
    ///         advances, and pre-emptively decremented in
    ///         `cancelDeregisterApproval` when the approval has not yet
    ///         matured.
    mapping(uint32 => uint32) public pendingDeregistersForEpoch;

    /// @dev Storage gap for upgrade safety. Reduce slot count on additions.
    uint256[40] private __gap;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the governance contract.
    /// @param _operatorRegistry Sibling `OperatorRegistry` that this contract
    ///                          will drive via `applyMutations`. Must already
    ///                          be deployed; will be pointed at this
    ///                          contract via `setEpochGovernance` after.
    /// @param _owner Admin address (queue mutator caller, bootstrap mutator
    ///               caller, epoch-duration setter).
    function initialize(
        address _operatorRegistry,
        address _owner
    ) external initializer {
        if (_operatorRegistry == address(0)) revert InvalidAddress();
        if (_owner == address(0)) revert InvalidAddress();
        __Ownable_init();
        _transferOwnership(_owner);
        operatorRegistry = IOperatorRegistryEpochSync(_operatorRegistry);
    }

    /// @notice Initialize access control and grant the guardian the ADMIN_ROLE.
    /// @dev    Uses reinitializer(3) so it can run on deployments where initializeEpochs
    ///         already consumed reinitializer(2).
    function initializeV2(
        address admin
    ) external onlyOwner reinitializer(3) {
        _initializeAdmin(admin);
    }

    /// @notice Flip out of the bootstrap phase by setting the initial
    ///         epoch duration. One-shot via `reinitializer(4)` — called last
    ///         after all bootstrap-phase mutations are complete.
    /// @param _initialEpochDurationBlocks Epoch duration in blocks. Must be > 0.
    function initializeEpochs(
        uint32 _initialEpochDurationBlocks
    ) external reinitializer(4) onlyOwner {
        if (_initialEpochDurationBlocks == 0) revert InvalidEpochDuration();
        currentEpoch = 0;
        epochStartBlock = uint64(block.number);
        epochDurationBlocks = _initialEpochDurationBlocks;
        emit EpochAdvanced(0, uint64(block.number), _initialEpochDurationBlocks);
    }

    /* ───────── BOOTSTRAP-PHASE MUTATORS — owner-gated, gated on `epochDurationBlocks == 0` ───────── */

    /// @notice Add an operator to the whitelist (bootstrap phase only).
    function addToWhitelist(
        address operator
    ) external onlyOwner {
        _bootstrapGate();
        _flushAdds(operator, true);
    }

    /// @notice Add multiple operators to the whitelist (bootstrap phase only).
    function addMultipleToWhitelist(
        address[] calldata operators
    ) external onlyOwner {
        _bootstrapGate();
        _flushAddsMany(operators, true);
    }

    /// @notice Remove an operator from the whitelist (bootstrap phase only).
    function removeFromWhitelist(
        address operator
    ) external onlyOwner {
        _bootstrapGate();
        _flushRemove(operator, true);
    }

    /// @notice Add a task generator (bootstrap phase only).
    function addTaskGenerator(
        address generator
    ) external onlyOwner {
        _bootstrapGate();
        _flushAdds(generator, false);
    }

    /// @notice Add multiple task generators (bootstrap phase only).
    function addMultipleToTaskGenerators(
        address[] calldata generators
    ) external onlyOwner {
        _bootstrapGate();
        _flushAddsMany(generators, false);
    }

    /// @notice Remove a task generator (bootstrap phase only).
    function removeTaskGenerator(
        address generator
    ) external onlyOwner {
        _bootstrapGate();
        _flushRemove(generator, false);
    }

    /* ───────── QUEUE MUTATORS — admin-gated, applied at next epoch boundary ───────── */

    /// @notice Queue an operator for whitelist addition at the next epoch.
    function queueAddToWhitelist(
        address operator
    ) external onlyAdmin {
        _queueWhitelistAdd(operator, currentEpoch + 1);
    }

    /// @notice Queue multiple operators for whitelist addition at the next epoch.
    function queueAddMultipleToWhitelist(
        address[] calldata operators
    ) external onlyAdmin {
        uint32 effectiveEpoch = currentEpoch + 1;
        for (uint256 i = 0; i < operators.length; ++i) {
            _queueWhitelistAdd(operators[i], effectiveEpoch);
        }
    }

    /// @notice Queue an operator for whitelist removal at the next epoch.
    /// @dev    Rejects `address(0)` for symmetry with the add-side variants
    ///         and to prevent confusing `WhitelistRemovalQueued(address(0), ...)`
    ///         events that off-chain indexers would mis-index.
    function queueRemoveFromWhitelist(
        address operator
    ) external onlyAdmin {
        if (operator == address(0)) revert InvalidAddress();
        uint32 effectiveEpoch = currentEpoch + 1;
        _pendingWhitelistRemovals[effectiveEpoch].push(operator);
        emit WhitelistRemovalQueued(operator, effectiveEpoch);
    }

    /// @notice Queue a task generator for addition at the next epoch.
    function queueAddTaskGenerator(
        address generator
    ) external onlyAdmin {
        _queueTaskGeneratorAdd(generator, currentEpoch + 1);
    }

    /// @notice Queue multiple task generators for addition at the next epoch.
    function queueAddMultipleToTaskGenerators(
        address[] calldata generators
    ) external onlyAdmin {
        uint32 effectiveEpoch = currentEpoch + 1;
        for (uint256 i = 0; i < generators.length; ++i) {
            _queueTaskGeneratorAdd(generators[i], effectiveEpoch);
        }
    }

    /// @notice Queue a task generator for removal at the next epoch.
    /// @dev    Rejects `address(0)` for symmetry with the add-side variants;
    ///         see `queueRemoveFromWhitelist` for rationale.
    function queueRemoveTaskGenerator(
        address generator
    ) external onlyAdmin {
        if (generator == address(0)) revert InvalidAddress();
        uint32 effectiveEpoch = currentEpoch + 1;
        _pendingTaskGeneratorRemovals[effectiveEpoch].push(generator);
        emit TaskGeneratorRemovalQueued(generator, effectiveEpoch);
    }

    /* ───────── OPERATOR-INITIATED DEREGISTRATION QUEUE ───────── */

    /// @notice Operator self-queues for deregistration; effective at next epoch.
    /// @dev    Re-queue is rejected; an operator can only have one pending
    ///         dereg at a time. Cleared by `consumeDeregisterApproval` (called
    ///         from `OperatorRegistry._beforeDeregisterOperator`) on
    ///         successful dereg.
    ///
    ///         Status gate: caller must currently have
    ///         `OperatorStatus.REGISTERED` per the EigenLayer middleware
    ///         lineage. This admits operators who were whitelisted, registered,
    ///         then later removed from the whitelist (their dereg path needs
    ///         to remain reachable) while still rejecting random EOAs that
    ///         would dust `pendingDeregistersForEpoch` and trigger empty
    ///         epoch advances.
    function queueDeregister() external {
        if (
            operatorRegistry.getOperatorStatus(msg.sender)
                != ISlashingRegistryCoordinatorTypes.OperatorStatus.REGISTERED
        ) {
            revert NotRegistered(msg.sender);
        }
        if (_approvedDeregisterEpoch[msg.sender] != 0) {
            revert AlreadyQueuedForDeregister(msg.sender);
        }
        uint32 effectiveEpoch = currentEpoch + 1;
        _approvedDeregisterEpoch[msg.sender] = effectiveEpoch;
        ++pendingDeregistersForEpoch[effectiveEpoch];
        emit OperatorDeregistrationQueued(msg.sender, effectiveEpoch);
    }

    /// @notice Consume the deregister approval for `operator`. Called only
    ///         from `OperatorRegistry._beforeDeregisterOperator`. Reverts on
    ///         unapproved or epoch-not-yet-reached so the actual dereg
    ///         transaction reverts with a Newton-specific reason.
    /// @dev    The per-epoch bucket has already been cleared by
    ///         `applyPendingChanges` when this runs (consume requires
    ///         `currentEpoch >= approvedEpoch`, and the advance to
    ///         `approvedEpoch` clears the bucket), so no bucket arithmetic
    ///         is needed here.
    function consumeDeregisterApproval(
        address operator
    ) external {
        if (msg.sender != address(operatorRegistry)) revert OnlyOperatorRegistry();
        uint32 approvedEpoch = _approvedDeregisterEpoch[operator];
        if (approvedEpoch == 0) revert DeregisterNotApproved(operator);
        if (currentEpoch < approvedEpoch) {
            revert DeregisterEpochNotReached(operator, currentEpoch, approvedEpoch);
        }
        delete _approvedDeregisterEpoch[operator];
    }

    /// @notice Clear a stored deregister approval without enforcing the epoch
    ///         gate. Called only from `OperatorRegistry._beforeDeregisterOperator`
    ///         on the ejector bypass path so `pendingDeregistersForEpoch` stays
    ///         exact across emergency dereg.
    /// @dev    Safe to call when no approval exists (no-op). Idempotent.
    ///         Decrements the per-epoch bucket only if the approval has not
    ///         yet matured (`approvedEpoch > currentEpoch`); for already-
    ///         matured approvals the bucket was cleared on advance.
    function cancelDeregisterApproval(
        address operator
    ) external {
        if (msg.sender != address(operatorRegistry)) revert OnlyOperatorRegistry();
        uint32 approvedEpoch = _approvedDeregisterEpoch[operator];
        if (approvedEpoch == 0) return;
        delete _approvedDeregisterEpoch[operator];
        if (approvedEpoch > currentEpoch) {
            --pendingDeregistersForEpoch[approvedEpoch];
        }
    }

    /* ───────── EPOCH DURATION GOVERNANCE ───────── */

    /// @notice Queue a new epoch duration; takes effect at the next advance.
    /// @dev    The new duration is consumed at the next
    ///         `applyPendingChanges()` and replaces `epochDurationBlocks`.
    ///         A queued duration overwrites any prior pending duration.
    function setEpochDurationBlocks(
        uint32 newDuration
    ) external onlyAdmin {
        if (newDuration == 0) revert InvalidEpochDuration();
        pendingEpochDurationBlocks = newDuration;
        emit EpochDurationBlocksQueued(newDuration, currentEpoch + 1);
    }

    /* ───────── PERMISSIONLESS EPOCH ADVANCE ───────── */

    /// @notice Apply all pending changes for the next epoch and advance.
    /// @dev    Permissionless. Reverts with `EpochNotReady` if the current
    ///         block is below `epochStartBlock + epochDurationBlocks`.
    ///         Apply order: additions before removals (last-call wins for
    ///         the same-epoch typo case). Drives the actual EnumerableSet
    ///         writes by calling `operatorRegistry.applyMutations(...)`.
    function applyPendingChanges() external {
        uint64 startBlock = epochStartBlock;
        uint32 duration = epochDurationBlocks;
        if (duration == 0) revert InvalidEpochDuration();
        if (block.number < uint256(startBlock) + uint256(duration)) {
            revert EpochNotReady(startBlock, duration, block.number);
        }
        if (address(operatorRegistry) == address(0)) revert OperatorRegistryUnset();

        uint32 newEpoch = currentEpoch + 1;

        address[] memory wAdds = _pendingWhitelistAdditions[newEpoch];
        address[] memory wRems = _pendingWhitelistRemovals[newEpoch];
        address[] memory tgAdds = _pendingTaskGeneratorAdditions[newEpoch];
        address[] memory tgRems = _pendingTaskGeneratorRemovals[newEpoch];
        uint32 newDuration = pendingEpochDurationBlocks;

        // Reject no-op advances. A permissionless `applyPendingChanges` that
        // emits `EpochAdvanced` even when nothing changed lets a griefer
        // force gateway-side cache rebuilds (twin watchers re-fetch the
        // operator set on every signal) for the cost of one tx per epoch.
        // Requiring at least one of: non-empty queue, queued duration change,
        // or pending dereg approval *maturing this epoch* blocks the grief
        // while still allowing dereg-only flows to advance the epoch
        // (operators need `currentEpoch >= approvedEpoch` for
        // `consumeDeregisterApproval` to accept them). Indexing by epoch
        // means an abandoned approval becomes inert once its target epoch
        // has elapsed — it cannot perpetually re-arm the empty-advance gate.
        uint32 maturingDereg = pendingDeregistersForEpoch[newEpoch];
        if (
            wAdds.length == 0 && wRems.length == 0 && tgAdds.length == 0 && tgRems.length == 0
                && newDuration == 0 && maturingDereg == 0
        ) {
            revert NoPendingChanges();
        }

        delete _pendingWhitelistAdditions[newEpoch];
        delete _pendingWhitelistRemovals[newEpoch];
        delete _pendingTaskGeneratorAdditions[newEpoch];
        delete _pendingTaskGeneratorRemovals[newEpoch];
        if (maturingDereg != 0) delete pendingDeregistersForEpoch[newEpoch];

        // Checks-Effects-Interactions: advance the epoch state machine BEFORE
        // the cross-contract call. The registry's `applyMutations` only
        // mutates EnumerableSets and emits events — it does not re-enter
        // governance — but ordering this way removes Slither's
        // `reentrancy-no-eth` finding and protects against future registry
        // impl changes that might add a callback path.
        if (newDuration != 0) {
            duration = newDuration;
            epochDurationBlocks = newDuration;
            delete pendingEpochDurationBlocks;
        }

        currentEpoch = newEpoch;
        uint64 newStartBlock = uint64(block.number);
        epochStartBlock = newStartBlock;
        emit EpochAdvanced(newEpoch, newStartBlock, duration);

        // Interaction last.
        operatorRegistry.applyMutations(wAdds, wRems, tgAdds, tgRems);
    }

    /* ───────── VIEW FUNCTIONS ───────── */

    /// @notice First block at which `applyPendingChanges()` will not revert.
    function nextEpochAdvanceAt() external view returns (uint256) {
        return uint256(epochStartBlock) + uint256(epochDurationBlocks);
    }

    /// @notice Whether `applyPendingChanges()` would succeed at the current block.
    function isEpochAdvanceReady() external view returns (bool) {
        return block.number >= uint256(epochStartBlock) + uint256(epochDurationBlocks);
    }

    function pendingWhitelistAdditions(
        uint32 epoch
    ) external view returns (address[] memory) {
        return _pendingWhitelistAdditions[epoch];
    }

    function pendingWhitelistRemovals(
        uint32 epoch
    ) external view returns (address[] memory) {
        return _pendingWhitelistRemovals[epoch];
    }

    function pendingTaskGeneratorAdditions(
        uint32 epoch
    ) external view returns (address[] memory) {
        return _pendingTaskGeneratorAdditions[epoch];
    }

    function pendingTaskGeneratorRemovals(
        uint32 epoch
    ) external view returns (address[] memory) {
        return _pendingTaskGeneratorRemovals[epoch];
    }

    /// @notice First epoch at which the operator may call `deregisterOperator`.
    /// @dev    Zero indicates no approval. Cleared on consumption.
    function approvedDeregisterEpoch(
        address operator
    ) external view returns (uint32) {
        return _approvedDeregisterEpoch[operator];
    }

    /* ───────── INTERNAL HELPERS ───────── */

    /// @dev Bootstrap-phase gate. Reverts with `BootstrapPhaseEnded` after
    ///      `initializeEpochs` set `epochDurationBlocks > 0`.
    function _bootstrapGate() internal view {
        if (epochDurationBlocks != 0) revert BootstrapPhaseEnded();
        if (address(operatorRegistry) == address(0)) revert OperatorRegistryUnset();
    }

    /// @dev Push a single address through the `applyMutations` path,
    ///      classified as either whitelist or task-generator addition.
    function _flushAdds(
        address addr,
        bool isWhitelist
    ) internal {
        if (addr == address(0)) revert InvalidAddress();
        address[] memory single = new address[](1);
        single[0] = addr;
        address[] memory empty;
        if (isWhitelist) {
            operatorRegistry.applyMutations(single, empty, empty, empty);
        } else {
            operatorRegistry.applyMutations(empty, empty, single, empty);
        }
    }

    /// @dev Multi-add bootstrap variant. Validates each entry, then pushes
    ///      one applyMutations call with the full array.
    function _flushAddsMany(
        address[] calldata addrs,
        bool isWhitelist
    ) internal {
        for (uint256 i = 0; i < addrs.length; ++i) {
            if (addrs[i] == address(0)) revert InvalidAddress();
        }
        address[] memory empty;
        if (isWhitelist) {
            operatorRegistry.applyMutations(addrs, empty, empty, empty);
        } else {
            operatorRegistry.applyMutations(empty, empty, addrs, empty);
        }
    }

    /// @dev Bootstrap-phase removal — pushes one entry through `applyMutations`.
    ///      Idempotent on the registry side: removing an absent address is a
    ///      silent no-op (no event, no revert). Pre-split the direct
    ///      `removeFromWhitelist` reverted with `OperatorNotInWhitelist`; the
    ///      new behavior matches the queue path's skip-if-absent semantics
    ///      and is documented in OPERATOR.md "Bootstrap phase".
    function _flushRemove(
        address addr,
        bool isWhitelist
    ) internal {
        address[] memory single = new address[](1);
        single[0] = addr;
        address[] memory empty;
        if (isWhitelist) {
            operatorRegistry.applyMutations(empty, single, empty, empty);
        } else {
            operatorRegistry.applyMutations(empty, empty, empty, single);
        }
    }

    function _queueWhitelistAdd(
        address operator,
        uint32 effectiveEpoch
    ) internal {
        if (operator == address(0)) revert InvalidAddress();
        _pendingWhitelistAdditions[effectiveEpoch].push(operator);
        emit WhitelistAdditionQueued(operator, effectiveEpoch);
    }

    function _queueTaskGeneratorAdd(
        address generator,
        uint32 effectiveEpoch
    ) internal {
        if (generator == address(0)) revert InvalidAddress();
        _pendingTaskGeneratorAdditions[effectiveEpoch].push(generator);
        emit TaskGeneratorAdditionQueued(generator, effectiveEpoch);
    }
}
