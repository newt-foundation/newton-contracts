// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {
    SlashingRegistryCoordinator
} from "@eigenlayer-middleware/src/SlashingRegistryCoordinator.sol";
import {
    ISlashingRegistryCoordinatorTypes
} from "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {IStakeRegistry} from "@eigenlayer-middleware/src/interfaces/IStakeRegistry.sol";
import {IBLSApkRegistry} from "@eigenlayer-middleware/src/interfaces/IBLSApkRegistry.sol";
import {IIndexRegistry} from "@eigenlayer-middleware/src/interfaces/IIndexRegistry.sol";
import {ISocketRegistry} from "@eigenlayer-middleware/src/interfaces/ISocketRegistry.sol";
import {IAllocationManager} from "@eigenlayer/contracts/interfaces/IAllocationManager.sol";
import {IPauserRegistry} from "@eigenlayer/contracts/interfaces/IPauserRegistry.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ChainLib} from "../libraries/ChainLib.sol";
import {IOperatorRegistryEpochGovernance} from "./IOperatorRegistryEpochGovernance.sol";

/// @title OperatorRegistry
/// @notice Whitelisted operator + task-generator registry for the Newton AVS.
///
/// @dev    SCOPE
///
///         This contract owns three things:
///         1. The EigenLayer-coupled operator registration / deregistration
///            hooks (`_beforeRegisterOperator`, `_afterRegisterOperator`,
///            `_beforeDeregisterOperator`, `_afterDeregisterOperator`).
///         2. The `_whitelistedOperators` and `_taskGenerators` EnumerableSets
///            — these have to live here because the register-time gate reads
///            from `_whitelistedOperators` and the EigenLayer middleware
///            inheritance chain forces us into the same contract address.
///         3. A single mutation entry point `applyMutations(...)` callable
///            only by the sibling `OperatorRegistryEpochGovernance` contract.
///
///         All queue mutators, bootstrap mutators, dereg-approval state, and
///         epoch governance live on the sibling contract. See its source for
///         the deployment order and bootstrap flow.
///
///         The split exists because `SlashingRegistryCoordinator` (parent
///         from EigenLayer middleware) plus the Newton epoch governance
///         machinery exceeded the EIP-170 24,576-byte runtime-code limit.
///
/// @dev    EJECTOR BYPASS
///
///         The EigenLayer-inherited `ejector` role bypasses the dereg gate
///         here (emergency override; future Security Council multisig per
///         NEWT-1176). On destination chains the `ejector` is `address(0)`
///         by deploy convention, so the gate is unbypassable there — which
///         matches destination registries not participating in operator
///         self-dereg in the first place.
contract OperatorRegistry is SlashingRegistryCoordinator {
    using EnumerableSet for EnumerableSet.AddressSet;

    /* CUSTOM ERRORS */
    /// @dev Mainnet whitelist gate: register attempts revert with this when
    ///      the operator is not in `_whitelistedOperators`. Tested by
    ///      `_beforeRegisterOperator`.
    error OperatorNotWhitelisted(address operator);
    /// @dev `setEpochGovernance` rejects `address(0)`.
    error InvalidAddress();
    /// @dev `applyMutations` rejects callers other than the wired sibling
    ///      governance contract. Distinct from `EpochGovernanceUnset` so
    ///      off-chain decoders can tell "wrong caller" from "not yet wired".
    error OnlyEpochGovernance();
    /// @dev Returned by `_beforeDeregisterOperator` when `epochGovernance`
    ///      has not been set yet. Pre-bootstrap deregistration is therefore
    ///      blocked entirely except via the `ejector` role — a stronger
    ///      invariant than fail-open.
    error EpochGovernanceUnset();
    /// @dev `setEpochGovernance` is one-shot — re-set is rejected to make
    ///      a misconfiguration impossible to silently overwrite.
    error EpochGovernanceAlreadySet();

    /* EVENTS */
    event TaskGeneratorAdded(address indexed generator);
    event TaskGeneratorRemoved(address indexed generator);
    event OperatorWhitelisted(address indexed operator, bool indexed isWhitelisted);
    event EpochGovernanceSet(address indexed governance);

    /* STORAGE — Slots 252-256 (existing, do not reorder)
     *
     *   252  _quorumNumberToOperators            mapping(bytes32 => mapping(address => OperatorInfo))
     *   253  _whitelistedOperators._values       address[]   (EnumerableSet.AddressSet, slot[0])
     *   254  _whitelistedOperators._indexes      mapping     (EnumerableSet.AddressSet, slot[1])
     *   255  _taskGenerators._values             address[]
     *   256  _taskGenerators._indexes            mapping
     */
    /// @notice mapping from quorum number to registered operators
    mapping(bytes32 => mapping(address => ISlashingRegistryCoordinatorTypes.OperatorInfo)) private
        _quorumNumberToOperators;

    EnumerableSet.AddressSet private _whitelistedOperators;
    EnumerableSet.AddressSet private _taskGenerators;

    /* STORAGE — Slot 257+ (sibling-contract pointer + gap) */

    /// @notice Sibling middleware driving queue + bootstrap mutations and the
    ///         dereg-approval gate. Set once via `setEpochGovernance`. Until
    ///         set, register flows still work but the dereg gate is fully
    ///         **closed** for non-`ejector` callers — `_beforeDeregisterOperator`
    ///         reverts with `EpochGovernanceUnset` for any operator dereg
    ///         attempt during the wiring window. Only the inherited
    ///         EigenLayer `ejector` role can dereg pre-bootstrap; this is the
    ///         emergency-removal escape hatch.
    IOperatorRegistryEpochGovernance public epochGovernance;

    /// @dev Reserved storage to absorb the slots vacated by the pre-split
    ///      governance state (currentEpoch / epochStartBlock /
    ///      epochDurationBlocks / 4 pending mappings / approvedDeregisterEpoch
    ///      / pendingEpochDurationBlocks). Sized at uint256[42] so the slot
    ///      occupancy through slot 299 matches the previous layout for any
    ///      contracts (libraries, mixins) that may have indexed into them.
    uint256[42] private __gap;

    constructor(
        IStakeRegistry _stakeRegistry,
        IBLSApkRegistry _blsApkRegistry,
        IIndexRegistry _indexRegistry,
        ISocketRegistry _socketRegistry,
        IAllocationManager _allocationManager,
        IPauserRegistry _pauserRegistry,
        string memory _version
    )
        SlashingRegistryCoordinator(
            _stakeRegistry,
            _blsApkRegistry,
            _indexRegistry,
            _socketRegistry,
            _allocationManager,
            _pauserRegistry,
            _version
        )
    {}

    /// @notice One-shot setter for the sibling governance contract. Owner-only;
    ///         reverts on re-set so an incorrect wiring can't be silently
    ///         replaced.
    function setEpochGovernance(
        address governance
    ) external onlyOwner {
        if (governance == address(0)) revert InvalidAddress();
        if (address(epochGovernance) != address(0)) revert EpochGovernanceAlreadySet();
        epochGovernance = IOperatorRegistryEpochGovernance(governance);
        emit EpochGovernanceSet(governance);
    }

    /// @notice Sole mutation entry point for the whitelist + task-generator
    ///         sets. Callable only by the sibling governance contract.
    /// @dev    Apply order per set: additions before removals (last-call wins
    ///         for the typo case, matching the previous in-contract
    ///         applyPendingChanges semantics). Skip-if-already-present is
    ///         intentional for additions; idempotent.
    function applyMutations(
        address[] calldata whitelistAdditions,
        address[] calldata whitelistRemovals,
        address[] calldata taskGeneratorAdditions,
        address[] calldata taskGeneratorRemovals
    ) external {
        if (msg.sender != address(epochGovernance)) revert OnlyEpochGovernance();

        for (uint256 i = 0; i < whitelistAdditions.length; ++i) {
            address op = whitelistAdditions[i];
            if (op != address(0) && _whitelistedOperators.add(op)) {
                emit OperatorWhitelisted(op, true);
            }
        }
        for (uint256 i = 0; i < whitelistRemovals.length; ++i) {
            address op = whitelistRemovals[i];
            if (_whitelistedOperators.remove(op)) {
                emit OperatorWhitelisted(op, false);
            }
        }
        for (uint256 i = 0; i < taskGeneratorAdditions.length; ++i) {
            address tg = taskGeneratorAdditions[i];
            if (tg != address(0) && _taskGenerators.add(tg)) {
                emit TaskGeneratorAdded(tg);
            }
        }
        for (uint256 i = 0; i < taskGeneratorRemovals.length; ++i) {
            address tg = taskGeneratorRemovals[i];
            if (_taskGenerators.remove(tg)) {
                emit TaskGeneratorRemoved(tg);
            }
        }
    }

    /// @dev Hook to allow for any pre-register logic in `_registerOperator`
    function _beforeRegisterOperator(
        address operator,
        bytes32,
        /* operatorId */
        bytes memory,
        /* quorumNumbers */
        uint192 /* currentBitmap */
    ) internal virtual override {
        ChainLib.requireSupportedChain();
        if (ChainLib.isMainnet() && !_whitelistedOperators.contains(operator)) {
            revert OperatorNotWhitelisted(operator);
        }
    }

    /// @dev Hook to allow for any post-register logic in `_registerOperator`
    function _afterRegisterOperator(
        address operator,
        bytes32 operatorId,
        bytes memory quorumNumbers,
        uint192 /* newBitmap */
    ) internal virtual override {
        bytes32 quorumNumberHash = keccak256(quorumNumbers);
        _quorumNumberToOperators[quorumNumberHash][operator] =
            ISlashingRegistryCoordinatorTypes.OperatorInfo(
                operatorId, ISlashingRegistryCoordinatorTypes.OperatorStatus.REGISTERED
            );
    }

    /// @dev Pre-deregister hook: enforce epoch-bounded deregistration via the
    ///      sibling governance contract. Bypassed for the inherited `ejector`
    ///      role (emergency override). On destination chains the `ejector` is
    ///      `address(0)` so the gate is unbypassable.
    ///
    ///      PRE-BOOTSTRAP INVARIANT: with `epochGovernance == address(0)` —
    ///      i.e., between contract deployment and the one-shot
    ///      `setEpochGovernance` call — every dereg attempt by a non-ejector
    ///      reverts with `EpochGovernanceUnset`. This is intentional: it
    ///      makes accidental dereg-without-approval impossible during the
    ///      window where the governance pointer hasn't been wired yet.
    ///      Mainnet deploys MUST call `setEpochGovernance` before exposing
    ///      the contract to operators.
    function _beforeDeregisterOperator(
        address operator,
        bytes32, /* operatorId */
        bytes memory, /* quorumNumbers */
        uint192 /* currentBitmap */
    ) internal virtual override {
        IOperatorRegistryEpochGovernance gov = epochGovernance;
        if (msg.sender == ejector) {
            // Cancel any pending dereg approval the operator may have queued
            // before being ejected. Without this, the operator's slot in
            // `pendingDeregistersForEpoch[approvedEpoch]` leaks until the
            // bucket clears on advance — and if the ejection happens after
            // the bucket has already cleared, the per-operator
            // `_approvedDeregisterEpoch` entry would linger and let a
            // later spurious `consumeDeregisterApproval` call succeed.
            // Idempotent — no-op if the operator never queued.
            if (address(gov) != address(0)) {
                gov.cancelDeregisterApproval(operator);
            }
            return;
        }
        if (address(gov) == address(0)) revert EpochGovernanceUnset();
        gov.consumeDeregisterApproval(operator);
    }

    /// @dev Hook to allow for any post-deregister logic in `_deregisterOperator`
    function _afterDeregisterOperator(
        address operator,
        bytes32 operatorId,
        bytes memory quorumNumbers,
        uint192 /* newBitmap */
    ) internal virtual override {
        bytes32 quorumNumberHash = keccak256(quorumNumbers);
        require(
            _quorumNumberToOperators[quorumNumberHash][operator].status
                == ISlashingRegistryCoordinatorTypes.OperatorStatus.REGISTERED,
            OperatorNotRegisteredForQuorum()
        );
        _quorumNumberToOperators[quorumNumberHash][operator] =
            ISlashingRegistryCoordinatorTypes.OperatorInfo(
                operatorId, ISlashingRegistryCoordinatorTypes.OperatorStatus.DEREGISTERED
            );
    }

    /* QUERY FUNCTIONS */

    /**
     * @notice Get all operators registered for a given quorum number
     * @param quorumNumbers The quorum number bytes to get operators for
     * @return An array of operator addresses registered for the given quorum number
     */
    function getRegisteredOperators(
        bytes memory quorumNumbers
    ) public view returns (address[] memory) {
        bytes32 quorumNumberHash = keccak256(quorumNumbers);
        uint256 length = _whitelistedOperators.length();
        address[] memory operators = new address[](length);
        for (uint256 i = 0; i < length; ++i) {
            address operator = _whitelistedOperators.at(i);
            if (
                _quorumNumberToOperators[quorumNumberHash][operator].status
                    == ISlashingRegistryCoordinatorTypes.OperatorStatus.REGISTERED
            ) {
                operators[i] = operator;
            }
        }
        return operators;
    }

    /**
     * @notice Get all whitelisted operators
     * @return An array of whitelisted operator addresses
     */
    function getAllWhitelistedOperators() public view returns (address[] memory) {
        return _whitelistedOperators.values();
    }

    /**
     * @notice Check if an operator is whitelisted
     * @param operator The operator address to check
     */
    function isOperatorWhitelisted(
        address operator
    ) external view returns (bool) {
        return _whitelistedOperators.contains(operator);
    }

    /**
     * @notice Check if a generator is a task generator
     * @param generator The generator address to check
     */
    function isTaskGenerator(
        address generator
    ) external view returns (bool) {
        return _taskGenerators.contains(generator);
    }

    /**
     * @notice Get all task generators
     * @return An array of task generator addresses
     */
    function getAllTaskGenerators() external view returns (address[] memory) {
        return _taskGenerators.values();
    }

    /// @notice Active epoch duration in blocks. Forwarded from the sibling
    ///         governance contract. Returns 0 if governance is unset (i.e.,
    ///         in the bootstrap phase before `setEpochGovernance`); other
    ///         contracts (`TaskManager.epochBlocks()`) treat zero as
    ///         "not yet initialized."
    function epochDurationBlocks() external view returns (uint32) {
        IOperatorRegistryEpochGovernance gov = epochGovernance;
        if (address(gov) == address(0)) return 0;
        return gov.epochDurationBlocks();
    }

    /// @notice Active epoch number. Forwarded from the sibling governance.
    ///         Returns 0 if governance is unset.
    function currentEpoch() external view returns (uint32) {
        IOperatorRegistryEpochGovernance gov = epochGovernance;
        if (address(gov) == address(0)) return 0;
        return gov.currentEpoch();
    }
}
