// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "./INewtonProverTaskManager.sol";

/// @title IBatchTaskManager
/// @notice Interface for batching multiple createNewTask and respondToTask calls
/// @dev Enables high-throughput transaction submission by batching N calls per tx.
///      On the happy path (all items succeed), the tx commits with no events — minimal gas.
///      On failure, the tx reverts with a structured error containing all failed items,
///      allowing the caller to strip failures and retry the healthy remainder.
interface IBatchTaskManager {
    /// @notice A single item that failed within a batch
    struct FailedItem {
        uint256 index;
        bytes32 taskId;
        bytes reason;
    }

    /// @notice Reverted when one or more items in a batch fail
    /// @param failures Array of failed items with index, taskId, and revert reason
    error BatchPartialFailure(FailedItem[] failures);

    /// @notice Batch-submit multiple createNewTask calls in a single transaction.
    ///         Succeeds silently when all items pass. Reverts with BatchPartialFailure
    ///         containing all failed items when any fail.
    /// @param tasks Array of tasks to create
    function batchCreateTasks(
        INewtonProverTaskManager.Task[] calldata tasks
    ) external;

    /// @notice Batch-submit multiple respondToTask calls in a single transaction.
    ///         Succeeds silently when all items pass. Reverts with BatchPartialFailure
    ///         containing all failed items when any fail.
    /// @param tasks Array of tasks (must match responses and signatureDataArray by index)
    /// @param responses Array of task responses
    /// @param signatureDataArray Array of BLS signature data (one per response)
    function batchRespondToTasks(
        INewtonProverTaskManager.Task[] calldata tasks,
        INewtonProverTaskManager.TaskResponse[] calldata responses,
        bytes[] calldata signatureDataArray
    ) external;
}
