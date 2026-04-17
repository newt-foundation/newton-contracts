// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "./interfaces/INewtonProverTaskManager.sol";
import {IBatchTaskManager} from "./interfaces/IBatchTaskManager.sol";

/// @title BatchTaskManager
/// @notice Batches multiple createNewTask and respondToTask calls into single transactions
/// @dev This contract is registered as a task generator on OperatorRegistry.
///      Happy path: all items succeed, tx commits with no events (minimal gas).
///      Failure path: collects all failed items, reverts with BatchPartialFailure
///      so the caller can strip failures and retry the healthy remainder.
contract BatchTaskManager is IBatchTaskManager {
    error ArrayLengthMismatch();
    error EmptyBatch();
    error Unauthorized();

    INewtonProverTaskManager public immutable taskManager;

    /// @notice Addresses authorized to submit batches
    mapping(address => bool) public authorized;

    /// @notice Contract owner (can manage authorized callers)
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, Unauthorized());
        _;
    }

    modifier onlyAuthorized() {
        require(authorized[msg.sender], Unauthorized());
        _;
    }

    constructor(
        address _taskManager,
        address _owner
    ) {
        taskManager = INewtonProverTaskManager(_taskManager);
        owner = _owner;
        authorized[_owner] = true;
    }

    /// @notice Add an authorized caller (e.g., a gateway signer)
    function addAuthorized(
        address caller
    ) external onlyOwner {
        authorized[caller] = true;
    }

    /// @notice Remove an authorized caller
    function removeAuthorized(
        address caller
    ) external onlyOwner {
        authorized[caller] = false;
    }

    /// @notice Transfer ownership
    function transferOwnership(
        address newOwner
    ) external onlyOwner {
        owner = newOwner;
    }

    /// @inheritdoc IBatchTaskManager
    function batchCreateTasks(
        INewtonProverTaskManager.Task[] calldata tasks
    ) external onlyAuthorized {
        require(tasks.length > 0, EmptyBatch());

        // Pre-allocate max-size array; failCount tracks actual usage
        FailedItem[] memory failures = new FailedItem[](tasks.length);
        uint256 failCount;

        for (uint256 i; i < tasks.length;) {
            try taskManager.createNewTask(tasks[i]) {}
            catch (bytes memory reason) {
                failures[failCount] = FailedItem(i, tasks[i].taskId, reason);
                unchecked {
                    ++failCount;
                }
            }
            unchecked {
                ++i;
            }
        }

        if (failCount > 0) {
            // Trim array to actual size and revert with failure details
            FailedItem[] memory trimmed = new FailedItem[](failCount);
            for (uint256 j; j < failCount;) {
                trimmed[j] = failures[j];
                unchecked {
                    ++j;
                }
            }
            revert BatchPartialFailure(trimmed);
        }
    }

    /// @inheritdoc IBatchTaskManager
    function batchRespondToTasks(
        INewtonProverTaskManager.Task[] calldata tasks,
        INewtonProverTaskManager.TaskResponse[] calldata responses,
        bytes[] calldata signatureDataArray,
        bytes[] calldata attestationDataArray
    ) external onlyAuthorized {
        require(tasks.length > 0, EmptyBatch());
        require(
            tasks.length == responses.length && responses.length == signatureDataArray.length
                && signatureDataArray.length == attestationDataArray.length,
            ArrayLengthMismatch()
        );

        FailedItem[] memory failures = new FailedItem[](tasks.length);
        uint256 failCount;

        for (uint256 i; i < tasks.length;) {
            try taskManager.respondToTask(
                tasks[i], responses[i], signatureDataArray[i], attestationDataArray[i]
            ) {}
            catch (bytes memory reason) {
                failures[failCount] = FailedItem(i, responses[i].taskId, reason);
                unchecked {
                    ++failCount;
                }
            }
            unchecked {
                ++i;
            }
        }

        if (failCount > 0) {
            FailedItem[] memory trimmed = new FailedItem[](failCount);
            for (uint256 j; j < failCount;) {
                trimmed[j] = failures[j];
                unchecked {
                    ++j;
                }
            }
            revert BatchPartialFailure(trimmed);
        }
    }

    /// @inheritdoc IBatchTaskManager
    function batchCreateAndRespondToTasks(
        INewtonProverTaskManager.Task[] calldata tasks,
        INewtonProverTaskManager.TaskResponse[] calldata responses,
        bytes[] calldata signatureDataArray,
        bytes[] calldata attestationDataArray
    ) external onlyAuthorized {
        require(tasks.length > 0, EmptyBatch());
        require(
            tasks.length == responses.length && responses.length == signatureDataArray.length
                && signatureDataArray.length == attestationDataArray.length,
            ArrayLengthMismatch()
        );

        FailedItem[] memory failures = new FailedItem[](tasks.length);
        uint256 failCount;

        for (uint256 i; i < tasks.length;) {
            try this._createAndRespond(
                tasks[i], responses[i], signatureDataArray[i], attestationDataArray[i]
            ) {}
            catch (bytes memory reason) {
                failures[failCount] = FailedItem(i, responses[i].taskId, reason);
                unchecked {
                    ++failCount;
                }
            }
            unchecked {
                ++i;
            }
        }

        if (failCount > 0) {
            FailedItem[] memory trimmed = new FailedItem[](failCount);
            for (uint256 j; j < failCount;) {
                trimmed[j] = failures[j];
                unchecked {
                    ++j;
                }
            }
            revert BatchPartialFailure(trimmed);
        }
    }

    /// @dev Internal helper for atomic create+respond per item.
    ///      Must be external for try/catch but restricted to self-calls only.
    function _createAndRespond(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        bytes calldata signatureData,
        bytes calldata attestationData
    ) external {
        require(msg.sender == address(this), Unauthorized());
        taskManager.createNewTask(task);
        taskManager.respondToTask(task, taskResponse, signatureData, attestationData);
    }
}
