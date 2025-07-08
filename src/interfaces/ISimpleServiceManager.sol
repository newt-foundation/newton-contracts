// SPDX-License-Identifier: MIT

pragma solidity ^0.8.12;

import {Task} from "./INewtonManager.sol";

/**
 * @title Minimal interface for a ServiceManager-type contract that forms the single point for an AVS to push updates to EigenLayer
 * @author Newton Labs, Inc
 */
interface ISimpleServiceManager {
    /**
     * @notice Sets a policy ID for the sender, defining execution rules or parameters for tasks
     * @param policyID string pointing to the policy details
     * @dev Only callable by client contracts or EOAs to associate a policy with their address
     * @dev Emits a SetPolicy event upon successful association
     */
    function setPolicy(
        string memory policyID
    ) external;

    /**
     * @notice Verifies if a task is authorized by the required number of operators
     * @param _task Parameters of the task including sender, target, function signature, arguments, quorum count, and expiry block
     * @param input the input data for the task
     * @param proof the proof for the task
     * @return isVerified Boolean indicating if the task has been verified by the required number of operators
     */
    function verify(
        Task memory _task,
        bytes memory input,
        bytes memory proof
    ) external returns (bool isVerified);
}
