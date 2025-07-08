// SPDX-License-Identifier: MIT

pragma solidity ^0.8.12;

import {INewtonManager} from "../interfaces/INewtonManager.sol";

/// @notice Struct that bundles together a task's parameters for validation
struct NewtonMessage {
    // the unique identifier for the task
    string taskId;
    // the Timestamp expiry for the task
    uint256 expireByTime;
    // the input data for the task
    bytes input;
    // the proof for the task
    bytes proof;
}

/// @notice error type for unauthorized access
error NewtonClient__Unauthorized();

/// @notice Interface for a NewtonClient-type contract that enables clients to define execution rules or parameters for tasks they submit
interface INewtonClient {
    /**
     * @notice Sets a policy for the calling address, associating it with a policy document stored on IPFS.
     * @param _policyID A string representing the policyID from on chain.
     * @dev This function enables clients to define execution rules or parameters for tasks they submit.
     *      The policy governs how tasks submitted by the caller are executed, ensuring compliance with predefined rules.
     */
    function setPolicy(
        string memory _policyID
    ) external;

    /**
     * @notice Retrieves the policy for the calling address.
     * @return The policyID associated with the calling address.
     */
    function getPolicy() external view returns (string memory);

    /**
     * @notice Function for setting the Newton ServiceManager
     * @param _newtonManager address of the service manager
     */
    function setNewtonManager(
        address _newtonManager
    ) external;

    /**
     * @notice Function for getting the Newton ServiceManager
     * @return address of the service manager
     */
    function getNewtonManager() external view returns (address);
}
