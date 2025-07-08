// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

/// @notice Interface for a NewtonPolicyClient-type contract that enables clients to define execution rules or parameters for tasks they submit
interface INewtonPolicyClient is IERC165 {
    /// @notice error for when validate() is called with an incorrect policyID
    error InvalidPolicyID();

    /**
     * @notice Retrieves the policyID for the calling address.
     * @return The policyID associated with the calling address.
     */
    function getPolicyId() external view returns (bytes32);

    /**
     * @notice Retrieves the policy address for the calling address.
     * @return The policy address associated with the calling address.
     */
    function getPolicyAddress() external view returns (address);

    /**
     * @notice Function for getting the Newton PolicyTaskManager
     * @return address of the policy task manager
     */
    function getNewtonPolicyTaskManager() external view returns (address);
}
