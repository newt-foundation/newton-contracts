// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/**
 * @title IOperatorRegistry
 * @notice Interface for OperatorRegistry contract functions
 * @dev This interface defines the external functions needed for operator management
 */
interface IOperatorRegistry {
    /**
     * @notice Check if an operator is whitelisted
     * @param operator The operator address to check
     * @return True if the operator is whitelisted, false otherwise
     */
    function isOperatorWhitelisted(
        address operator
    ) external view returns (bool);

    /**
     * @notice Check if an address is a task generator
     * @param generator The address to check
     * @return True if the address is a task generator, false otherwise
     */
    function isTaskGenerator(
        address generator
    ) external view returns (bool);
}
