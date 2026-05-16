// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/**
 * @title IOperatorRegistry
 * @notice Minimal external surface used by other contracts (TaskManagers,
 *         IdentityRegistry, AddressesProviderConsumer mixin). The full
 *         queue-based mutator + epoch surface lives on the `OperatorRegistry`
 *         implementation contract — off-chain clients pick it up from the
 *         deployed contract ABI via alloy bindings, and on-chain governance
 *         scripts cast through `OperatorRegistry(addr)` directly.
 */
interface IOperatorRegistry {
    /// @notice Check if an operator is whitelisted.
    function isOperatorWhitelisted(
        address operator
    ) external view returns (bool);

    /// @notice Check if an address is a task generator.
    function isTaskGenerator(
        address generator
    ) external view returns (bool);

    /// @notice The active epoch duration in blocks (NEWT-1175 epoch governance).
    /// @dev Returns 0 during the bootstrap phase (before `OperatorRegistryEpochGovernance.initializeEpochs` runs);
    ///      callers that depend on a non-zero value (e.g., `TaskManager.epochBlocks()`)
    ///      must treat zero as a "not yet initialized" sentinel.
    function epochDurationBlocks() external view returns (uint32);
}
