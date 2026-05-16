// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @title IOperatorRegistryEpochGovernance
/// @notice Subset of `OperatorRegistryEpochGovernance` accessed by `OperatorRegistry`
///         and external readers (Rust ABI, off-chain consumers). Lives in its own
///         file so importers don't pull in the governance contract's full module
///         graph (the contract itself imports from `OperatorRegistry`, which would
///         create a circular dependency).
interface IOperatorRegistryEpochGovernance {
    function consumeDeregisterApproval(
        address operator
    ) external;
    /// @notice Clear a stored deregister approval without consuming it. Called
    ///         on the ejector bypass path so per-epoch dereg buckets stay
    ///         exact across emergency dereg.
    function cancelDeregisterApproval(
        address operator
    ) external;
    function epochDurationBlocks() external view returns (uint32);
    function currentEpoch() external view returns (uint32);
}
