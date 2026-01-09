// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @title ISemVerMixin
/// @notice A mixin interface that provides semantic versioning functionality.
/// @dev Follows SemVer 2.0.0 specification (https://semver.org/)
interface ISemVerMixin {
    /// @notice Returns the semantic version string of the contract.
    /// @return The version string in SemVer format (e.g., "1.0.0")
    function version() external view returns (string memory);
}

