// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {OwnableUpgradeable} from "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";

/// @title AdminMixin
/// @notice Shared access control for Newton contracts: owner (Safe) + guardian (ADMIN_ROLE).
/// @dev Uses ERC-7201 namespaced storage to avoid shifting the storage layout of inheriting
///      contracts. The role data lives at keccak256("newton.storage.AdminMixin") - 1, so
///      inserting this mixin into an existing inheritance chain has zero slot impact.
abstract contract AdminMixin is OwnableUpgradeable {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    error NotAdminOrOwner();
    error AdminAddressZero();

    /// @dev ERC-7201 namespaced storage for admin role data.
    /// @custom:storage-location erc7201:newton.storage.AdminMixin
    struct AdminStorage {
        mapping(bytes32 => mapping(address => bool)) roleMembers;
        mapping(bytes32 => bytes32) roleAdmin;
        address defaultAdmin;
    }

    // keccak256(abi.encode(uint256(keccak256("newton.storage.AdminMixin")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ADMIN_STORAGE_SLOT =
        0x6f14bdd5483d71ceb730ff4b462ada06c64ffdbf634fac0d2e342068d7faba00;

    function _getAdminStorage() private pure returns (AdminStorage storage s) {
        bytes32 slot = ADMIN_STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    modifier onlyAdmin() {
        AdminStorage storage s = _getAdminStorage();
        if (!s.roleMembers[ADMIN_ROLE][msg.sender] && msg.sender != owner()) {
            revert NotAdminOrOwner();
        }
        _;
    }

    function hasRole(
        bytes32 role,
        address account
    ) public view returns (bool) {
        return _getAdminStorage().roleMembers[role][account];
    }

    function grantRole(
        bytes32 role,
        address account
    ) external onlyOwner {
        _getAdminStorage().roleMembers[role][account] = true;
    }

    function revokeRole(
        bytes32 role,
        address account
    ) external onlyOwner {
        _getAdminStorage().roleMembers[role][account] = false;
    }

    function _initializeAdmin(
        address admin
    ) internal {
        if (admin == address(0)) revert AdminAddressZero();
        AdminStorage storage s = _getAdminStorage();
        s.defaultAdmin = owner();
        s.roleMembers[ADMIN_ROLE][admin] = true;
    }

    /// @dev Override to migrate admin roles when ownership is transferred.
    function transferOwnership(
        address newOwner
    ) public virtual override onlyOwner {
        AdminStorage storage s = _getAdminStorage();
        address previousOwner = owner();
        if (previousOwner != address(0)) {
            s.defaultAdmin = newOwner;
        }
        super.transferOwnership(newOwner);
    }
}
