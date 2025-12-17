// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {
    AccessControlUpgradeable
} from "@openzeppelin-upgrades/contracts/access/AccessControlUpgradeable.sol";
import {ERC20Upgradeable} from "@openzeppelin-upgrades/contracts/token/ERC20/ERC20Upgradeable.sol";
import {
    ERC20BurnableUpgradeable
} from "@openzeppelin-upgrades/contracts/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import {
    ERC20PermitUpgradeable
} from "@openzeppelin-upgrades/contracts/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {Initializable} from "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin-upgrades/contracts/proxy/utils/UUPSUpgradeable.sol";

contract MockToken is
    Initializable,
    ERC20Upgradeable,
    ERC20BurnableUpgradeable,
    AccessControlUpgradeable,
    ERC20PermitUpgradeable,
    UUPSUpgradeable
{
    error ERC20CapExceeded();
    error CapMustBeGreaterThan0();
    error UpgradesDisabled(address newImplementation);

    uint256 private _cap;
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor() {
        _disableInitializers();
    }

    function initialize(
        string memory name,
        string memory symbol,
        uint256 cap_,
        address defaultAdmin,
        address[] memory minters
    ) public initializer {
        require(cap_ > 0, CapMustBeGreaterThan0());
        _cap = cap_;
        __ERC20_init(name, symbol);
        __ERC20Burnable_init();
        __AccessControl_init();
        __ERC20Permit_init(name);
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        for (uint256 i = 0; i < minters.length; i++) {
            _grantRole(MINTER_ROLE, minters[i]);
        }
    }

    function supplyCap() public view returns (uint256) {
        return _cap;
    }

    function mint(
        address to,
        uint256 amount
    ) public onlyRole(MINTER_ROLE) {
        require(totalSupply() + amount <= supplyCap(), ERC20CapExceeded());
        _mint(to, amount);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {
        revert UpgradesDisabled(newImplementation);
    }
}
