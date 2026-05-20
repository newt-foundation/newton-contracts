// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

/// @notice ProxyAdmin with explicit initial owner for deterministic (CREATE2) deployment.
/// OZ v4 Ownable sets msg.sender as owner in the constructor. When deployed via CREATE2
/// in a forge script, msg.sender is the broadcasting EOA — but that coupling is fragile.
/// This contract accepts an explicit owner to make ownership deterministic regardless of
/// the deployment context.
contract NewtonProxyAdmin is ProxyAdmin {
    constructor(
        address initialOwner
    ) {
        require(initialOwner != address(0), "NewtonProxyAdmin: zero owner");
        _transferOwnership(initialOwner);
    }
}
