// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.12;

import {INewtonClient, NewtonMessage} from "../../interfaces/INewtonClient.sol";
import {NewtonClientProxy} from "./NewtonClientProxy.sol";
import {INewtonProtected} from "./INewtonProtected.sol";

abstract contract NewtonProtected is INewtonProtected {
    // note: this should be namespaced storage in a real impl
    bool private _newtonProxyEnabled;
    NewtonClientProxy private _newtonProxy;

    event NewtonProxySet(address indexed _newtonProxy);
    event NewtonProxyEnabled();
    event NewtonProxyDisabled();

    modifier onlyNewtonProxy() {
        if (_newtonProxyEnabled) {
            require(address(_newtonProxy) != address(0), "NewtonProtected: newton proxy not set");
            require(
                msg.sender == address(_newtonProxy),
                "NewtonProtected: only newton proxy can call this function"
            );
        }
        _;
    }

    function getNewtonProxy() external view returns (address) {
        return address(_newtonProxy);
    }

    function _setNewtonProxy(
        address _newtonProxyAddress
    ) internal {
        _newtonProxy = NewtonClientProxy(_newtonProxyAddress);
        emit NewtonProxySet(_newtonProxyAddress);
    }

    function _enableNewtonProxy() internal {
        _newtonProxyEnabled = true;
        emit NewtonProxyEnabled();
    }

    function _disableNewtonProxy() internal {
        _newtonProxyEnabled = false;
        emit NewtonProxyDisabled();
    }
}
