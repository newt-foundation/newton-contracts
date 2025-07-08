// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.12;

import {INewtonClient, NewtonMessage} from "../../interfaces/INewtonClient.sol";
import {NewtonClientWrapper} from "./NewtonClientWrapper.sol";
import {INewtonProtected} from "./INewtonProtected.sol";

abstract contract NewtonProtected is INewtonProtected {
    // note: this should be namespaced storage in a real impl
    bool private _newtonWrapperEnabled;
    NewtonClientWrapper private _newtonWrapper;

    event NewtonWrapperSet(address indexed _newtonWrapper);
    event NewtonWrapperEnabled();
    event NewtonWrapperDisabled();

    modifier withNewton(
        address _sender,
        address _receiver,
        uint256 _amount,
        uint256 _value,
        NewtonMessage calldata _message
    ) {
        if (_newtonWrapperEnabled) {
            require(address(_newtonWrapper) != address(0), "NewtonProtected: newton wrapper not set");
            _newtonWrapper.sendCoinNewton(_sender, _receiver, _amount, _value, _message);
        }
        _;
    }

    function getNewtonWrapper() external view returns (address) {
        return address(_newtonWrapper);
    }

    function _setNewtonWrapper(
        address _newtonWrapperAddress
    ) internal {
        _newtonWrapper = NewtonClientWrapper(_newtonWrapperAddress);
        emit NewtonWrapperSet(_newtonWrapperAddress);
    }

    function _enableNewtonWrapper() internal {
        _newtonWrapperEnabled = true;
        emit NewtonWrapperEnabled();
    }

    function _disableNewtonWrapper() internal {
        _newtonWrapperEnabled = false;
        emit NewtonWrapperDisabled();
    }
}
