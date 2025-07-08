// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.12;

import {NewtonClient} from "../../mixins/NewtonClient.sol";
import {NewtonMessage} from "../../interfaces/INewtonClient.sol";
import {INewtonManager} from "../../interfaces/INewtonManager.sol";

contract NewtonClientWrapper is NewtonClient {
    constructor(address _serviceManager, string memory _policyID) {
        _initNewtonClient(_serviceManager, _policyID);
    }

    function sendCoinNewton(
        address _sender,
        address _receiver,
        uint256 _amount,
        uint256 _value,
        NewtonMessage calldata _message
    ) external {
        // you can do some additional checks or pre-processing here
        // ...
        bytes memory encodedSigAndArgs = abi.encodeWithSignature("_sendCoin(address,uint256)", _receiver, _amount);
        require(
            _authorizeTransaction(_message, encodedSigAndArgs, _sender, _value),
            "NewtonClientWrapper: unauthorized transaction"
        );
    }

    function setPolicy(
        string memory _policyID
    ) external {
        _setPolicy(_policyID);
    }

    function setNewtonManager(
        address _newtonManager
    ) public {
        _setNewtonManager(_newtonManager);
    }
}
