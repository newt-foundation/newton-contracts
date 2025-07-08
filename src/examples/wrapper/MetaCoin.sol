// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.12;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {NewtonProtected} from "./NewtonProtected.sol";
import {NewtonMessage} from "../../interfaces/INewtonClient.sol";

contract MetaCoin is Ownable, NewtonProtected {
    mapping(address => uint256) public balances;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);

    constructor(address _owner, address _newtonWrapperAddress) Ownable(_owner) {
        balances[_owner] = 10_000_000_000_000;
        _setNewtonWrapper(_newtonWrapperAddress);
        transferOwnership(_owner);
    }

    function sendCoin(
        address _receiver,
        uint256 _amount,
        NewtonMessage calldata _message
    ) external payable withNewton(msg.sender, _receiver, _amount, msg.value, _message) {
        _sendCoin(_receiver, _amount);
    }

    function _sendCoin(address _receiver, uint256 _amount) internal {
        require(balances[msg.sender] >= _amount, "MetaCoin: insufficient balance");
        balances[msg.sender] -= _amount;
        balances[_receiver] += _amount;
        emit Transfer(msg.sender, _receiver, _amount);
    }

    function getBalance(
        address _addr
    ) external view returns (uint256) {
        return balances[_addr];
    }

    function setNewtonWrapper(
        address _newtonWrapperAddress
    ) external override onlyOwner {
        _setNewtonWrapper(_newtonWrapperAddress);
    }

    function enableNewtonWrapper() external override onlyOwner {
        _enableNewtonWrapper();
    }

    function disableNewtonWrapper() external override onlyOwner {
        _disableNewtonWrapper();
    }
}
