// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.12;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {NewtonClient} from "../../mixins/NewtonClient.sol";
import {NewtonMessage} from "../../interfaces/INewtonClient.sol";
import {INewtonManager} from "../../interfaces/INewtonManager.sol";

contract MetaCoin is NewtonClient, Ownable {
    mapping(address => uint256) public balances;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);

    constructor(address _owner, address _serviceManager, string memory _policyID) Ownable(_owner) {
        balances[_owner] = 10_000_000_000_000;
        _initNewtonClient(_serviceManager, _policyID);
    }

    function sendCoin(address _receiver, uint256 _amount, NewtonMessage calldata _message) external payable {
        bytes memory encodedSigAndArgs = abi.encodeWithSignature("_sendCoin(address,uint256)", _receiver, _amount);
        require(
            _authorizeTransaction(_message, encodedSigAndArgs, msg.sender, msg.value),
            "MetaCoin: unauthorized transaction"
        );

        // business logic function that is protected
        _sendCoin(_receiver, _amount);
    }

    function setPolicy(
        string memory _policyID
    ) external onlyOwner {
        _setPolicy(_policyID);
    }

    function setNewtonManager(
        address _newtonManager
    ) public onlyOwner {
        _setNewtonManager(_newtonManager);
    }

    function _sendCoin(address _receiver, uint256 _amount) internal {
        require(balances[msg.sender] >= _amount, "MetaCoin: insufficient balance");
        balances[msg.sender] -= _amount;
        balances[_receiver] += _amount;
        emit Transfer(msg.sender, _receiver, _amount);
    }

    function getBalance(
        address _addr
    ) public view returns (uint256) {
        return balances[_addr];
    }
}
