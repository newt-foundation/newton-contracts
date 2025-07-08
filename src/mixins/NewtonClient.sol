// SPDX-License-Identifier: MIT

pragma solidity ^0.8.12;

import {INewtonManager, Task} from "../interfaces/INewtonManager.sol";
import "../interfaces/INewtonClient.sol";

abstract contract NewtonClient is INewtonClient {
    /// @notice Struct to contain stateful values for NewtonClient-type contracts
    /// @custom:storage-location erc7201:newton.storage.NewtonClient
    struct NewtonClientStorage {
        INewtonManager serviceManager;
        string policyID;
    }

    /// @notice the storage slot for the NewtonClientStorage struct
    /// @dev keccak256(abi.encode(uint256(keccak256("newton.storage.NewtonClient")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _PREDICATE_CLIENT_STORAGE_SLOT =
        0x804776a84f3d03ad8442127b1451e2fbbb6a715c681d6a83c9e9fca787b99300;

    function _getNewtonClientStorage() private pure returns (NewtonClientStorage storage $) {
        assembly {
            $.slot := _PREDICATE_CLIENT_STORAGE_SLOT
        }
    }

    function _initNewtonClient(address _serviceManagerAddress, string memory _policyID) internal {
        NewtonClientStorage storage $ = _getNewtonClientStorage();
        $.serviceManager = INewtonManager(_serviceManagerAddress);
        _setPolicy(_policyID);
    }

    function _setPolicy(
        string memory _policyID
    ) internal {
        NewtonClientStorage storage $ = _getNewtonClientStorage();
        $.policyID = _policyID;
        $.serviceManager.setPolicy(_policyID);
    }

    function getPolicy() external view override returns (string memory) {
        return _getPolicy();
    }

    function _getPolicy() internal view returns (string memory) {
        return _getNewtonClientStorage().policyID;
    }

    function _setNewtonManager(
        address _newtonManager
    ) internal {
        NewtonClientStorage storage $ = _getNewtonClientStorage();
        $.serviceManager = INewtonManager(_newtonManager);
    }

    function getNewtonManager() external view override returns (address) {
        return _getNewtonManager();
    }

    function _getNewtonManager() internal view returns (address) {
        return address(_getNewtonClientStorage().serviceManager);
    }

    modifier onlyNewtonServiceManager() {
        if (msg.sender != address(_getNewtonClientStorage().serviceManager)) {
            revert NewtonClient__Unauthorized();
        }
        _;
    }

    /**
     *
     * @notice Validates the transaction by checking the zk proof.
     */
    function _authorizeTransaction(
        NewtonMessage memory _newtonMessage,
        bytes memory _encodedSigAndArgs,
        address _msgSender,
        uint256 _value
    ) internal returns (bool) {
        NewtonClientStorage storage $ = _getNewtonClientStorage();
        Task memory task = Task({
            msgSender: _msgSender,
            target: address(this),
            value: _value,
            encodedSigAndArgs: _encodedSigAndArgs,
            policyID: $.policyID,
            taskId: _newtonMessage.taskId,
            expireByTime: _newtonMessage.expireByTime
        });
        return
            $.serviceManager.verify(task, _newtonMessage.input, _newtonMessage.proof);
    }
}
