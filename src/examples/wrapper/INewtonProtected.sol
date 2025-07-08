// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.8.12;

interface INewtonProtected {
    function getNewtonWrapper() external view returns (address);
    function setNewtonWrapper(
        address _newtonWrapperAddress
    ) external;
    function enableNewtonWrapper() external;
    function disableNewtonWrapper() external;
}
