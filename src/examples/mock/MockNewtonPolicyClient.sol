// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {NewtonPolicyClient} from "../../mixins/NewtonPolicyClient.sol";
import {NewtonMessage} from "../../core/NewtonMessage.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";

contract MockNewtonPolicyClient is NewtonPolicyClient, OwnableUpgradeable {
    // Errors
    error InvalidAttestation();
    error IntentExecutionFailed();

    // Events
    /* Token Deposits */
    event Deposit(address indexed clientAddress, address token, uint256 tokenAmount);
    /* Token Withdrawals */
    event Withdraw(address indexed clientAddress, address token, uint256 tokenAmount);
    /* Intent Execution */
    event IntentExecuted(address indexed clientAddress, NewtonMessage.Intent intent);

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address policyTaskManager,
        address policy,
        address owner
    ) public initializer {
        _initNewtonPolicyClient(policyTaskManager, policy, owner);
        __Ownable_init();
        _transferOwnership(owner);
    }

    function setOwner(
        address _owner
    ) external onlyOwner {
        _transferOwnership(_owner);
        NewtonPolicyClient(address(this)).setPolicyClientOwner(_owner);
    }

    function deposit(address token, uint256 tokenAmount) external onlyOwner {
        IERC20(token).transferFrom(msg.sender, address(this), tokenAmount);
        emit Deposit(address(this), token, tokenAmount);
    }

    function balanceOf(
        address token
    ) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }

    function withdraw(address token, uint256 tokenAmount) external onlyOwner {
        IERC20(token).transfer(msg.sender, tokenAmount);
        emit Withdraw(address(this), token, tokenAmount);
    }

    function executeIntent(
        NewtonMessage.Attestation calldata attestation
    ) external returns (bytes memory) {
        require(_validateAttestation(attestation), InvalidAttestation());
        NewtonMessage.Intent memory intent = attestation.intent;

        // Send the raw call and capture return data
        (bool success, bytes memory returnData) = intent.to.call{value: intent.value}(intent.data);
        if (!success) {
            // Bubble up the revert error if there's return data, otherwise use generic error
            if (returnData.length > 0) {
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(32, returnData), returnDataSize)
                }
            } else {
                revert IntentExecutionFailed();
            }
        }

        emit IntentExecuted(address(this), intent);
        return returnData;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
