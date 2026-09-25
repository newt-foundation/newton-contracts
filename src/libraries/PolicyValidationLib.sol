// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";

/**
 * @title PolicyValidationLib
 * @dev Library for policy and data validation
 */
library PolicyValidationLib {
    error PolicyIdMismatch();
    error PolicyAddressMismatch();
    error PolicyDataLengthMismatch();
    error PolicyDataAddressMismatch();
    error PolicyDataExpired();

    /**
     * @dev Validates policy data addresses and expiry.
     * @notice Called during respondToTask to validate operator-generated policyTaskData.
     */
    function validatePolicyData(
        address policyAddress,
        NewtonMessage.PolicyTaskData calldata policyTaskData,
        uint32 currentBlock
    ) external view {
        address[] memory policyDataAddresses = INewtonPolicy(policyAddress).getPolicyData();
        NewtonMessage.PolicyData[] memory policyData = policyTaskData.policyData;

        require(policyData.length == policyDataAddresses.length, PolicyDataLengthMismatch());

        for (uint256 i; i < policyDataAddresses.length;) {
            require(
                policyData[i].policyDataAddress == policyDataAddresses[i],
                PolicyDataAddressMismatch()
            );

            require(policyData[i].expireBlock >= currentBlock, PolicyDataExpired());

            unchecked {
                ++i;
            }
        }
    }
}
