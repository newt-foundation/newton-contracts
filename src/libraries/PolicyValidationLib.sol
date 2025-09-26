// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";
import {INewtonPolicyData} from "../interfaces/INewtonPolicyData.sol";
import {INewtonPolicyClient} from "../interfaces/INewtonPolicyClient.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";
import {ChainLib} from "./ChainLib.sol";

/**
 * @title PolicyValidationLib
 * @dev Library for policy and data validation
 */
library PolicyValidationLib {
    error PolicyIdMismatch();
    error PolicyAddressMismatch();
    error PolicyDataLengthMismatch();
    error PolicyDataAddressMismatch();
    error PolicyDataAttestationFailed();
    error PolicyDataExpired();
    error PolicyNotVerified();
    error PolicyDataNotVerified();

    /**
     * @dev Checks if the policy is a verified policy. Only used for mainnet.
     */
    function checkVerifiedPolicy(
        address policyClient,
        NewtonMessage.PolicyTaskData calldata policyTaskData
    ) external view returns (address policyAddress, bytes32 policyId) {
        policyAddress = INewtonPolicyClient(policyClient).getPolicyAddress();
        policyId = INewtonPolicyClient(policyClient).getPolicyId();

        require(policyTaskData.policyId == policyId, PolicyIdMismatch());
        require(policyTaskData.policyAddress == policyAddress, PolicyAddressMismatch());

        require(INewtonPolicy(policyAddress).isPolicyVerified(), PolicyNotVerified());
    }

    /**
     * @dev Validates policy data attestations
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

            require(
                INewtonPolicyData(policyTaskData.policyData[i].policyDataAddress)
                    .isPolicyDataVerified(),
                PolicyDataNotVerified()
            );

            require(
                INewtonPolicyData(policyDataAddresses[i]).attest(policyData[i]),
                PolicyDataAttestationFailed()
            );
            require(policyData[i].expireBlock >= currentBlock, PolicyDataExpired());

            unchecked {
                ++i;
            }
        }
    }
}
