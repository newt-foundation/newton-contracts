// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";
import {INewtonPolicyClient} from "../interfaces/INewtonPolicyClient.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {PolicyValidationLib} from "./PolicyValidationLib.sol";

/**
 * @title TaskLib
 * @dev Library for task evaluation and result processing
 */
library TaskLib {
    /* CUSTOM ERRORS */
    error TaskMismatch();
    error InvalidPolicyId();
    error InvalidPolicyAddress();
    error TaskAlreadyResponded();
    error TaskResponseTooLate(
        uint32 blockNumber, uint32 taskCreatedBlock, uint32 taskResponseWindowBlock
    );
    error OnlyPolicyClient();
    error InvalidPolicyClient();
    error InterfaceNotSupported();
    error InvalidIntent();

    /* FUNCTIONS */

    function createTask(
        bytes32 taskId,
        uint32 nonce,
        address policyClient,
        NewtonMessage.Intent calldata intent,
        NewtonMessage.PolicyTaskData calldata policyTaskData,
        bytes calldata quorumNumbers,
        uint32 quorumThresholdPercentage
    ) external view returns (INewtonProverTaskManager.Task memory) {
        require(intent.from != address(0) && intent.to != address(0), InvalidIntent());

        // Validate policy client and get basic info
        (address policyAddress, bytes32 policyId) =
            PolicyValidationLib.checkVerifiedPolicy(policyClient, policyTaskData);

        uint32 currentBlock = uint32(block.number);

        // Validate policy data attestations
        PolicyValidationLib.validatePolicyData(policyAddress, policyTaskData, currentBlock);

        // Create task
        INewtonProverTaskManager.Task memory newTask = INewtonProverTaskManager.Task({
            taskId: taskId,
            nonce: nonce,
            intent: intent,
            policyId: policyId,
            policyClient: policyClient,
            policyTaskData: policyTaskData,
            policyConfig: INewtonPolicy(policyAddress).getPolicyConfig(policyId),
            taskCreatedBlock: currentBlock,
            quorumNumbers: quorumNumbers,
            quorumThresholdPercentage: quorumThresholdPercentage
        });

        return newTask;
    }

    /**
     * @dev Evaluates the result of a task execution
     * @param evaluationResult The result data to evaluate
     * @return bool True if the result indicates success/true
     */
    function evaluateResult(
        bytes memory evaluationResult
    ) external pure returns (bool) {
        uint256 length = evaluationResult.length;

        // Case 1: ABI-encoded bool true (32 bytes)
        if (length == 32) {
            uint256 val;
            assembly {
                val := mload(add(evaluationResult, 32))
            }
            return val == 1;
        }

        // Case 2: ABI-encoded "true" string (96+ bytes)
        if (length >= 96) {
            uint256 strLen;
            assembly {
                strLen := mload(add(evaluationResult, 64))
            }
            if (strLen == 4) {
                bytes32 strData;
                assembly {
                    strData := mload(add(evaluationResult, 96))
                }
                return strData == 0x7472756500000000000000000000000000000000000000000000000000000000;
            }
        }

        return false;
    }

    /**
     * @dev Sanity checks the task response. Throws if any of the checks fail.
     * @param task The task
     * @param taskResponse The task response
     * @param blockNumber The block number
     * @param responseWindowBlock The response window block
     */
    function sanityCheckTaskResponse(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        uint32 blockNumber,
        uint32 responseWindowBlock
    ) external pure {
        require(taskResponse.policyId == task.policyId, InvalidPolicyId());
        require(taskResponse.policyClient == task.policyClient, InvalidPolicyClient());
        require(
            taskResponse.policyAddress == task.policyTaskData.policyAddress, InvalidPolicyAddress()
        );
        require(
            blockNumber <= task.taskCreatedBlock + responseWindowBlock,
            TaskResponseTooLate(blockNumber, task.taskCreatedBlock, responseWindowBlock)
        );
    }

    function sanityCheckAttestation(
        NewtonMessage.Attestation calldata attestation
    ) external view {
        require(
            attestation.policyId == INewtonPolicyClient(attestation.policyClient).getPolicyId(),
            PolicyValidationLib.PolicyIdMismatch()
        );
    }

    // onlyAttestationClient is used to restrict validateAttestation from only being called by the correct policy client
    function onlyAttestationClient(
        NewtonMessage.Attestation calldata attestation
    ) external view {
        require(msg.sender.code.length > 0, OnlyPolicyClient());

        bytes4 interfaceId = type(INewtonPolicyClient).interfaceId;

        (bool success, bytes memory result) = msg.sender
            .staticcall(abi.encodeWithSelector(IERC165.supportsInterface.selector, interfaceId));

        require(
            success && result.length == 32 && abi.decode(result, (bool)), InterfaceNotSupported()
        );

        require(msg.sender == attestation.policyClient, InvalidPolicyClient());
    }
}
