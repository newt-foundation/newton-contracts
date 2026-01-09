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
    error PolicyNotVerified();
    error TaskResponseMismatch();
    error EntrypointMismatch();
    error TaskMismatch(bytes32 expected, bytes32 actual);
    error InvalidTaskId();
    error InvalidPolicyId();
    error InvalidPolicyAddress();
    error InvalidIntent();
    error InvalidIntentSignature();
    error TaskAlreadyResponded();
    error TaskResponseTooLate(
        uint32 blockNumber, uint32 taskCreatedBlock, uint32 taskResponseWindowBlock
    );
    error TaskResponseWindowNotPassed(
        uint32 blockNumber, uint32 taskCreatedBlock, uint32 taskResponseWindowBlock
    );
    error OnlyPolicyClient();
    error InvalidPolicyClient();
    error InterfaceNotSupported();
    error InvalidSourceOrDestination();
    error InvalidPolicyVersion(string actual, string minimum);
    error InvalidPolicyDataVersion(string actual, string minimum);

    /* FUNCTIONS */

    function createTask(
        INewtonProverTaskManager.TaskParams calldata params,
        uint32 nonce
    ) external view returns (INewtonProverTaskManager.Task memory) {
        require(
            params.intent.from != address(0) && params.intent.to != address(0),
            InvalidSourceOrDestination()
        );

        // Validate policy client and get basic info
        (address policyAddress, bytes32 policyId) =
            PolicyValidationLib.checkVerifiedPolicy(params.policyClient, params.policyTaskData);

        // NOTE: Version validation is performed off-chain by the gateway/operator
        // to reduce contract size and gas costs. See gateway/src/rpc/api/sync.rs
        // and operator/src/builder.rs for version compatibility checks.

        uint32 currentBlock = uint32(block.number);

        // Validate policy data attestations
        PolicyValidationLib.validatePolicyData(policyAddress, params.policyTaskData, currentBlock);

        // Create task
        INewtonProverTaskManager.Task memory newTask = INewtonProverTaskManager.Task({
            taskId: params.taskId,
            nonce: nonce,
            intent: params.intent,
            intentSignature: params.intentSignature,
            policyId: policyId,
            policyClient: params.policyClient,
            policyTaskData: params.policyTaskData,
            policyConfig: INewtonPolicy(policyAddress).getPolicyConfig(policyId),
            taskCreatedBlock: currentBlock,
            quorumNumbers: params.quorumNumbers,
            quorumThresholdPercentage: params.quorumThresholdPercentage
        });

        return newTask;
    }

    /**
     * @dev Evaluates the result of a task execution
     * @param evaluationResult The result data to evaluate
     * @return bool True if the result indicates success/true
     */
    // solhint-disable-next-line gas-calldata-parameters
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
        // solhint-disable-next-line gas-strict-inequalities
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
        require(taskResponse.taskId == task.taskId, InvalidTaskId());
        require(taskResponse.policyId == task.policyId, InvalidPolicyId());
        require(taskResponse.policyClient == task.policyClient, InvalidPolicyClient());
        require(
            taskResponse.policyAddress == task.policyTaskData.policyAddress, InvalidPolicyAddress()
        );
        require(
            keccak256(abi.encode(taskResponse.intent)) == keccak256(abi.encode(task.intent)),
            InvalidIntent()
        );
        require(
            keccak256(taskResponse.intentSignature) == keccak256(task.intentSignature),
            InvalidIntentSignature()
        );
        require(
            blockNumber < task.taskCreatedBlock + responseWindowBlock,
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

    function taskHash(
        INewtonProverTaskManager.Task calldata task
    ) external pure returns (bytes32) {
        return keccak256(
            abi.encode(
                task.taskId,
                task.intent,
                task.intentSignature,
                task.policyId,
                task.policyClient,
                task.policyTaskData,
                task.policyConfig,
                task.quorumNumbers,
                task.quorumThresholdPercentage
            )
        );
    }
}
