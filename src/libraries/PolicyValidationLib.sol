// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";
import {INewtonPolicyFactoryRegistry} from "../interfaces/INewtonPolicyFactory.sol";
import {ISemVerMixin} from "../interfaces/ISemVerMixin.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";
import {
    MAX_POLICIES,
    MAX_POLICY_FIELD_BYTES,
    MAX_RESPONSE_POLICY_BYTES,
    MAX_TASK_POLICY_BYTES,
    POLICY_SET_DOMAIN
} from "./PolicyConstants.sol";
import {VersionLib} from "./VersionLib.sol";
import {TaskManagerErrors} from "./TaskManagerErrors.sol";

/**
 * @title PolicyValidationLib
 * @dev Library for policy set validation at task admission and response time
 */
library PolicyValidationLib {
    /* CUSTOM ERRORS */
    error PolicySetEmpty();
    error PolicySetTooLarge();
    error PolicyDataExpired();
    error ResponseLengthMismatch();
    error RegoCodeHashMismatch(uint256 index);
    error PolicyAddressMismatch(uint256 index);
    error WasmArgsMismatch(uint256 index);
    error PureRegoInputNotEmpty(uint256 index);
    error PureRegoOutputNotEmpty(uint256 index);
    error InvalidOracleOutput(uint256 index);
    error IncompatiblePolicyVersion(uint256 index, string actual, string minimum);
    error PolicyParamsTooLarge(uint256 index, uint256 size);
    error PolicyInputTooLarge(uint256 index, uint256 size);
    error PolicyRegoTooLarge(uint256 index, uint256 size);
    error OracleOutputTooLarge(uint256 index, uint256 size);
    error PolicyNotFromActiveFactory(uint256 index, address policy);
    error TaskPolicyDataTooLarge(uint256 size);

    /// @notice The commitment a task's carried policy snapshot must reproduce on `chainId`.
    /// @dev Byte-for-byte identical to `NewtonPolicyClient._setPolicies`'s derivation, so a
    /// caller-supplied snapshot can never diverge from the set the client accepted. `chainId` is
    /// a parameter (not `block.chainid`) so the destination-chain challenge path can reproduce a
    /// source-created task's commitment.
    function computePolicySetId(
        uint256 chainId,
        INewtonProverTaskManager.Task calldata task
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                POLICY_SET_DOMAIN, chainId, task.policyClient, task.policyRevision, task.policies
            )
        );
    }

    /// @notice Requires `task.policyId` to match the recomputed commitment on this chain.
    function requirePolicySnapshot(
        INewtonProverTaskManager.Task calldata task
    ) internal view {
        require(
            computePolicySetId(block.chainid, task) == task.policyId,
            TaskManagerErrors.PolicySnapshotMismatch()
        );
    }

    /// @notice Every policy a task freezes must still come from the currently configured factory.
    /// @dev `NewtonPolicyClient._setPolicies` checks provenance against whichever factory was
    /// configured when the client accepted the set, and never revisits it. Rotating the task
    /// manager's factory would otherwise leave an unreconfigured client admitting tasks built
    /// from retired-factory policies indefinitely. Fail-closed: such a client must re-run
    /// `setPolicies` before its tasks admit again, which is the intended cutover step.
    function requireActiveFactory(
        INewtonProverTaskManager.Task calldata task,
        address factory
    ) internal view {
        require(factory != address(0), TaskManagerErrors.InvalidPolicyFactory());

        uint256 count = task.policies.length;
        for (uint256 i; i < count;) {
            address policy = task.policies[i].policy;
            require(
                INewtonPolicyFactoryRegistry(factory).isPolicy(policy),
                PolicyNotFromActiveFactory(i, policy)
            );

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Bound the dynamically sized policy data a task carries, before any policy runs.
    /// @dev The policy count is capped but params and inputs are not, so without this one task
    /// can mint arbitrary calldata, event data, operator allocations and proof input. Both the
    /// per-field and the aggregate cap are checked: the product of MAX_POLICIES and the per-field
    /// cap is far looser than what actually bounds a task.
    function requirePolicyDataBounds(
        INewtonProverTaskManager.Task calldata task
    ) internal pure {
        uint256 count = task.policies.length;
        require(count != 0, PolicySetEmpty());
        require(count <= MAX_POLICIES, PolicySetTooLarge());
        require(task.wasmArgs.length == count, ResponseLengthMismatch());

        uint256 total;
        for (uint256 i; i < count;) {
            uint256 paramsLen = task.policies[i].config.policyParams.length;
            uint256 inputLen = task.wasmArgs[i].length;
            require(paramsLen <= MAX_POLICY_FIELD_BYTES, PolicyParamsTooLarge(i, paramsLen));
            require(inputLen <= MAX_POLICY_FIELD_BYTES, PolicyInputTooLarge(i, inputLen));
            total += paramsLen + inputLen;

            unchecked {
                ++i;
            }
        }

        require(total <= MAX_TASK_POLICY_BYTES, TaskPolicyDataTooLarge(total));
    }

    /// @notice Validates a task response against the policy set its task is frozen to, and
    /// returns the certificate expiry: the minimum `expireAfter` across the set, so a
    /// certificate never outlives its shortest-lived entry.
    function validateResponse(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        string memory minPolicyVersion
    ) internal view returns (uint32 minExpireAfterBlocks) {
        uint256 count = task.policies.length;
        require(count != 0, PolicySetEmpty());
        require(count <= MAX_POLICIES, PolicySetTooLarge());
        require(
            taskResponse.policyTaskData.length == count && task.wasmArgs.length == count,
            ResponseLengthMismatch()
        );
        require(taskResponse.policyId == task.policyId, TaskManagerErrors.PolicyIdMismatch());

        minExpireAfterBlocks = type(uint32).max;
        uint256 totalBytes;
        uint32 currentBlock = uint32(block.number);

        for (uint256 i; i < count;) {
            address policyAddress = task.policies[i].policy;
            INewtonPolicy policy = INewtonPolicy(policyAddress);
            NewtonMessage.PolicyTaskData calldata ptd = taskResponse.policyTaskData[i];

            uint256 paramsLen = task.policies[i].config.policyParams.length;
            uint256 inputLen = task.wasmArgs[i].length;
            uint256 regoLen = ptd.policy.length;
            require(paramsLen <= MAX_POLICY_FIELD_BYTES, PolicyParamsTooLarge(i, paramsLen));
            require(inputLen <= MAX_POLICY_FIELD_BYTES, PolicyInputTooLarge(i, inputLen));
            require(regoLen <= MAX_POLICY_FIELD_BYTES, PolicyRegoTooLarge(i, regoLen));
            totalBytes += paramsLen + inputLen + regoLen;

            // The response's own identity fields are signed but otherwise unread; bind them to
            // the task so a consumer can never observe authenticated evidence that disagrees
            // with the set the task froze.
            require(ptd.policyAddress == policyAddress, PolicyAddressMismatch(i));
            require(ptd.policyId == task.policyId, TaskManagerErrors.PolicyIdMismatch());

            require(keccak256(ptd.policy) == policy.getPolicyCodeHash(), RegoCodeHashMismatch(i));

            bool hasOracle = bytes(policy.getWasmCid()).length != 0;
            if (!hasOracle) {
                require(inputLen == 0, PureRegoInputNotEmpty(i));
                require(ptd.policyData.length == 0, PureRegoOutputNotEmpty(i));
            } else {
                require(ptd.policyData.length == 1, InvalidOracleOutput(i));
                require(ptd.policyData[0].expireBlock >= currentBlock, PolicyDataExpired());
                bytes calldata output = ptd.policyData[0].data;
                uint256 outputLen = output.length;
                require(outputLen <= MAX_POLICY_FIELD_BYTES, OracleOutputTooLarge(i, outputLen));
                totalBytes += outputLen;
                require(
                    outputLen > 1 && output[0] == "{" && output[outputLen - 1] == "}",
                    InvalidOracleOutput(i)
                );

                bytes calldata nestedWasmArgs = ptd.policyData[0].wasmArgs;
                require(
                    keccak256(nestedWasmArgs) == keccak256(task.wasmArgs[i]), WasmArgsMismatch(i)
                );
            }

            if (bytes(minPolicyVersion).length > 0) {
                string memory factoryVersion = ISemVerMixin(policy.factory()).version();
                require(
                    VersionLib.isCompatible(factoryVersion, minPolicyVersion),
                    IncompatiblePolicyVersion(i, factoryVersion, minPolicyVersion)
                );
            }

            uint32 e = task.policies[i].config.expireAfter;
            if (e < minExpireAfterBlocks) {
                minExpireAfterBlocks = e;
            }

            unchecked {
                ++i;
            }
        }

        require(totalBytes <= MAX_RESPONSE_POLICY_BYTES, TaskPolicyDataTooLarge(totalBytes));

        return minExpireAfterBlocks;
    }
}
