// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";

/**
 * @title IRegoVerifier
 * @notice Interface for RegoVerifier contract functions
 * @dev This interface defines the external functions needed for rego policy evaluation
 */
interface IRegoVerifier {
    // STRUCTS

    /// @notice The context of the policy-set evaluation. One entry per policy in
    ///         `task.policies` order in each array.
    /// @dev `policyCodeHashes[i]` is `keccak256` of the raw policy program bytes that the
    ///      SP1 circuit actually executed for policy `i`. The challenge path binds this to
    ///      `INewtonPolicy.getPolicyCodeHash()` so a caller cannot supply divergent
    ///      policy bytes in the zkVM and still slash an operator. The per-policy address and
    ///      module bytes are already reachable via `taskResponse.policyTaskData[i]`, so no
    ///      separate identity field is carried here.
    struct RegoContext {
        INewtonProverTaskManager.Task task;
        INewtonProverTaskManager.TaskResponse taskResponse;
        string[] entrypoints;
        bytes[] evaluations;
        bytes32[] policyCodeHashes;
    }

    /// @notice The entrypoint for verifying the proof of a rego policy evaluation.
    /// @param _publicValues The encoded public values.
    /// @param _proofBytes The encoded proof.
    function verifyRegoProof(
        bytes calldata _publicValues,
        bytes calldata _proofBytes
    ) external view returns (RegoContext memory);
}
