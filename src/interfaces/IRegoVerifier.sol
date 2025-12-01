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

    /// @notice The context of the rego policy evaluation.
    struct RegoContext {
        INewtonProverTaskManager.Task task;
        INewtonProverTaskManager.TaskResponse taskResponse;
        string entrypoint;
        bytes evaluation;
    }

    /// @notice The entrypoint for verifying the proof of a rego policy evaluation.
    /// @param _publicValues The encoded public values.
    /// @param _proofBytes The encoded proof.
    function verifyRegoProof(
        bytes calldata _publicValues,
        bytes calldata _proofBytes
    ) external view returns (RegoContext calldata);
}
