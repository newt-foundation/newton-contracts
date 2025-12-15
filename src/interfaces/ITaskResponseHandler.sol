// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "./INewtonProverTaskManager.sol";
import {IBLSSignatureChecker} from "@eigenlayer-middleware/src/interfaces/IBLSSignatureChecker.sol";

/**
 * @title ITaskResponseHandler
 * @notice Interface for handling task response verification
 * @dev This interface abstracts the difference between source chain (stake registry)
 *      and destination chain (certificate) verification
 */
interface ITaskResponseHandler {
    /**
     * @notice Verify a task response based on chain type
     * @param task The task being responded to
     * @param taskResponse The task response to verify
     * @param nonSignerStakesAndSignature BLS signature data (for source chains) or empty (for destination)
     * @return hashOfNonSigners The hash of non-signers after verification
     * @dev For source chains: verifies BLS signatures against stake registry
     *      For destination chains: verifies certificates from source chain
     */
    function verifyTaskResponse(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        IBLSSignatureChecker.NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) external returns (bytes32 hashOfNonSigners);
}

