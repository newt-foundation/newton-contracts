// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "./INewtonProverTaskManager.sol";

/**
 * @title ITaskResponseHandler
 * @notice Interface for handling task response verification
 * @dev This interface abstracts the difference between source chain (stake registry)
 *      and destination chain (certificate) verification
 */
interface ITaskResponseHandler {
    /// @notice Thrown when signatureData cannot be decoded as valid signature data
    error InvalidTaskResponse(bytes signatureData, bytes errorData);

    /**
     * @notice Verify a task response based on chain type
     * @param task The task being responded to
     * @param taskResponse The task response to verify
     * @param signatureData Encoded signature data - NonSignerStakesAndSignature for source chains,
     *        BN254Certificate for destination chains
     * @return hashOfNonSigners The hash of non-signers after verification
     * @dev For source chains: decodes as NonSignerStakesAndSignature and verifies BLS signatures
     *      For destination chains: decodes as BN254Certificate and verifies certificate
     */
    function verifyTaskResponse(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        bytes memory signatureData
    ) external returns (bytes32 hashOfNonSigners);
}

