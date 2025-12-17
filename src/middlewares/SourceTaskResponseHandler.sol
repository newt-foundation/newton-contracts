// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ITaskResponseHandler} from "../interfaces/ITaskResponseHandler.sol";
import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {OperatorVerifierLib} from "../libraries/OperatorVerifierLib.sol";
import {IBLSSignatureChecker} from "@eigenlayer-middleware/src/interfaces/IBLSSignatureChecker.sol";
import {
    ISlashingRegistryCoordinator
} from "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {BLSSignatureChecker} from "@eigenlayer-middleware/src/BLSSignatureChecker.sol";

/**
 * @title SourceTaskResponseHandler
 * @notice Handler for verifying task responses on source chains using BLS signature verification
 * @dev Uses OperatorVerifierLib to verify BLS signatures against EigenLayer stake registry
 *      This handler extends BLSSignatureChecker so it can provide checkSignatures as a function pointer
 */
contract SourceTaskResponseHandler is ITaskResponseHandler, BLSSignatureChecker {
    constructor(
        ISlashingRegistryCoordinator _registryCoordinator
    ) BLSSignatureChecker(_registryCoordinator) {}

    /**
     * @notice Verify task response using BLS signature verification against stake registry
     * @param task The task being responded to
     * @param taskResponse The task response to verify
     * @param nonSignerStakesAndSignature BLS signature data for verification
     * @return hashOfNonSigners The hash of non-signers after verification
     * @dev Uses OperatorVerifierLib which calls this contract's checkSignatures method via function pointer
     */
    function verifyTaskResponse(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        IBLSSignatureChecker.NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) external view override returns (bytes32 hashOfNonSigners) {
        // Delegate to OperatorVerifierLib for signature verification
        // This contract extends BLSSignatureChecker, so we can pass this.checkSignatures as a function pointer
        (, hashOfNonSigners) = OperatorVerifierLib.verifyTaskResponseSignatures(
            task,
            taskResponse,
            nonSignerStakesAndSignature,
            registryCoordinator,
            this.checkSignatures
        );
    }
}

