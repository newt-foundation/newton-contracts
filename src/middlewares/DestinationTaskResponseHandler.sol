// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ITaskResponseHandler} from "../interfaces/ITaskResponseHandler.sol";
import {ICertificateVerifier} from "../interfaces/ICertificateVerifier.sol";
import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {IBLSSignatureChecker} from "@eigenlayer-middleware/src/interfaces/IBLSSignatureChecker.sol";
import "@eigenlayer-middleware/src/libraries/BN254.sol";

/**
 * @title DestinationTaskResponseHandler
 * @notice Handler for verifying task responses on destination chains using certificates
 * @dev Uses ICertificateVerifier to verify certificates from source chains
 */
contract DestinationTaskResponseHandler is ITaskResponseHandler {
    /// @notice The certificate verifier for verifying certificates from source chains
    ICertificateVerifier public immutable certificateVerifier;

    constructor(
        ICertificateVerifier _certificateVerifier
    ) {
        certificateVerifier = _certificateVerifier;
    }

    /**
     * @notice Verify task response using certificate verification from source chain
     * @param task The task being responded to
     * @param taskResponse The task response to verify
     * @param nonSignerStakesAndSignature Not used for destination chains (should be empty)
     * @return hashOfNonSigners The hash of non-signers derived from certificate verification
     * @dev For destination chains, we verify certificates rather than BLS signatures directly
     *      The certificate contains proof of operator consensus from the source chain
     */
    function verifyTaskResponse(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        IBLSSignatureChecker.NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) external override returns (bytes32 hashOfNonSigners) {
        // For destination chains, we extract certificate data from nonSignerStakesAndSignature
        // The certificate data format depends on the ICertificateVerifier implementation
        // For now, we encode the nonSignerStakesAndSignature as certificate data
        // TODO: Define proper certificate data format based on ICertificateVerifier implementation

        // Encode the certificate data (this will be replaced with proper certificate format)
        bytes memory certificateData = abi.encode(nonSignerStakesAndSignature);

        // Verify the certificate using the certificate verifier
        hashOfNonSigners =
            certificateVerifier.verifyCertificate(task, taskResponse, certificateData);
    }
}

