// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {ITaskResponseHandler} from "../interfaces/ITaskResponseHandler.sol";
import {ICertificateVerifier} from "../interfaces/ICertificateVerifier.sol";
import {
    IBN254CertificateVerifier,
    IBN254CertificateVerifierTypes
} from "@eigenlayer/contracts/interfaces/IBN254CertificateVerifier.sol";
import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {OperatorVerifierLib} from "../libraries/OperatorVerifierLib.sol";

/**
 * @title DestinationTaskResponseHandler
 * @notice Handler for verifying task responses on destination chains using certificates
 * @dev Uses ICertificateVerifier to verify certificates from source chains
 */
contract DestinationTaskResponseHandler is ITaskResponseHandler {
    /// @notice The certificate verifier for verifying certificates from source chains
    ICertificateVerifier public immutable certificateVerifier;

    /// @notice The source chain AVS address (service manager on source chain)
    address public immutable sourceChainAvsAddress;

    constructor(
        ICertificateVerifier _certificateVerifier,
        address _sourceChainAvsAddress
    ) {
        certificateVerifier = _certificateVerifier;
        sourceChainAvsAddress = _sourceChainAvsAddress;
    }

    /**
     * @notice Verify task response using certificate verification from source chain
     * @param task The task being responded to
     * @param taskResponse The task response to verify
     * @param signatureData ABI-encoded BN254Certificate
     * @return hashOfNonSigners The hash of non-signers derived from certificate verification
     * @dev For destination chains, we verify certificates rather than BLS signatures directly
     *      The certificate contains proof of operator consensus from the source chain
     */
    function verifyTaskResponse(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        bytes memory signatureData
    ) external override returns (bytes32 hashOfNonSigners) {
        // decode certificate from signatureData with error handling
        IBN254CertificateVerifierTypes.BN254Certificate memory certificate;
        try this.decodeCertificate(signatureData) returns (
            IBN254CertificateVerifierTypes.BN254Certificate memory _certificate
        ) {
            certificate = _certificate;
        } catch (bytes memory errorData) {
            revert InvalidTaskResponse(signatureData, errorData);
        }

        hashOfNonSigners = OperatorVerifierLib.verifyTaskResponseCertificate(
            task,
            taskResponse,
            certificate,
            IBN254CertificateVerifier(address(certificateVerifier)),
            sourceChainAvsAddress
        );

        return hashOfNonSigners;
    }

    /// @notice helper function to decode certificate
    function decodeCertificate(
        bytes memory signatureData
    ) external pure returns (IBN254CertificateVerifierTypes.BN254Certificate memory) {
        return abi.decode(signatureData, (IBN254CertificateVerifierTypes.BN254Certificate));
    }
}

