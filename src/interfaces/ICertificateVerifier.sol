// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "./INewtonProverTaskManager.sol";

/**
 * @title ICertificateVerifier
 * @notice Interface for verifying certificates from source chains on destination chains
 * @dev This interface abstracts certificate verification for multichain setups
 */
interface ICertificateVerifier {
    /**
     * @notice Verify a certificate for a task response
     * @param task The task being responded to
     * @param taskResponse The task response
     * @param certificateData The certificate data to verify (format depends on implementation)
     * @return hashOfNonSigners The hash of non-signers derived from certificate verification
     * @dev This method verifies that the certificate proves sufficient operator consensus
     */
    function verifyCertificate(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        bytes calldata certificateData
    ) external returns (bytes32 hashOfNonSigners);
}

