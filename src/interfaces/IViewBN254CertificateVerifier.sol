// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {
    IBN254CertificateVerifierTypes
} from "@eigenlayer/contracts/interfaces/IBN254CertificateVerifier.sol";
import {OperatorSet} from "@eigenlayer/contracts/libraries/OperatorSetLib.sol";

/**
 * @title IViewBN254CertificateVerifier
 * @notice View-compatible interface for BN254 certificate verification
 * @dev Newton's fork of EigenLayer's IBN254CertificateVerifier that declares
 *      verifyCertificate as view. This enables the entire EIP-1271 call chain
 *      (isValidSignature -> verifyTaskResponse -> verifyCertificate) to be view-compatible.
 *
 *      EigenLayer's original BN254CertificateVerifier caches non-signer operator info
 *      on first verification (SSTORE), making verifyCertificate non-view.
 *      Newton's ViewBN254CertificateVerifier removes this cache, always verifying
 *      merkle proofs instead, making the function stateless.
 */
interface IViewBN254CertificateVerifier is IBN254CertificateVerifierTypes {
    /**
     * @notice Verify a BN254 certificate without caching operator info
     * @param operatorSet The operator set the certificate is for
     * @param cert The certificate to verify
     * @return totalSignedStakeWeights The amount of stake that signed for each stake type
     */
    function verifyCertificate(
        OperatorSet memory operatorSet,
        IBN254CertificateVerifierTypes.BN254Certificate memory cert
    ) external view returns (uint256[] memory totalSignedStakeWeights);

    /**
     * @notice Get operator set info for a given operator set and reference timestamp
     * @param operatorSet The operator set to query
     * @param referenceTimestamp The reference timestamp
     * @return The operator set info
     */
    function getOperatorSetInfo(
        OperatorSet memory operatorSet,
        uint32 referenceTimestamp
    ) external view returns (IBN254CertificateVerifierTypes.BN254OperatorSetInfo memory);
}
