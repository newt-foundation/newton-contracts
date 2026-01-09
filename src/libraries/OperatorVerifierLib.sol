// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {BN254} from "@eigenlayer-middleware/src/libraries/BN254.sol";
import {BitmapUtils} from "@eigenlayer-middleware/src/libraries/BitmapUtils.sol";
import {IBLSApkRegistry} from "@eigenlayer-middleware/src/interfaces/IBLSApkRegistry.sol";
import {IIndexRegistry} from "@eigenlayer-middleware/src/interfaces/IIndexRegistry.sol";
import {
    ISlashingRegistryCoordinator
} from "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";
import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {IBLSSignatureChecker} from "@eigenlayer-middleware/src/interfaces/IBLSSignatureChecker.sol";
import {
    IBN254CertificateVerifier,
    IBN254CertificateVerifierTypes
} from "@eigenlayer/contracts/interfaces/IBN254CertificateVerifier.sol";
import {OperatorSet} from "@eigenlayer/contracts/libraries/OperatorSetLib.sol";

library OperatorVerifierLib {
    error OperatorNotWhitelisted();
    error InsufficientQuorumStake();
    error InvalidQuorumThresholdPercentage();
    error CertificateMessageHashMismatch();
    error InvalidOperatorSetQuorums();

    /**
     * @notice Verify that all signing operators are whitelisted
     * @param registryCoordinator The registry coordinator contract
     * @param task The task being responded to
     * @param nonSignerStakesAndSignature The BLS signature data containing operator information
     */
    function verifySigningOperatorsWhitelisted(
        ISlashingRegistryCoordinator registryCoordinator,
        INewtonProverTaskManager.Task calldata task,
        IBLSSignatureChecker.NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) public view {
        if (address(registryCoordinator) == address(0)) {
            return; // Skip whitelist check if registry not set
        }

        IOperatorRegistry registry = IOperatorRegistry(address(registryCoordinator));
        IBLSApkRegistry blsApkRegistry = registryCoordinator.blsApkRegistry();
        IIndexRegistry indexRegistry = registryCoordinator.indexRegistry();

        // Get all operators registered for each quorum at the task creation block
        // Then subtract non-signers to get the actual signers
        for (uint256 i = 0; i < task.quorumNumbers.length; ++i) {
            uint8 quorumNumber = uint8(task.quorumNumbers[i]);

            // Get all operator IDs registered for this quorum at the task creation block
            bytes32[] memory operatorIds =
                indexRegistry.getOperatorListAtBlockNumber(quorumNumber, task.taskCreatedBlock);

            // Create a set of non-signer operator IDs for this quorum
            bytes32[] memory nonSignerIds =
                new bytes32[](nonSignerStakesAndSignature.nonSignerPubkeys.length);
            uint256 nonSignerCount = 0;

            for (uint256 j = 0; j < nonSignerStakesAndSignature.nonSignerPubkeys.length; ++j) {
                bytes32 pubkeyHash =
                    BN254.hashG1Point(nonSignerStakesAndSignature.nonSignerPubkeys[j]);
                // Check if this non-signer was registered for this quorum
                uint256 quorumBitmap = registryCoordinator.getQuorumBitmapAtBlockNumberByIndex(
                    pubkeyHash,
                    task.taskCreatedBlock,
                    nonSignerStakesAndSignature.nonSignerQuorumBitmapIndices[j]
                );
                if (BitmapUtils.isSet(quorumBitmap, quorumNumber)) {
                    nonSignerIds[nonSignerCount] = pubkeyHash;
                    unchecked {
                        ++nonSignerCount;
                    }
                }
            }

            // Check all operators in this quorum - if they're not non-signers, they're signers
            for (uint256 k = 0; k < operatorIds.length; ++k) {
                bytes32 operatorId = operatorIds[k];

                // Check if this operator is a non-signer
                bool isNonSigner = false;
                for (uint256 m = 0; m < nonSignerCount; ++m) {
                    if (nonSignerIds[m] == operatorId) {
                        isNonSigner = true;
                        break;
                    }
                }

                // Skip if this operator is a non-signer
                if (isNonSigner) {
                    continue;
                }

                // This operator is a signer - get their address and check whitelist
                address operator = blsApkRegistry.getOperatorFromPubkeyHash(operatorId);

                // Skip if operator address is zero (unregistered pubkey)
                if (operator == address(0)) {
                    continue;
                }

                // Check if operator is whitelisted
                if (!registry.isOperatorWhitelisted(operator)) {
                    revert OperatorNotWhitelisted();
                }
            }
        }
    }

    /**
     * @notice Verify task response signatures, quorum thresholds, and whitelist status
     * @param task The task being responded to
     * @param taskResponse The task response
     * @param nonSignerStakesAndSignature The BLS signature data
     * @param registryCoordinator The registry coordinator contract
     * @param checkSignatures The function to check BLS signatures
     * @return quorumStakeTotals The quorum stake totals
     * @return hashOfNonSigners The hash of non-signers
     */
    function verifyTaskResponseSignatures(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        IBLSSignatureChecker.NonSignerStakesAndSignature memory nonSignerStakesAndSignature,
        ISlashingRegistryCoordinator registryCoordinator,
        function(bytes32, bytes memory, uint32, IBLSSignatureChecker
                        .NonSignerStakesAndSignature memory)
            external
            view returns (IBLSSignatureChecker.QuorumStakeTotals memory, bytes32) checkSignatures
    )
        external
        view
        returns (
            IBLSSignatureChecker.QuorumStakeTotals memory quorumStakeTotals,
            bytes32 hashOfNonSigners
        )
    {
        // Check signatures and threshold
        bytes32 message = keccak256(abi.encode(taskResponse));
        (quorumStakeTotals, hashOfNonSigners) = checkSignatures(
            message, task.quorumNumbers, uint32(task.taskCreatedBlock), nonSignerStakesAndSignature
        );

        if (task.quorumThresholdPercentage > 100) {
            revert InvalidQuorumThresholdPercentage();
        }
        uint8 threshold = uint8(task.quorumThresholdPercentage);

        for (uint256 i; i < task.quorumNumbers.length;) {
            require(
                quorumStakeTotals.signedStakeForQuorum[i] * 100
                    >= quorumStakeTotals.totalStakeForQuorum[i] * threshold,
                InsufficientQuorumStake()
            );
            unchecked {
                ++i;
            }
        }

        // Verify that all signing operators are whitelisted
        verifySigningOperatorsWhitelisted(registryCoordinator, task, nonSignerStakesAndSignature);
    }

    /**
     * @notice Verify task response using certificate from destination chain
     * @param task The task being responded to
     * @param taskResponse The task response
     * @param certificate The BN254 certificate from source chain
     * @param certificateVerifier The certificate verifier contract
     * @param sourceChainAvsAddress The AVS address on the source chain
     * @return hashOfNonSigners The hash of non-signers
     * @dev This function verifies:
     *      1. Certificate messageHash matches taskResponse hash
     *      2. Certificate signature is valid via BN254CertificateVerifier
     *      3. Quorum threshold percentage is met
     */
    function verifyTaskResponseCertificate(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        IBN254CertificateVerifierTypes.BN254Certificate memory certificate,
        IBN254CertificateVerifier certificateVerifier,
        address sourceChainAvsAddress
    ) external returns (bytes32 hashOfNonSigners) {
        // verify that certificate messageHash matches the taskResponse
        bytes32 taskResponseHash = keccak256(abi.encode(taskResponse));
        if (certificate.messageHash != taskResponseHash) {
            revert CertificateMessageHashMismatch();
        }

        // construct operator set from task quorum numbers and source chain AVS
        // using first quorum number as operator set id
        if (task.quorumNumbers.length == 0) {
            revert InvalidOperatorSetQuorums();
        }
        uint32 operatorSetId = uint32(uint8(task.quorumNumbers[0]));
        OperatorSet memory operatorSet =
            OperatorSet({avs: sourceChainAvsAddress, id: operatorSetId});

        // verify certificate using BN254CertificateVerifier
        uint256[] memory signedStakes =
            certificateVerifier.verifyCertificate(operatorSet, certificate);

        // get operator set info to calculate total stakes
        IBN254CertificateVerifierTypes.BN254OperatorSetInfo memory operatorSetInfo =
            certificateVerifier.getOperatorSetInfo(operatorSet, certificate.referenceTimestamp);

        // verify quorum threshold percentage
        if (task.quorumThresholdPercentage > 100) {
            revert InvalidQuorumThresholdPercentage();
        }

        // verify threshold for each stake type
        // typically only one stake type (index 0), but verify all to be safe
        for (uint256 i = 0; i < signedStakes.length; ++i) {
            uint256 totalStake = operatorSetInfo.totalWeights[i];
            uint256 signedStake = signedStakes[i];
            uint256 requiredStake = (totalStake * task.quorumThresholdPercentage) / 100;

            if (signedStake < requiredStake) {
                revert InsufficientQuorumStake();
            }
        }

        // calculate hashOfNonSigners from certificate
        // the hash should include all non-signer pubkeys
        bytes32[] memory nonSignerPubkeyHashes =
            new bytes32[](certificate.nonSignerWitnesses.length);
        for (uint256 i = 0; i < certificate.nonSignerWitnesses.length; ++i) {
            nonSignerPubkeyHashes[i] = keccak256(
                abi.encodePacked(
                    certificate.nonSignerWitnesses[i].operatorInfo.pubkey.X,
                    certificate.nonSignerWitnesses[i].operatorInfo.pubkey.Y
                )
            );
        }
        hashOfNonSigners = keccak256(abi.encodePacked(nonSignerPubkeyHashes));

        return hashOfNonSigners;
    }
}
