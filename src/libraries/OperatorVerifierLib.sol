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
import {TaskLib} from "./TaskLib.sol";
import {
    IBN254CertificateVerifier,
    IBN254CertificateVerifierTypes
} from "@eigenlayer/contracts/interfaces/IBN254CertificateVerifier.sol";
import {IViewBN254CertificateVerifier} from "../interfaces/IViewBN254CertificateVerifier.sol";
import {OperatorSet} from "@eigenlayer/contracts/libraries/OperatorSetLib.sol";

library OperatorVerifierLib {
    /// @notice Default cross-chain quorum threshold percentage for the slashing path.
    /// @dev The v1 protocol default (gateway-defaulted to 40% across all environments). Used by
    ///      `ChallengeVerifier.crossChainQuorumThresholdPercentage()` as the effective value for
    ///      deployments that have not explicitly configured one. See the threshold-verification
    ///      note in `verifyTaskResponseCertificate` for why the slash path uses a contract value
    ///      rather than the caller-supplied `task.quorumThresholdPercentage`.
    uint256 internal constant DEFAULT_CROSS_CHAIN_QUORUM_THRESHOLD_PERCENTAGE = 40;

    error OperatorNotWhitelisted();
    error InsufficientQuorumStake();
    /// @notice The cross-chain quorum threshold is zero or above 100.
    error InvalidCrossChainQuorumThreshold(uint256 threshold);
    error InvalidQuorumThresholdPercentage();
    error CertificateMessageHashMismatch();
    error InvalidOperatorSetQuorums();
    error ArrayLengthMismatch();
    error EmptySignedStakes();
    error ZeroTotalWeight(uint256 strategyIndex);

    /**
     * @notice Verify that all signing operators are whitelisted
     * NOTE: Gas optimization required to avoid liveness/DoS at scale:
     * - Precompute non-signer quorum bitmaps once (outside per-quorum loop) to reduce O(Q×R) external calls to O(R).
     * - Replace O(N×M) linear membership checks with sorting + binary search (or two-pointer merge if operatorIds sorted).
     * - Optionally cache operator address lookups across quorums to reduce repeated external calls.
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

        // On destination chains, sub-registries are address(0) since EigenLayer registries
        // are not deployed. Skip whitelist check — BLS signature is verified via pairing.
        if (address(blsApkRegistry) == address(0) || address(indexRegistry) == address(0)) {
            return;
        }

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
        // Use consensus digest (attestations zeroed) to match what operators signed
        // Attestations are validated separately in validateTaskResponsePolicyData
        bytes32 message = TaskLib.computeConsensusDigest(taskResponse);
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
     * @param quorumThresholdPercentage The effective quorum threshold percentage to enforce.
     *        SECURITY (NEWT-1708): the caller decides what to pass here based on whether the Task
     *        is authenticated on its path. On the SLASH path (ChallengeVerifier, unauthenticated
     *        Task) it MUST be a contract-configured value, NOT `task.quorumThresholdPercentage`.
     *        On the ACCEPT path (DestinationTaskResponseHandler via respondToTask) the Task is
     *        pinned by `taskHash(task) == allTaskHashes[taskId]`, so passing the authenticated
     *        `task.quorumThresholdPercentage` is safe. Must be in (0, 100].
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
        IViewBN254CertificateVerifier certificateVerifier,
        address sourceChainAvsAddress,
        uint256 quorumThresholdPercentage
    ) external view returns (bytes32 hashOfNonSigners) {
        // Verify that certificate messageHash matches the consensus digest of the taskResponse
        //
        // SECURITY (NEWT-1708): this certificate only authenticates (a) the TaskResponse
        // consensus digest and (b) the operator set derived from `quorumNumbers[0]` at the
        // signature-covered `referenceTimestamp`. It does NOT authenticate `taskCreatedBlock`,
        // any additional entries in `quorumNumbers`, or `quorumThresholdPercentage`. Callers on
        // the cross-chain slashing path (ChallengeVerifier.slashForCrossChainChallenge) MUST
        // therefore (1) restrict slashing to a single quorum equal to `quorumNumbers[0]` and
        // (2) pin the slashing snapshot block to the block bound to `referenceTimestamp`.
        // On the SLASH path the caller passes a contract-configured `quorumThresholdPercentage`
        // (see the threshold-verification note) rather than `task.quorumThresholdPercentage`,
        // which is neither cert-authenticated nor proof-constrained on that path. On the ACCEPT
        // path the Task is pinned to `allTaskHashes[taskId]`, so the caller passes the
        // authenticated `task.quorumThresholdPercentage`.
        // Uses consensus digest (attestations zeroed) to match what operators signed
        bytes32 taskResponseHash = TaskLib.computeConsensusDigest(taskResponse);
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

        // Verify the quorum threshold.
        //
        // SECURITY (NEWT-1708): on the SLASH path (ChallengeVerifier.slashForCrossChainChallenge)
        // the Task is caller-supplied and `task.quorumThresholdPercentage` is neither
        // BLS-cert-authenticated nor SP1-proof-constrained (the circuit commits `task` verbatim,
        // so the `taskHash(context.task) == taskHash(task)` bind is circular — the caller controls
        // both sides). Deriving `requiredStake` from it would let an attacker relay
        // `quorumThresholdPercentage = 1`, collapse the bar to ~1%, and slash operators whose
        // response was valid under the real rule. That path therefore passes a contract-configured
        // threshold instead. On the ACCEPT path the Task is pinned to `allTaskHashes[taskId]`, so
        // the authenticated `task.quorumThresholdPercentage` is passed through unchanged.
        //
        // Either way the effective threshold must be in (0, 100]: a 0 threshold makes the
        // `totalStake * threshold <= 100 * signedStake` check below vacuously true (any response,
        // including one with zero signed stake, would pass), and > 100 is nonsensical.
        if (quorumThresholdPercentage == 0 || quorumThresholdPercentage > 100) {
            revert InvalidCrossChainQuorumThreshold(quorumThresholdPercentage);
        }

        uint256 signedStakeLen = signedStakes.length;
        require(signedStakeLen > 0, EmptySignedStakes());
        require(signedStakeLen == operatorSetInfo.totalWeights.length, ArrayLengthMismatch());

        // verify threshold for each stake type
        // typically only one stake type (index 0), but verify all to be safe
        for (uint256 i = 0; i < signedStakeLen; ++i) {
            uint256 totalStake = operatorSetInfo.totalWeights[i];
            require(totalStake > 0, ZeroTotalWeight(i));
            uint256 signedStake = signedStakes[i];

            require(
                totalStake * quorumThresholdPercentage <= 100 * signedStake,
                InsufficientQuorumStake()
            );
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
        // Include taskCreatedBlock in the hash to match the format
        // expected by ChallengeLib.validateSignatoryRecord, which computes:
        //   keccak256(abi.encodePacked(taskCreatedBlock, hashesOfPubkeys))
        // Without this, destination-chain challenges always fail with InvalidNonSigners.
        hashOfNonSigners = keccak256(abi.encodePacked(task.taskCreatedBlock, nonSignerPubkeyHashes));

        return hashOfNonSigners;
    }
}
