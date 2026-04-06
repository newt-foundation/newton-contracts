// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";

import {BN254} from "@eigenlayer/contracts/libraries/BN254.sol";
import {BN254SignatureVerifier} from "@eigenlayer/contracts/libraries/BN254SignatureVerifier.sol";
import {Merkle} from "@eigenlayer/contracts/libraries/Merkle.sol";
import {OperatorSetLib, OperatorSet} from "@eigenlayer/contracts/libraries/OperatorSetLib.sol";
import {SemVerMixin} from "@eigenlayer/contracts/mixins/SemVerMixin.sol";
import {LeafCalculatorMixin} from "@eigenlayer/contracts/mixins/LeafCalculatorMixin.sol";
import {
    BN254CertificateVerifierStorage
} from "@eigenlayer/contracts/multichain/BN254CertificateVerifierStorage.sol";
import {IOperatorTableUpdater} from "@eigenlayer/contracts/interfaces/IOperatorTableUpdater.sol";
import {
    IBaseCertificateVerifier
} from "@eigenlayer/contracts/interfaces/IBaseCertificateVerifier.sol";
import {
    IBN254CertificateVerifier
} from "@eigenlayer/contracts/interfaces/IBN254CertificateVerifier.sol";
import {IViewBN254CertificateVerifier} from "../interfaces/IViewBN254CertificateVerifier.sol";

/**
 * @title ViewBN254CertificateVerifier
 * @notice Newton's fork of EigenLayer's BN254CertificateVerifier with caching removed
 * @dev The only difference from EigenLayer's implementation is that non-signer operator info
 *      is always verified via merkle proof instead of being cached in storage. This makes
 *      verifyCertificate a view function, enabling EIP-1271 isValidSignature on destination chains.
 *
 *      Gas trade-off: repeat verifications for the same reference timestamp cost ~1-3K more gas
 *      per non-signer (merkle proof vs SLOAD). First verifications are cheaper (no SSTORE).
 *      For EIP-1271 validation (once per intent), this trade-off is negligible.
 */
contract ViewBN254CertificateVerifier is
    Initializable,
    BN254CertificateVerifierStorage,
    SemVerMixin,
    LeafCalculatorMixin,
    IViewBN254CertificateVerifier
{
    using Merkle for bytes;
    using BN254 for BN254.G1Point;

    /**
     * @notice Struct to hold verification context and reduce stack depth
     */
    struct VerificationContext {
        bytes32 operatorSetKey;
        BN254OperatorSetInfo operatorSetInfo;
        uint256[] totalSignedStakeWeights;
        BN254.G1Point nonSignerApk;
    }

    /**
     * @notice Restricts access to the operator table updater
     */
    modifier onlyTableUpdater() {
        require(msg.sender == address(operatorTableUpdater), OnlyTableUpdater());
        _;
    }

    constructor(
        IOperatorTableUpdater _operatorTableUpdater,
        string memory _version
    ) BN254CertificateVerifierStorage(_operatorTableUpdater) SemVerMixin(_version) {
        _disableInitializers();
    }

    /*//////////////////////////////////////////////////////////////
                         EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBN254CertificateVerifier
    function updateOperatorTable(
        OperatorSet calldata operatorSet,
        uint32 referenceTimestamp,
        BN254OperatorSetInfo memory operatorSetInfo,
        OperatorSetConfig calldata operatorSetConfig
    ) external onlyTableUpdater {
        bytes32 operatorSetKey = operatorSet.key();

        require(referenceTimestamp > _latestReferenceTimestamps[operatorSetKey], TableUpdateStale());

        _operatorSetInfos[operatorSetKey][referenceTimestamp] = operatorSetInfo;
        _latestReferenceTimestamps[operatorSetKey] = referenceTimestamp;
        _operatorSetOwners[operatorSetKey] = operatorSetConfig.owner;
        _maxStalenessPeriods[operatorSetKey] = operatorSetConfig.maxStalenessPeriod;
        _referenceTimestampsSet[operatorSetKey][referenceTimestamp] = true;

        emit TableUpdated(operatorSet, referenceTimestamp, operatorSetInfo);
    }

    /// @dev View-compatible: always verifies merkle proofs, never caches operator info
    function verifyCertificate(
        OperatorSet memory operatorSet,
        BN254Certificate memory cert
    )
        external
        view
        override(IBN254CertificateVerifier, IViewBN254CertificateVerifier)
        returns (uint256[] memory totalSignedStakeWeights)
    {
        return _verifyCertificate(operatorSet, cert);
    }

    /// @inheritdoc IBN254CertificateVerifier
    function verifyCertificateProportion(
        OperatorSet memory operatorSet,
        BN254Certificate memory cert,
        uint16[] memory totalStakeProportionThresholds
    ) external view returns (bool) {
        uint256[] memory totalSignedStakeWeights = _verifyCertificate(operatorSet, cert);

        bytes32 operatorSetKey = operatorSet.key();
        BN254OperatorSetInfo memory operatorSetInfo =
            _operatorSetInfos[operatorSetKey][cert.referenceTimestamp];
        uint256[] memory totalStakes = operatorSetInfo.totalWeights;

        require(
            totalSignedStakeWeights.length == totalStakeProportionThresholds.length,
            ArrayLengthMismatch()
        );

        for (uint256 i = 0; i < totalSignedStakeWeights.length; i++) {
            uint256 threshold =
                (totalStakes[i] * totalStakeProportionThresholds[i]) / BPS_DENOMINATOR;
            if (totalSignedStakeWeights[i] < threshold) {
                return false;
            }
        }

        return true;
    }

    /// @inheritdoc IBN254CertificateVerifier
    function verifyCertificateNominal(
        OperatorSet memory operatorSet,
        BN254Certificate memory cert,
        uint256[] memory totalStakeNominalThresholds
    ) external view returns (bool) {
        uint256[] memory totalSignedStakeWeights = _verifyCertificate(operatorSet, cert);

        require(
            totalSignedStakeWeights.length == totalStakeNominalThresholds.length,
            ArrayLengthMismatch()
        );

        for (uint256 i = 0; i < totalSignedStakeWeights.length; i++) {
            if (totalSignedStakeWeights[i] < totalStakeNominalThresholds[i]) {
                return false;
            }
        }

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _verifyCertificate(
        OperatorSet memory operatorSet,
        BN254Certificate memory cert
    ) internal view returns (uint256[] memory totalSignedStakeWeights) {
        VerificationContext memory ctx;
        ctx.operatorSetKey = operatorSet.key();

        _validateCertificateTimestamp(ctx.operatorSetKey, cert.referenceTimestamp);
        ctx.operatorSetInfo = _operatorSetInfos[ctx.operatorSetKey][cert.referenceTimestamp];

        ctx.totalSignedStakeWeights = new uint256[](ctx.operatorSetInfo.totalWeights.length);
        for (uint256 i = 0; i < ctx.operatorSetInfo.totalWeights.length; i++) {
            ctx.totalSignedStakeWeights[i] = ctx.operatorSetInfo.totalWeights[i];
        }

        ctx.nonSignerApk = _processNonSigners(ctx, cert);

        _verifySignature(ctx, cert);

        return ctx.totalSignedStakeWeights;
    }

    function _validateCertificateTimestamp(
        bytes32 operatorSetKey,
        uint32 referenceTimestamp
    ) internal view {
        uint32 maxStaleness = _maxStalenessPeriods[operatorSetKey];
        require(
            maxStaleness == 0 || block.timestamp <= referenceTimestamp + maxStaleness,
            CertificateStale()
        );
        require(
            _referenceTimestampsSet[operatorSetKey][referenceTimestamp],
            ReferenceTimestampDoesNotExist()
        );
        require(operatorTableUpdater.isRootValidByTimestamp(referenceTimestamp), RootDisabled());
    }

    /**
     * @notice Processes non-signer witnesses and returns aggregate non-signer public key
     * @dev Unlike EigenLayer's version, this always verifies merkle proofs (no caching)
     */
    function _processNonSigners(
        VerificationContext memory ctx,
        BN254Certificate memory cert
    ) internal view returns (BN254.G1Point memory nonSignerApk) {
        nonSignerApk = BN254.G1Point(0, 0);
        uint32 previousOperatorIndex = 0;

        for (uint256 i = 0; i < cert.nonSignerWitnesses.length; i++) {
            BN254OperatorInfoWitness memory witness = cert.nonSignerWitnesses[i];

            if (i > 0) {
                require(witness.operatorIndex > previousOperatorIndex, NonSignerIndicesNotSorted());
            }

            require(
                witness.operatorIndex < ctx.operatorSetInfo.numOperators, InvalidOperatorIndex()
            );

            // Always verify merkle proof — no caching
            BN254OperatorInfo memory operatorInfo =
                _verifyNonsignerOperatorInfo(ctx.operatorSetKey, cert.referenceTimestamp, witness);

            nonSignerApk = nonSignerApk.plus(operatorInfo.pubkey);

            for (uint256 j = 0; j < operatorInfo.weights.length; j++) {
                if (j < ctx.totalSignedStakeWeights.length) {
                    ctx.totalSignedStakeWeights[j] -= operatorInfo.weights[j];
                }
            }

            previousOperatorIndex = witness.operatorIndex;
        }
    }

    /**
     * @notice Verifies non-signer operator info via merkle proof (stateless, no caching)
     * @dev Replaces EigenLayer's _getOrCacheNonsignerOperatorInfo which wrote to storage
     */
    function _verifyNonsignerOperatorInfo(
        bytes32 operatorSetKey,
        uint32 referenceTimestamp,
        BN254OperatorInfoWitness memory witness
    ) internal view returns (BN254OperatorInfo memory operatorInfo) {
        bool verified = _verifyOperatorInfoMerkleProof(
            operatorSetKey,
            referenceTimestamp,
            witness.operatorIndex,
            witness.operatorInfo,
            witness.operatorInfoProof
        );
        require(verified, VerificationFailed());
        return witness.operatorInfo;
    }

    function _verifySignature(
        VerificationContext memory ctx,
        BN254Certificate memory cert
    ) internal view {
        BN254.G1Point memory signerApk =
            ctx.operatorSetInfo.aggregatePubkey.plus(ctx.nonSignerApk.negate());
        bytes32 signableDigest =
            calculateCertificateDigest(cert.referenceTimestamp, cert.messageHash);
        (bool pairingSuccessful, bool signatureValid) =
            trySignatureVerification(signableDigest, signerApk, cert.apk, cert.signature);
        require(pairingSuccessful && signatureValid, VerificationFailed());
    }

    function _verifyOperatorInfoMerkleProof(
        bytes32 operatorSetKey,
        uint32 referenceTimestamp,
        uint32 operatorIndex,
        BN254OperatorInfo memory operatorInfo,
        bytes memory proof
    ) internal view returns (bool verified) {
        bytes32 leaf = calculateOperatorInfoLeaf(operatorInfo);
        bytes32 root = _operatorSetInfos[operatorSetKey][referenceTimestamp].operatorInfoTreeRoot;
        return proof.verifyInclusionKeccak(root, leaf, operatorIndex);
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBaseCertificateVerifier
    function getOperatorSetOwner(
        OperatorSet memory operatorSet
    ) external view returns (address) {
        bytes32 operatorSetKey = operatorSet.key();
        return _operatorSetOwners[operatorSetKey];
    }

    /// @inheritdoc IBaseCertificateVerifier
    function maxOperatorTableStaleness(
        OperatorSet memory operatorSet
    ) external view returns (uint32) {
        bytes32 operatorSetKey = operatorSet.key();
        return _maxStalenessPeriods[operatorSetKey];
    }

    /// @inheritdoc IBaseCertificateVerifier
    function latestReferenceTimestamp(
        OperatorSet memory operatorSet
    ) external view returns (uint32) {
        bytes32 operatorSetKey = operatorSet.key();
        return _latestReferenceTimestamps[operatorSetKey];
    }

    /// @inheritdoc IBaseCertificateVerifier
    function isReferenceTimestampSet(
        OperatorSet memory operatorSet,
        uint32 referenceTimestamp
    ) external view returns (bool) {
        bytes32 operatorSetKey = operatorSet.key();
        return _referenceTimestampsSet[operatorSetKey][referenceTimestamp];
    }

    /// @inheritdoc IBaseCertificateVerifier
    function getTotalStakeWeights(
        OperatorSet memory operatorSet,
        uint32 referenceTimestamp
    ) external view returns (uint256[] memory) {
        bytes32 operatorSetKey = operatorSet.key();
        return _operatorSetInfos[operatorSetKey][referenceTimestamp].totalWeights;
    }

    /// @inheritdoc IBaseCertificateVerifier
    function getOperatorCount(
        OperatorSet memory operatorSet,
        uint32 referenceTimestamp
    ) external view returns (uint256) {
        bytes32 operatorSetKey = operatorSet.key();
        return _operatorSetInfos[operatorSetKey][referenceTimestamp].numOperators;
    }

    /// @inheritdoc IBN254CertificateVerifier
    function trySignatureVerification(
        bytes32 msgHash,
        BN254.G1Point memory aggPubkey,
        BN254.G2Point memory apkG2,
        BN254.G1Point memory signature
    ) public view returns (bool pairingSuccessful, bool signatureValid) {
        return BN254SignatureVerifier.verifySignature(
            msgHash, signature, aggPubkey, apkG2, true, PAIRING_EQUALITY_CHECK_GAS
        );
    }

    /// @inheritdoc IBN254CertificateVerifier
    /// @dev Always returns zero-initialized struct — _operatorInfos is never written to.
    /// Non-signer info is verified via merkle proof in verifyCertificate, not cached.
    function getNonsignerOperatorInfo(
        OperatorSet memory,
        uint32,
        uint256
    ) external pure returns (BN254OperatorInfo memory) {
        // Return zero-initialized struct (caching removed)
        BN254OperatorInfo memory empty;
        return empty;
    }

    /// @inheritdoc IBN254CertificateVerifier
    /// @dev Always returns false — this fork does not cache operator info.
    /// _operatorInfos is never written to; non-signers are always verified via merkle proof.
    function isNonsignerCached(
        OperatorSet memory,
        uint32,
        uint256
    ) external pure returns (bool) {
        return false;
    }

    function getOperatorSetInfo(
        OperatorSet memory operatorSet,
        uint32 referenceTimestamp
    )
        external
        view
        override(IBN254CertificateVerifier, IViewBN254CertificateVerifier)
        returns (BN254OperatorSetInfo memory)
    {
        bytes32 operatorSetKey = operatorSet.key();
        return _operatorSetInfos[operatorSetKey][referenceTimestamp];
    }

    /// @inheritdoc IBN254CertificateVerifier
    function calculateCertificateDigest(
        uint32 referenceTimestamp,
        bytes32 messageHash
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(BN254_CERTIFICATE_TYPEHASH, referenceTimestamp, messageHash));
    }
}
