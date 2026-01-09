// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@openzeppelin-upgrades/contracts/security/ReentrancyGuardUpgradeable.sol";
import "@eigenlayer/contracts/permissions/Pausable.sol";
import "@eigenlayer/contracts/mixins/SemVerMixin.sol";

import {
    IBN254CertificateVerifier
} from "@eigenlayer/contracts/interfaces/IBN254CertificateVerifier.sol";
import {
    OperatorTableUpdaterStorage
} from "@eigenlayer/contracts/multichain/OperatorTableUpdaterStorage.sol";
import {
    IECDSACertificateVerifier
} from "@eigenlayer/contracts/interfaces/IECDSACertificateVerifier.sol";
import {IOperatorTableUpdater} from "@eigenlayer/contracts/interfaces/IOperatorTableUpdater.sol";
import {
    IBaseCertificateVerifier
} from "@eigenlayer/contracts/interfaces/IBaseCertificateVerifier.sol";
import {
    IOperatorTableCalculatorTypes
} from "@eigenlayer/contracts/interfaces/IOperatorTableCalculator.sol";
import {ICrossChainRegistryTypes} from "@eigenlayer/contracts/interfaces/ICrossChainRegistry.sol";
import {IKeyRegistrarTypes} from "@eigenlayer/contracts/interfaces/IKeyRegistrar.sol";
import {OperatorSet} from "@eigenlayer/contracts/libraries/OperatorSetLib.sol";
import {Merkle} from "@eigenlayer/contracts/libraries/Merkle.sol";
import {LeafCalculatorMixin} from "@eigenlayer/contracts/mixins/LeafCalculatorMixin.sol";

/**
 * @title ECDSAOperatorTableUpdater
 * @notice operator table updater that uses eoa authorization
 * @dev This contract uses eoa authorization instead of threshold signatures
 *      (as OperatorTableUpdater.sol does) to gate access to a global state
 *      root.
 */
contract ECDSAOperatorTableUpdater is
    Initializable,
    OwnableUpgradeable,
    Pausable,
    OperatorTableUpdaterStorage,
    SemVerMixin,
    LeafCalculatorMixin,
    ReentrancyGuardUpgradeable
{
    /**
     *
     *                         INITIALIZING FUNCTIONS
     *
     */
    constructor(
        IBN254CertificateVerifier _bn254CertificateVerifier,
        IECDSACertificateVerifier _ecdsaCertificateVerifier,
        IPauserRegistry _pauserRegistry,
        string memory _version
    )
        OperatorTableUpdaterStorage(_bn254CertificateVerifier, _ecdsaCertificateVerifier)
        Pausable(_pauserRegistry)
        SemVerMixin(_version)
    {
        _disableInitializers();
    }

    /**
     * @notice Initializes the ECDSAOperatorTableUpdater
     * @param _owner The owner of the ECDSAOperatorTableUpdater
     * @param initialPausedStatus The initial paused status of the ECDSAOperatorTableUpdater
     * @dev We set the `_latestReferenceTimestamp` to the current timestamp, so that only *new* roots can be confirmed
     */
    function initialize(
        address _owner,
        uint256 initialPausedStatus
    ) external initializer {
        _transferOwnership(_owner);
        _setPausedStatus(initialPausedStatus);

        // initialize with current timestamp to prevent stale roots
        _latestReferenceTimestamp = uint32(block.timestamp);
    }

    // operator table
    struct OperatorTableData {
        OperatorSet operatorSet;
        CurveType curveType;
        OperatorSetConfig operatorSetConfig;
        bytes operatorTableInfo;
    }

    /**
     * @notice confirms a global table root
     * @param globalTableRoot merkle root of all operatorset tables
     * @param referenceTimestamp block timestamp at which the global table root was calculated
     * @param referenceBlockNumber block number corresponding to the reference timestamp
     */
    function confirmGlobalTableRoot(
        bytes32 globalTableRoot,
        uint32 referenceTimestamp,
        uint32 referenceBlockNumber
    ) external onlyOwner onlyWhenNotPaused(PAUSED_GLOBAL_ROOT_UPDATE) nonReentrant {
        // validate timestamp
        require(referenceTimestamp <= block.timestamp, GlobalTableRootInFuture());
        require(referenceTimestamp > _latestReferenceTimestamp, GlobalTableRootStale());

        // update state
        _latestReferenceTimestamp = referenceTimestamp;
        _referenceBlockNumbers[referenceTimestamp] = referenceBlockNumber;
        _referenceTimestamps[referenceBlockNumber] = referenceTimestamp;
        _globalTableRoots[referenceTimestamp] = globalTableRoot;
        _isRootValid[globalTableRoot] = true;

        emit NewGlobalTableRoot(referenceTimestamp, globalTableRoot);
    }

    /**
     * @notice updates an operator table
     * @param referenceTimestamp the reference timestamp of the global table root
     * @param globalTableRoot the global table root
     * @param operatorSetIndex the index of the given operatorset being updated
     * @param proof the proof of the leaf at index against the global table root
     * @param operatorTableBytes the bytes of the operator table
     */
    function updateOperatorTable(
        uint32 referenceTimestamp,
        bytes32 globalTableRoot,
        uint32 operatorSetIndex,
        bytes calldata proof,
        bytes calldata operatorTableBytes
    ) external {
        (
            OperatorSet memory operatorSet,
            CurveType curveType,
            OperatorSetConfig memory operatorSetConfig,
            bytes memory operatorTableInfo
        ) = _decodeOperatorTableBytes(operatorTableBytes);

        // check that the global table root is not disabled
        require(_isRootValid[globalTableRoot], InvalidRoot());

        // it's fine if reference timestamp has already been updated for the operatorset
        if (IBaseCertificateVerifier(getCertificateVerifier(curveType))
                .isReferenceTimestampSet(operatorSet, referenceTimestamp)) {
            return;
        }

        // new reference timestamp > latest reference timestamp
        require(
            referenceTimestamp
                > IBaseCertificateVerifier(getCertificateVerifier(curveType))
                    .latestReferenceTimestamp(operatorSet),
            TableUpdateForPastTimestamp()
        );

        // global table root matches the reference timestamp
        require(_globalTableRoots[referenceTimestamp] == globalTableRoot, InvalidGlobalTableRoot());

        // verify update
        _verifyMerkleInclusion({
            globalTableRoot: globalTableRoot,
            operatorSetIndex: operatorSetIndex,
            proof: proof,
            operatorSetLeafHash: calculateOperatorTableLeaf(operatorTableBytes)
        });

        // actually update
        if (curveType == CurveType.BN254) {
            bn254CertificateVerifier.updateOperatorTable(
                operatorSet,
                referenceTimestamp,
                _getBN254OperatorInfo(operatorTableInfo),
                operatorSetConfig
            );
        } else if (curveType == CurveType.ECDSA) {
            ecdsaCertificateVerifier.updateOperatorTable(
                operatorSet,
                referenceTimestamp,
                _getECDSAOperatorInfo(operatorTableInfo),
                operatorSetConfig
            );
        } else {
            revert InvalidCurveType();
        }
    }

    /**
     * @notice disables a global table root
     * @param globalTableRoot the global table root to disable
     */
    function disableRoot(
        bytes32 globalTableRoot
    ) external onlyPauser {
        require(_isRootValid[globalTableRoot], InvalidRoot());

        _isRootValid[globalTableRoot] = false;
        emit GlobalRootDisabled(globalTableRoot);
    }

    // view functions

    function getGlobalTableRootByTimestamp(
        uint32 referenceTimestamp
    ) external view returns (bytes32) {
        return _globalTableRoots[referenceTimestamp];
    }

    function getCurrentGlobalTableRoot() external view returns (bytes32) {
        return _globalTableRoots[_latestReferenceTimestamp];
    }

    function getLatestReferenceTimestamp() external view returns (uint32) {
        return _latestReferenceTimestamp;
    }

    function getLatestReferenceBlockNumber() external view returns (uint32) {
        return _referenceBlockNumbers[_latestReferenceTimestamp];
    }

    function getReferenceBlockNumberByTimestamp(
        uint32 referenceTimestamp
    ) external view returns (uint32) {
        return _referenceBlockNumbers[referenceTimestamp];
    }

    function getReferenceTimestampByBlockNumber(
        uint32 referenceBlockNumber
    ) external view returns (uint32) {
        return _referenceTimestamps[referenceBlockNumber];
    }

    function isRootValid(
        bytes32 globalTableRoot
    ) external view returns (bool) {
        return _isRootValid[globalTableRoot];
    }

    function isRootValidByTimestamp(
        uint32 referenceTimestamp
    ) external view returns (bool) {
        return _isRootValid[_globalTableRoots[referenceTimestamp]];
    }

    function getCertificateVerifier(
        CurveType curveType
    ) public view returns (address) {
        if (curveType == CurveType.BN254) {
            return address(bn254CertificateVerifier);
        } else if (curveType == CurveType.ECDSA) {
            return address(ecdsaCertificateVerifier);
        } else {
            revert InvalidCurveType();
        }
    }

    // no generator
    function confirmGlobalTableRoot(
        BN254Certificate calldata,
        bytes32,
        uint32,
        uint32
    ) external pure {
        revert("no generator");
    }

    function getGenerator() external pure returns (OperatorSet memory) {
        revert("no generator");
    }

    function getGlobalTableUpdateMessageHash(
        bytes32,
        uint32,
        uint32
    ) external pure returns (bytes32) {
        revert("no generator");
    }

    function getGlobalTableUpdateSignableDigest(
        bytes32,
        uint32,
        uint32
    ) external pure returns (bytes32) {
        revert("no generator");
    }

    function getGeneratorReferenceTimestamp() external pure returns (uint32) {
        revert("no generator");
    }

    function getGeneratorConfig() external pure returns (OperatorSetConfig memory) {
        revert("no generator");
    }

    function setGlobalRootConfirmationThreshold(
        uint16
    ) external pure {
        revert("no generator");
    }

    function updateGenerator(
        OperatorSet calldata,
        BN254OperatorSetInfo calldata
    ) external pure {
        revert("no generator");
    }

    // helpers

    function _verifyMerkleInclusion(
        bytes32 globalTableRoot,
        uint32 operatorSetIndex,
        bytes calldata proof,
        bytes32 operatorSetLeafHash
    ) internal pure {
        require(
            Merkle.verifyInclusionKeccak({
                proof: proof,
                root: globalTableRoot,
                leaf: operatorSetLeafHash,
                index: operatorSetIndex
            }),
            InvalidOperatorSetProof()
        );
    }

    function _decodeOperatorTableBytes(
        bytes calldata operatorTable
    )
        internal
        pure
        returns (
            OperatorSet memory operatorSet,
            CurveType curveType,
            OperatorSetConfig memory operatorSetConfig,
            bytes memory operatorTableInfo
        )
    {
        (
            operatorSet, curveType, operatorSetConfig, operatorTableInfo
        ) = abi.decode(operatorTable, (OperatorSet, CurveType, OperatorSetConfig, bytes));
    }

    function _getBN254OperatorInfo(
        bytes memory BN254OperatorSetInfoBytes
    ) internal pure returns (BN254OperatorSetInfo memory) {
        return abi.decode(BN254OperatorSetInfoBytes, (BN254OperatorSetInfo));
    }

    function _getECDSAOperatorInfo(
        bytes memory ECDSAOperatorInfoBytes
    ) internal pure returns (ECDSAOperatorInfo[] memory) {
        return abi.decode(ECDSAOperatorInfoBytes, (ECDSAOperatorInfo[]));
    }

    /**
     * @notice Sets the global root confirmation threshold
     * @param bps The threshold, in bps, for a global root to be signed off on and updated
     */
    function _setGlobalRootConfirmationThreshold(
        uint16 bps
    ) internal {
        require(bps <= MAX_BPS, InvalidConfirmationThreshold());
        globalRootConfirmationThreshold = bps;
        emit GlobalRootConfirmationThresholdUpdated(bps);
    }
}
