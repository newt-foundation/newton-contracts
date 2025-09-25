// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@eigenlayer-middleware/src/libraries/BN254.sol";
import {BLSApkRegistry} from "@eigenlayer-middleware/src/BLSApkRegistry.sol";
import {ISlashingRegistryCoordinator} from
    "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {OperatorStateRetriever} from "@eigenlayer-middleware/src/OperatorStateRetriever.sol";
import {InstantSlasher} from "@eigenlayer-middleware/src/slashers/InstantSlasher.sol";
import {IAllocationManager} from "@eigenlayer/contracts/interfaces/IAllocationManager.sol";
import {IAllocationManagerTypes} from "@eigenlayer/contracts/interfaces/IAllocationManager.sol";
import {OperatorSet} from "@eigenlayer/contracts/libraries/OperatorSetLib.sol";
import {IStrategy} from "@eigenlayer/contracts/interfaces/IStrategy.sol";

/**
 * @title ChallengeLib
 * @dev Library for challenge processing and operator slashing
 */
library ChallengeLib {
    using BN254 for BN254.G1Point;

    error InvalidNonSigners();

    uint256 public constant WADS_TO_SLASH = 100000000000000000; // 10%

    struct ChallengeContext {
        address blsApkRegistry;
        address registryCoordinator;
        address allocationManager;
        address instantSlasher;
        address serviceManager;
    }

    /**
     * @dev Processes non-signing operators for challenge validation
     */
    function processNonSigners(
        BN254.G1Point[] memory pubkeysOfNonSigningOperators,
        address blsApkRegistry
    )
        external
        view
        returns (
            bytes32[] memory hashesOfPubkeysOfNonSigningOperators,
            address[] memory addressOfNonSigningOperators
        )
    {
        uint256 nonSignerLength = pubkeysOfNonSigningOperators.length;
        hashesOfPubkeysOfNonSigningOperators = new bytes32[](nonSignerLength);
        addressOfNonSigningOperators = new address[](nonSignerLength);

        for (uint256 i; i < nonSignerLength;) {
            bytes32 pubkeyHash = pubkeysOfNonSigningOperators[i].hashG1Point();
            hashesOfPubkeysOfNonSigningOperators[i] = pubkeyHash;
            addressOfNonSigningOperators[i] =
                BLSApkRegistry(blsApkRegistry).pubkeyHashToOperator(pubkeyHash);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Validates signatory record hash
     */
    function validateSignatoryRecord(
        uint32 taskCreatedBlock,
        bytes32[] memory hashesOfPubkeysOfNonSigningOperators,
        bytes32 expectedHash
    ) external pure {
        bytes32 signatoryRecordHash =
            keccak256(abi.encodePacked(taskCreatedBlock, hashesOfPubkeysOfNonSigningOperators));
        require(signatoryRecordHash == expectedHash, InvalidNonSigners());
    }

    /**
     * @dev Slashes operators who signed incorrectly
     */
    function slashSigningOperators(
        ChallengeContext memory ctx,
        bytes calldata quorumNumbers,
        uint32 taskCreatedBlock,
        address[] memory addressOfNonSigningOperators
    ) external {
        OperatorStateRetriever.Operator[][] memory allOperatorInfo = OperatorStateRetriever(
            ctx.registryCoordinator
        ).getOperatorState(
            ISlashingRegistryCoordinator(ctx.registryCoordinator), quorumNumbers, taskCreatedBlock
        );

        uint256 nonSignerLength = addressOfNonSigningOperators.length;

        for (uint256 i; i < allOperatorInfo.length;) {
            for (uint256 j; j < allOperatorInfo[i].length;) {
                bytes32 operatorID = allOperatorInfo[i][j].operatorId;
                address operatorAddress =
                    BLSApkRegistry(ctx.blsApkRegistry).getOperatorFromPubkeyHash(operatorID);

                // Check if operator was a signer
                bool wasSigningOperator = true;
                for (uint256 k; k < nonSignerLength;) {
                    if (operatorAddress == addressOfNonSigningOperators[k]) {
                        wasSigningOperator = false;
                        break;
                    }
                    unchecked {
                        ++k;
                    }
                }

                if (wasSigningOperator) {
                    _slashOperator(ctx, operatorAddress, uint8(quorumNumbers[i]));
                }
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Internal function to slash an operator
     */
    function _slashOperator(
        ChallengeContext memory ctx,
        address operatorAddress,
        uint8 quorumId
    ) private {
        OperatorSet memory operatorset = OperatorSet({avs: ctx.serviceManager, id: quorumId});

        IStrategy[] memory strategies =
            IAllocationManager(ctx.allocationManager).getStrategiesInOperatorSet(operatorset);
        uint256 strategyLength = strategies.length;
        uint256[] memory wadsToSlash = new uint256[](strategyLength);

        for (uint256 i; i < strategyLength;) {
            wadsToSlash[i] = WADS_TO_SLASH;
            unchecked {
                ++i;
            }
        }

        IAllocationManagerTypes.SlashingParams memory slashingparams = IAllocationManagerTypes
            .SlashingParams({
            operator: operatorAddress,
            operatorSetId: quorumId,
            strategies: strategies,
            wadsToSlash: wadsToSlash,
            description: "slash_the_operator"
        });

        InstantSlasher(ctx.instantSlasher).fulfillSlashingRequest(slashingparams);
    }
}
