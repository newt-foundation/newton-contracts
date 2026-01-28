// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IStrategy} from "@eigenlayer/contracts/interfaces/IStrategy.sol";
import {
    ISlashingRegistryCoordinatorTypes
} from "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {IStakeRegistryTypes} from "@eigenlayer-middleware/src/interfaces/IStakeRegistry.sol";
import {UpgradeableProxyLib} from "./UpgradeableProxyLib.sol";
import {OperatorRegistry} from "../../src/middlewares/OperatorRegistry.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {DeploymentLib} from "./DeploymentLib.sol";

library StakeQuorumLib {
    using stdJson for *;
    using Strings for *;
    using UpgradeableProxyLib for address;

    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function createDelegatedStakeQuorum(
        DeploymentLib.NewtonStakingConfig memory config,
        DeploymentLib.DeploymentData memory newtonProver
    ) internal {
        IStrategy[] memory deployedStrategyArray = new IStrategy[](1);
        deployedStrategyArray[0] = IStrategy(newtonProver.strategy);
        uint256 numStrategies = deployedStrategyArray.length;

        uint256 numQuorums = config.numQuorums;
        ISlashingRegistryCoordinatorTypes.OperatorSetParam[] memory quorumsOperatorSetParams =
            new ISlashingRegistryCoordinatorTypes.OperatorSetParam[](numQuorums);
        uint256[] memory operatorParams = config.operatorParams;
        uint96 minimumStake = config.minimumStake;

        IStakeRegistryTypes.StrategyParams[][] memory quorumsStrategyParams =
            new IStakeRegistryTypes.StrategyParams[][](numQuorums);

        // see https://github.com/Layr-Labs/eigenlayer-middleware/blob/m2-mainnet/src/StakeRegistry.sol#L484
        //    weight += uint96(sharesAmount * strategyAndMultiplier.multiplier / WEIGHTING_DIVISOR);
        uint96 multiplier = 1 ether;
        for (uint256 i = 0; i < numQuorums; i++) {
            quorumsOperatorSetParams[i] = ISlashingRegistryCoordinatorTypes.OperatorSetParam({
                maxOperatorCount: uint32(operatorParams[i]),
                kickBIPsOfOperatorStake: uint16(operatorParams[i + 1]),
                kickBIPsOfTotalStake: uint16(operatorParams[i + 2])
            });

            quorumsStrategyParams[i] = new IStakeRegistryTypes.StrategyParams[](numStrategies);
            for (uint256 j = 0; j < numStrategies; ++j) {
                quorumsStrategyParams[i][j] = IStakeRegistryTypes.StrategyParams({
                    strategy: deployedStrategyArray[j], multiplier: multiplier
                });
            }

            OperatorRegistry(newtonProver.operatorRegistry)
                .createTotalDelegatedStakeQuorum(
                    quorumsOperatorSetParams[i], minimumStake, quorumsStrategyParams[i]
                );
        }
    }

    function createSlashableStakeQuorum(
        DeploymentLib.NewtonStakingConfig memory config,
        DeploymentLib.DeploymentData memory newtonProver
    ) internal {
        IStrategy[] memory deployedStrategyArray = new IStrategy[](1);
        deployedStrategyArray[0] = IStrategy(newtonProver.strategy);
        uint256 numStrategies = deployedStrategyArray.length;

        uint256 numQuorums = config.numQuorums;
        ISlashingRegistryCoordinatorTypes.OperatorSetParam[] memory quorumsOperatorSetParams =
            new ISlashingRegistryCoordinatorTypes.OperatorSetParam[](numQuorums);
        uint256[] memory operatorParams = config.operatorParams;
        uint96 minimumStake = config.minimumStake;
        uint32 lookAheadPeriod = config.lookAheadPeriod;

        IStakeRegistryTypes.StrategyParams[][] memory quorumsStrategyParams =
            new IStakeRegistryTypes.StrategyParams[][](numQuorums);

        // see https://github.com/Layr-Labs/eigenlayer-middleware/blob/m2-mainnet/src/StakeRegistry.sol#L484
        //    weight += uint96(sharesAmount * strategyAndMultiplier.multiplier / WEIGHTING_DIVISOR);
        uint96 multiplier = 1 ether;
        for (uint256 i = 0; i < numQuorums; i++) {
            quorumsOperatorSetParams[i] = ISlashingRegistryCoordinatorTypes.OperatorSetParam({
                maxOperatorCount: uint32(operatorParams[i]),
                kickBIPsOfOperatorStake: uint16(operatorParams[i + 1]),
                kickBIPsOfTotalStake: uint16(operatorParams[i + 2])
            });

            quorumsStrategyParams[i] = new IStakeRegistryTypes.StrategyParams[](numStrategies);
            for (uint256 j = 0; j < numStrategies; j++) {
                quorumsStrategyParams[i][j] = IStakeRegistryTypes.StrategyParams({
                    strategy: deployedStrategyArray[j], multiplier: multiplier
                });
            }

            OperatorRegistry(newtonProver.operatorRegistry)
                .createSlashableStakeQuorum(
                    quorumsOperatorSetParams[i],
                    minimumStake,
                    quorumsStrategyParams[i],
                    lookAheadPeriod
                );
        }
    }

    function addOperatorsToWhitelist(
        DeploymentLib.DeploymentData memory newtonProver,
        address[] memory operators
    ) internal {
        OperatorRegistry(newtonProver.operatorRegistry).addMultipleToWhitelist(operators);
    }

    function removeOperatorsFromWhitelist(
        DeploymentLib.DeploymentData memory newtonProver,
        address operator
    ) internal {
        OperatorRegistry(newtonProver.operatorRegistry).removeFromWhitelist(operator);
    }

    function addOperatorToWhitelist(
        DeploymentLib.DeploymentData memory newtonProver,
        address operator
    ) internal {
        OperatorRegistry(newtonProver.operatorRegistry).addToWhitelist(operator);
    }
}
