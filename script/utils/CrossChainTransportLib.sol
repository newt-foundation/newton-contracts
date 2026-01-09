// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {OperatorRegistry} from "../../src/middlewares/OperatorRegistry.sol";
import {OperatorSet} from "@eigenlayer/contracts/libraries/OperatorSetLib.sol";
import {IKeyRegistrar} from "@eigenlayer/contracts/interfaces/IKeyRegistrar.sol";
import {IKeyRegistrarTypes} from "@eigenlayer/contracts/interfaces/IKeyRegistrar.sol";
import {ICrossChainRegistry} from "@eigenlayer/contracts/interfaces/ICrossChainRegistry.sol";
import {ICrossChainRegistryTypes} from "@eigenlayer/contracts/interfaces/ICrossChainRegistry.sol";
import {
    IOperatorTableCalculator
} from "@eigenlayer/contracts/interfaces/IOperatorTableCalculator.sol";
import {CoreDeploymentLib} from "./CoreDeploymentLib.sol";
import {DeploymentLib} from "./DeploymentLib.sol";

library CrossChainTransportLib {
    /// @notice configure crosschain transport
    /// @param coreData core deployment data
    /// @param deploymentData avs deployment data
    /// @param owner owner
    function configureCrossChainTransport(
        CoreDeploymentLib.DeploymentData memory coreData,
        DeploymentLib.DeploymentData memory deploymentData,
        address owner
    ) external {
        uint8 numQuorums = OperatorRegistry(deploymentData.operatorRegistry).quorumCount();

        IKeyRegistrar keyRegistrar = IKeyRegistrar(coreData.keyRegistrar);
        ICrossChainRegistry crossChainRegistry = ICrossChainRegistry(coreData.crossChainRegistry);

        // transport all quorums
        for (uint32 i = 0; i < numQuorums; i++) {
            OperatorSet memory operatorSet =
                OperatorSet({avs: deploymentData.newtonProverServiceManager, id: i});

            // only set if not already set
            if (
                keyRegistrar.getOperatorSetCurveType(operatorSet)
                    == IKeyRegistrarTypes.CurveType.NONE
            ) {
                keyRegistrar.configureOperatorSet(operatorSet, IKeyRegistrarTypes.CurveType.BN254);
            }

            // create generation reservation if not already existing
            try crossChainRegistry.createGenerationReservation(
                operatorSet,
                IOperatorTableCalculator(deploymentData.operatorTableCalculator),
                ICrossChainRegistryTypes.OperatorSetConfig({
                    owner: owner,
                    maxStalenessPeriod: 0 // never stale
                })
            ) {}
                catch {
                // existing
            }
        }
    }
}
