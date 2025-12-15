// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {INewtonProverTaskManager} from "./interfaces/INewtonProverTaskManager.sol";
import "@eigenlayer-middleware/src/ServiceManagerBase.sol";
import {IAllocationManager} from "@eigenlayer/contracts/interfaces/IAllocationManager.sol";
import {IRewardsCoordinator} from "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";
import {
    ISlashingRegistryCoordinator
} from "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";

/**
 * @title Primary entrypoint for procuring services from NewtonProver.
 * @author Dennis Won
 */
contract NewtonProverServiceManager is ServiceManagerBase {
    /* ERRORS */
    error OnlyNewtonProverTaskManager();

    /* STORAGE */
    INewtonProverTaskManager public immutable NEWTON_PROVER_TASK_MANAGER;

    /// @notice when applied to a function, ensures that the function is only callable by the `registryCoordinator`.
    modifier onlyNewtonProverTaskManager() {
        require(msg.sender == address(NEWTON_PROVER_TASK_MANAGER), OnlyNewtonProverTaskManager());
        _;
    }

    constructor(
        IAVSDirectory _avsDirectory,
        ISlashingRegistryCoordinator _slashingRegistryCoordinator,
        IStakeRegistry _stakeRegistry,
        address rewardsCoordinator,
        IAllocationManager allocationManager,
        IPermissionController _permissionController,
        INewtonProverTaskManager _newtonProverTaskManager
    )
        ServiceManagerBase(
            _avsDirectory,
            IRewardsCoordinator(rewardsCoordinator),
            _slashingRegistryCoordinator,
            _stakeRegistry,
            _permissionController,
            allocationManager
        )
    {
        NEWTON_PROVER_TASK_MANAGER = _newtonProverTaskManager;
    }

    function initialize(
        address initialOwner,
        address rewardsInitiator
    ) external initializer {
        __ServiceManagerBase_init(initialOwner, rewardsInitiator);
    }
}
