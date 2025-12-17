// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {SourceTaskManagerStorage} from "./middlewares/TaskManagerStorage.sol";
import {NewtonProverTaskManagerShared} from "./NewtonProverTaskManagerShared.sol";
import {IPauserRegistry} from "@eigenlayer/contracts/interfaces/IPauserRegistry.sol";
import {OperatorRegistry} from "./middlewares/OperatorRegistry.sol";
import {
    ISlashingRegistryCoordinator
} from "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {IOperatorRegistry} from "./interfaces/IOperatorRegistry.sol";

/**
 * @title NewtonProverTaskManager
 * @notice Source chain TaskManager - extends SourceTaskManagerStorage which includes BLSSignatureChecker
 */
contract NewtonProverTaskManager is SourceTaskManagerStorage, NewtonProverTaskManagerShared {
    constructor(
        OperatorRegistry _operatorRegistry,
        IPauserRegistry _pauserRegistry
    )
        SourceTaskManagerStorage(
            ISlashingRegistryCoordinator(address(_operatorRegistry)), _pauserRegistry
        )
    {}

    function initialize(
        address initialOwner,
        address _aggregator,
        address _serviceManager,
        address _operatorRegistry,
        address _taskResponseHandler,
        address _challengeVerifier,
        address _attestationValidator,
        uint32 _taskResponseWindowBlock
    ) public initializer {
        _transferOwnership(initialOwner);
        aggregator = _aggregator;
        serviceManager = _serviceManager;
        operatorRegistry = _operatorRegistry;
        taskResponseHandler = _taskResponseHandler;
        challengeVerifier = _challengeVerifier;
        attestationValidator = _attestationValidator;
        taskResponseWindowBlock = _taskResponseWindowBlock;
    }
}
