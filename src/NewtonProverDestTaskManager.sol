// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {DestinationTaskManagerStorage} from "./middlewares/TaskManagerStorage.sol";
import {NewtonProverTaskManagerShared} from "./NewtonProverTaskManagerShared.sol";
import {IPauserRegistry} from "@eigenlayer/contracts/interfaces/IPauserRegistry.sol";
import {OperatorRegistry} from "./middlewares/OperatorRegistry.sol";
import {IOperatorRegistry} from "./interfaces/IOperatorRegistry.sol";

/**
 * @title NewtonProverDestTaskManager
 * @notice Destination chain TaskManager - extends DestinationTaskManagerStorage (no BLSSignatureChecker)
 */
contract NewtonProverDestTaskManager is
    DestinationTaskManagerStorage,
    NewtonProverTaskManagerShared
{
    constructor(
        OperatorRegistry _operatorRegistry,
        IPauserRegistry _pauserRegistry
    )
        DestinationTaskManagerStorage(
            IOperatorRegistry(address(_operatorRegistry)), _pauserRegistry
        )
    {}

    function initialize(
        address initialOwner,
        address _aggregator,
        address _certificateVerifier,
        address _operatorRegistry,
        address _taskResponseHandler,
        address _challengeVerifier,
        address _attestationValidator,
        uint32 _taskResponseWindowBlock
    ) public initializer {
        _transferOwnership(initialOwner);
        aggregator = _aggregator;
        certificateVerifier = _certificateVerifier;
        operatorRegistry = _operatorRegistry;
        taskResponseHandler = _taskResponseHandler;
        challengeVerifier = _challengeVerifier;
        attestationValidator = _attestationValidator;
        taskResponseWindowBlock = _taskResponseWindowBlock;
    }
}
