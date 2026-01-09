// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {DestinationTaskManagerStorage} from "./middlewares/TaskManagerStorage.sol";
import {NewtonProverTaskManagerShared} from "./NewtonProverTaskManagerShared.sol";
import {IPauserRegistry} from "@eigenlayer/contracts/interfaces/IPauserRegistry.sol";
import {OperatorRegistry} from "./middlewares/OperatorRegistry.sol";
import {IOperatorRegistry} from "./interfaces/IOperatorRegistry.sol";
import {SemVerMixin} from "./mixins/SemVerMixin.sol";

/**
 * @title NewtonProverDestTaskManager
 * @notice Destination chain TaskManager - extends DestinationTaskManagerStorage (no BLSSignatureChecker)
 */
contract NewtonProverDestTaskManager is
    DestinationTaskManagerStorage,
    NewtonProverTaskManagerShared,
    SemVerMixin
{
    constructor(
        OperatorRegistry _operatorRegistry,
        IPauserRegistry _pauserRegistry,
        string memory _version
    )
        DestinationTaskManagerStorage(
            IOperatorRegistry(address(_operatorRegistry)), _pauserRegistry
        )
        SemVerMixin(_version)
    {}

    function initialize(
        address initialOwner,
        address _aggregator, // DEPRECATED: kept for backward compatibility, no longer used
        address _serviceManager,
        address _certificateVerifier,
        address _operatorRegistry,
        address _taskResponseHandler,
        address _challengeVerifier,
        address _attestationValidator,
        uint32 _taskResponseWindowBlock,
        uint32 _epochBlocks
    ) public initializer {
        _transferOwnership(initialOwner);
        aggregator = _aggregator;
        serviceManager = _serviceManager;
        certificateVerifier = _certificateVerifier;
        operatorRegistry = _operatorRegistry;
        taskResponseHandler = _taskResponseHandler;
        challengeVerifier = _challengeVerifier;
        attestationValidator = _attestationValidator;
        taskResponseWindowBlock = _taskResponseWindowBlock;
        epochBlocks = _epochBlocks;
    }
}
