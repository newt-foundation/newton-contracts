// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {
    SlashingRegistryCoordinator
} from "@eigenlayer-middleware/src/SlashingRegistryCoordinator.sol";
import {
    ISlashingRegistryCoordinatorTypes
} from "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {IStakeRegistry} from "@eigenlayer-middleware/src/interfaces/IStakeRegistry.sol";
import {IBLSApkRegistry} from "@eigenlayer-middleware/src/interfaces/IBLSApkRegistry.sol";
import {IIndexRegistry} from "@eigenlayer-middleware/src/interfaces/IIndexRegistry.sol";
import {ISocketRegistry} from "@eigenlayer-middleware/src/interfaces/ISocketRegistry.sol";
import {IAllocationManager} from "@eigenlayer/contracts/interfaces/IAllocationManager.sol";
import {IPauserRegistry} from "@eigenlayer/contracts/interfaces/IPauserRegistry.sol";
import {ChainLib} from "../libraries/ChainLib.sol";
import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";

contract OperatorRegistry is SlashingRegistryCoordinator, IOperatorRegistry {
    /* CUSTOM ERRORS */
    error GeneratorDoesNotExist();
    error GeneratorAlreadyExists();
    error OperatorNotWhitelisted(address operator);
    error OperatorAlreadyWhitelisted(address operator);
    error OperatorNotInWhitelist(address operator);
    error InvalidAddress();

    /* EVENTS */
    event TaskGeneratorAdded(address indexed generator);
    event TaskGeneratorRemoved(address indexed generator);

    /* STORAGE */
    /// @notice Mapping to track whitelisted operators
    mapping(address => bool) public whitelistedOperators;

    /// @notice Array to keep track of all whitelisted operators for enumeration
    address[] public whitelistedOperatorsList;

    /// @notice Mapping to track if an operator is in the whitelist array (for efficient removal)
    mapping(address => uint256) private _whitelistedOperatorsIndex;

    /// @notice Task generator management
    mapping(address => bool) public taskGenerators;

    /// @notice mapping from quorum number to registered operators
    mapping(bytes32 => mapping(address => ISlashingRegistryCoordinatorTypes.OperatorInfo)) private
        _quorumNumberToOperators;

    /* EVENTS */
    event OperatorWhitelisted(address indexed operator, bool isWhitelisted);

    constructor(
        IStakeRegistry _stakeRegistry,
        IBLSApkRegistry _blsApkRegistry,
        IIndexRegistry _indexRegistry,
        ISocketRegistry _socketRegistry,
        IAllocationManager _allocationManager,
        IPauserRegistry _pauserRegistry,
        string memory _version
    )
        SlashingRegistryCoordinator(
            _stakeRegistry,
            _blsApkRegistry,
            _indexRegistry,
            _socketRegistry,
            _allocationManager,
            _pauserRegistry,
            _version
        )
    {}

    /// @dev Hook to allow for any pre-register logic in `_registerOperator`
    function _beforeRegisterOperator(
        address operator,
        bytes32,
        /* operatorId */
        bytes memory,
        /* quorumNumbers */
        uint192 /* currentBitmap */
    ) internal virtual override {
        // Check if operator is whitelisted
        ChainLib.requireSupportedChain();
        if (ChainLib.isMainnet() && !whitelistedOperators[operator]) {
            revert OperatorNotWhitelisted(operator);
        }
    }

    /// @dev Hook to allow for any post-register logic in `_registerOperator`
    function _afterRegisterOperator(
        address operator,
        bytes32 operatorId,
        bytes memory quorumNumbers,
        uint192 /* newBitmap */
    ) internal virtual override {
        bytes32 quorumNumberHash = keccak256(quorumNumbers);
        // Update quorum number to operators registered mapping
        _quorumNumberToOperators[quorumNumberHash][operator] =
            ISlashingRegistryCoordinatorTypes.OperatorInfo(
                operatorId, ISlashingRegistryCoordinatorTypes.OperatorStatus.REGISTERED
            );
    }

    /// @dev Hook to allow for any pre-deregister logic in `_deregisterOperator`
    function _beforeDeregisterOperator(
        address operator,
        bytes32 operatorId,
        bytes memory quorumNumbers,
        uint192 currentBitmap
    ) internal virtual override {}

    /// @dev Hook to allow for any post-deregister logic in `_deregisterOperator`
    function _afterDeregisterOperator(
        address operator,
        bytes32 operatorId,
        bytes memory quorumNumbers,
        uint192 /* newBitmap */
    ) internal virtual override {
        bytes32 quorumNumberHash = keccak256(quorumNumbers);
        require(
            _quorumNumberToOperators[quorumNumberHash][operator].status
                == ISlashingRegistryCoordinatorTypes.OperatorStatus.REGISTERED,
            OperatorNotRegisteredForQuorum()
        );
        // Update quorum number to operators registered mapping
        _quorumNumberToOperators[quorumNumberHash][operator] =
            ISlashingRegistryCoordinatorTypes.OperatorInfo(
                operatorId, ISlashingRegistryCoordinatorTypes.OperatorStatus.DEREGISTERED
            );
    }

    /* WHITELIST MANAGEMENT FUNCTIONS */

    /**
     * @notice Get all operators registered for a given quorum number
     * @param quorumNumbers The quorum number bytes to get operators for
     * @return An array of operator addresses registered for the given quorum number
     */
    function getRegisteredOperators(
        bytes memory quorumNumbers
    ) public view returns (address[] memory) {
        bytes32 quorumNumberHash = keccak256(quorumNumbers);
        address[] memory operators = new address[](whitelistedOperatorsList.length);
        for (uint256 i = 0; i < operators.length; i++) {
            address operator = whitelistedOperatorsList[i];
            if (
                _quorumNumberToOperators[quorumNumberHash][operator].status
                    == ISlashingRegistryCoordinatorTypes.OperatorStatus.REGISTERED
            ) {
                operators[i] = operator;
            }
        }
        return operators;
    }

    /**
     * @notice Get all whitelisted operators
     * @return An array of whitelisted operator addresses
     */
    function getAllWhitelistedOperators() public view returns (address[] memory) {
        return whitelistedOperatorsList;
    }

    /**
     * @notice Add an operator to the whitelist
     * @param operator The operator address to whitelist
     * @dev Only callable by the owner
     */
    function addToWhitelist(
        address operator
    ) external onlyOwner {
        if (operator == address(0)) revert InvalidAddress();
        if (whitelistedOperators[operator]) {
            revert OperatorAlreadyWhitelisted(operator);
        }

        whitelistedOperators[operator] = true;
        _whitelistedOperatorsIndex[operator] = whitelistedOperatorsList.length;
        whitelistedOperatorsList.push(operator);

        emit OperatorWhitelisted(operator, true);
    }

    /**
     * @notice Remove an operator from the whitelist
     * @param operator The operator address to remove from whitelist
     * @dev Only callable by the owner
     */
    function removeFromWhitelist(
        address operator
    ) external onlyOwner {
        if (!whitelistedOperators[operator]) {
            revert OperatorNotInWhitelist(operator);
        }

        whitelistedOperators[operator] = false;

        // Remove from array efficiently
        uint256 index = _whitelistedOperatorsIndex[operator];
        uint256 lastIndex = whitelistedOperatorsList.length - 1;

        if (index != lastIndex) {
            address lastOperator = whitelistedOperatorsList[lastIndex];
            whitelistedOperatorsList[index] = lastOperator;
            _whitelistedOperatorsIndex[lastOperator] = index;
        }

        whitelistedOperatorsList.pop();
        delete _whitelistedOperatorsIndex[operator];

        emit OperatorWhitelisted(operator, false);
    }

    /**
     * @notice Add multiple operators to the whitelist in a single transaction
     * @param operators Array of operator addresses to whitelist
     * @dev Only callable by the owner
     */
    function addMultipleToWhitelist(
        address[] calldata operators
    ) external onlyOwner {
        for (uint256 i = 0; i < operators.length; i++) {
            address operator = operators[i];
            if (operator == address(0)) revert InvalidAddress();
            if (whitelistedOperators[operator]) {
                revert OperatorAlreadyWhitelisted(operator);
            }

            whitelistedOperators[operator] = true;
            _whitelistedOperatorsIndex[operator] = whitelistedOperatorsList.length;
            whitelistedOperatorsList.push(operator);

            emit OperatorWhitelisted(operator, true);
        }
    }

    /**
     * @notice Check if an operator is whitelisted
     * @param operator The operator address to check
     * @return True if the operator is whitelisted, false otherwise
     */
    function isOperatorWhitelisted(
        address operator
    ) external view returns (bool) {
        return whitelistedOperators[operator];
    }

    /**
     * @notice Add a task generator
     * @param generator The task generator address to add
     * @dev Only callable by the owner
     */
    function addTaskGenerator(
        address generator
    ) external onlyOwner {
        if (generator == address(0)) revert InvalidAddress();
        if (taskGenerators[generator]) revert GeneratorAlreadyExists();
        taskGenerators[generator] = true;
        emit TaskGeneratorAdded(generator);
    }

    /**
     * @notice Add multiple task generators in a single transaction
     * @param generators Array of task generator addresses to add
     * @dev Only callable by the owner
     */
    function addMultipleToTaskGenerators(
        address[] calldata generators
    ) external onlyOwner {
        for (uint256 i = 0; i < generators.length; i++) {
            address generator = generators[i];
            if (generator == address(0)) revert InvalidAddress();
            if (taskGenerators[generator]) revert GeneratorAlreadyExists();
            taskGenerators[generator] = true;
            emit TaskGeneratorAdded(generator);
        }
    }

    /**
     * @notice Remove a task generator
     * @param generator The task generator address to remove
     * @dev Only callable by the owner
     */
    function removeTaskGenerator(
        address generator
    ) external onlyOwner {
        if (!taskGenerators[generator]) revert GeneratorDoesNotExist();
        delete taskGenerators[generator];
        emit TaskGeneratorRemoved(generator);
    }

    /**
     * @notice Check if a generator is a task generator
     * @param generator The generator address to check
     * @return True if the generator is a task generator, false otherwise
     */
    function isTaskGenerator(
        address generator
    ) external view returns (bool) {
        return taskGenerators[generator];
    }
}
