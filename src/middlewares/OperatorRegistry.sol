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
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ChainLib} from "../libraries/ChainLib.sol";
import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";

contract OperatorRegistry is SlashingRegistryCoordinator, IOperatorRegistry {
    using EnumerableSet for EnumerableSet.AddressSet;

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
    event OperatorWhitelisted(address indexed operator, bool indexed isWhitelisted);

    /* STORAGE */
    /// @notice mapping from quorum number to registered operators
    mapping(bytes32 => mapping(address => ISlashingRegistryCoordinatorTypes.OperatorInfo)) private
        _quorumNumberToOperators;

    EnumerableSet.AddressSet private _whitelistedOperators;
    EnumerableSet.AddressSet private _taskGenerators;

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
        ChainLib.requireSupportedChain();
        if (ChainLib.isMainnet() && !_whitelistedOperators.contains(operator)) {
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
        uint256 length = _whitelistedOperators.length();
        address[] memory operators = new address[](length);
        for (uint256 i = 0; i < length; ++i) {
            address operator = _whitelistedOperators.at(i);
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
        return _whitelistedOperators.values();
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
        if (!_whitelistedOperators.add(operator)) {
            revert OperatorAlreadyWhitelisted(operator);
        }
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
        if (!_whitelistedOperators.remove(operator)) {
            revert OperatorNotInWhitelist(operator);
        }
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
        for (uint256 i = 0; i < operators.length; ++i) {
            address operator = operators[i];
            if (operator == address(0)) revert InvalidAddress();
            if (!_whitelistedOperators.add(operator)) {
                revert OperatorAlreadyWhitelisted(operator);
            }
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
        return _whitelistedOperators.contains(operator);
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
        if (!_taskGenerators.add(generator)) revert GeneratorAlreadyExists();
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
        for (uint256 i = 0; i < generators.length; ++i) {
            address generator = generators[i];
            if (generator == address(0)) revert InvalidAddress();
            if (!_taskGenerators.add(generator)) revert GeneratorAlreadyExists();
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
        if (!_taskGenerators.remove(generator)) revert GeneratorDoesNotExist();
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
        return _taskGenerators.contains(generator);
    }

    /**
     * @notice Get all task generators
     * @return An array of task generator addresses
     */
    function getAllTaskGenerators() external view returns (address[] memory) {
        return _taskGenerators.values();
    }
}
