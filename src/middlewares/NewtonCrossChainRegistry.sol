// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@eigenlayer/contracts/permissions/Pausable.sol";
import "@eigenlayer/contracts/mixins/SemVerMixin.sol";

import {OperatorSet} from "@eigenlayer/contracts/libraries/OperatorSetLib.sol";
import {
    IOperatorTableCalculator,
    IOperatorTableCalculatorTypes
} from "@eigenlayer/contracts/interfaces/IOperatorTableCalculator.sol";
import {ICrossChainRegistryTypes} from "@eigenlayer/contracts/interfaces/ICrossChainRegistry.sol";

/**
 * @title NewtonCrossChainRegistry
 * @notice Newton's CrossChainRegistry deployed on Ethereum (source chain) for L2 destinations
 *         that EigenLayer does not yet natively support
 * @dev This contract is deployed on Ethereum mainnet/Sepolia alongside EigenLayer's own
 *      CrossChainRegistry. While EigenLayer's registry handles supported destinations (e.g., Base),
 *      Newton's registry handles other L2s (e.g., Arbitrum, Optimism, Polygon) that EigenLayer
 *      cross-chain infrastructure doesn't yet support.
 */
contract NewtonCrossChainRegistry is Initializable, OwnableUpgradeable, Pausable, SemVerMixin {
    // =============================================================
    //                           CONSTANTS
    // =============================================================

    /// @notice Pause flag for operator set configuration updates
    uint8 public constant PAUSED_OPERATOR_SET_CONFIG = 0;

    /// @notice Pause flag for chain whitelist updates
    uint8 public constant PAUSED_CHAIN_WHITELIST = 1;

    // =============================================================
    //                           ERRORS
    // =============================================================

    /// @notice Thrown when an operator set is not registered
    error OperatorSetNotRegistered();

    /// @notice Thrown when an operator set is already registered
    error OperatorSetAlreadyRegistered();

    /// @notice Thrown when caller is not the operator set owner
    error NotOperatorSetOwner();

    /// @notice Thrown when the operator table calculator is the zero address
    error InvalidOperatorTableCalculator();

    /// @notice Thrown when owner address is the zero address
    error InvalidOwner();

    /// @notice Thrown when chain ID is already whitelisted
    error ChainIdAlreadyWhitelisted();

    /// @notice Thrown when chain ID is not whitelisted
    error ChainIdNotWhitelisted();

    /// @notice Thrown when chain IDs array is empty
    error EmptyChainIds();

    // =============================================================
    //                           EVENTS
    // =============================================================

    /// @notice Emitted when an operator set is registered for cross-chain transport
    event OperatorSetRegistered(
        address indexed avs,
        uint32 indexed operatorSetId,
        address operatorTableCalculator,
        address owner,
        uint32 maxStalenessPeriod
    );

    /// @notice Emitted when an operator set configuration is updated
    event OperatorSetConfigUpdated(
        address indexed avs, uint32 indexed operatorSetId, address owner, uint32 maxStalenessPeriod
    );

    /// @notice Emitted when an operator table calculator is updated
    event OperatorTableCalculatorUpdated(
        address indexed avs, uint32 indexed operatorSetId, address operatorTableCalculator
    );

    /// @notice Emitted when an operator set is removed from registry
    event OperatorSetRemoved(address indexed avs, uint32 indexed operatorSetId);

    /// @notice Emitted when chain IDs are added to whitelist
    event ChainIdsWhitelisted(uint256[] chainIds);

    /// @notice Emitted when chain IDs are removed from whitelist
    event ChainIdsRemovedFromWhitelist(uint256[] chainIds);

    // =============================================================
    //                           STORAGE
    // =============================================================

    /// @notice Mapping from operator set hash to operator set configuration
    mapping(bytes32 => ICrossChainRegistryTypes.OperatorSetConfig) internal _operatorSetConfigs;

    /// @notice Mapping from operator set hash to operator table calculator
    mapping(bytes32 => IOperatorTableCalculator) internal _operatorTableCalculators;

    /// @notice Mapping from operator set hash to registration status
    mapping(bytes32 => bool) internal _isOperatorSetRegistered;

    /// @notice Mapping of whitelisted destination chain IDs
    mapping(uint256 => bool) internal _whitelistedChainIds;

    /// @notice Array of all whitelisted chain IDs for enumeration
    uint256[] internal _supportedChainIds;

    // =============================================================
    //                         CONSTRUCTOR
    // =============================================================

    constructor(
        IPauserRegistry _pauserRegistry,
        string memory _version
    ) Pausable(_pauserRegistry) SemVerMixin(_version) {
        _disableInitializers();
    }

    // =============================================================
    //                         INITIALIZER
    // =============================================================

    /**
     * @notice Initializes the NewtonCrossChainRegistry
     * @param _owner The owner of the contract
     * @param initialPausedStatus The initial paused status
     */
    function initialize(
        address _owner,
        uint256 initialPausedStatus
    ) external initializer {
        _transferOwnership(_owner);
        _setPausedStatus(initialPausedStatus);
    }

    // =============================================================
    //                    OPERATOR SET MANAGEMENT
    // =============================================================

    /**
     * @notice Registers an operator set for cross-chain transport
     * @param operatorSet The operator set to register
     * @param operatorTableCalculator The calculator for computing operator table state
     * @param operatorSetConfig The configuration for the operator set
     * @dev Similar to EigenLayer's createGenerationReservation but simplified
     */
    function createGenerationReservation(
        OperatorSet calldata operatorSet,
        IOperatorTableCalculator operatorTableCalculator,
        ICrossChainRegistryTypes.OperatorSetConfig calldata operatorSetConfig
    ) external onlyWhenNotPaused(PAUSED_OPERATOR_SET_CONFIG) {
        require(address(operatorTableCalculator) != address(0), InvalidOperatorTableCalculator());
        require(operatorSetConfig.owner != address(0), InvalidOwner());

        bytes32 operatorSetHash = _hashOperatorSet(operatorSet);

        require(!_isOperatorSetRegistered[operatorSetHash], OperatorSetAlreadyRegistered());

        _isOperatorSetRegistered[operatorSetHash] = true;
        _operatorSetConfigs[operatorSetHash] = operatorSetConfig;
        _operatorTableCalculators[operatorSetHash] = operatorTableCalculator;

        emit OperatorSetRegistered(
            operatorSet.avs,
            operatorSet.id,
            address(operatorTableCalculator),
            operatorSetConfig.owner,
            operatorSetConfig.maxStalenessPeriod
        );
    }

    /**
     * @notice Removes an operator set from cross-chain registry
     * @param operatorSet The operator set to remove
     * @dev Only the operator set owner can remove the registration
     */
    function removeGenerationReservation(
        OperatorSet calldata operatorSet
    ) external onlyWhenNotPaused(PAUSED_OPERATOR_SET_CONFIG) {
        bytes32 operatorSetHash = _hashOperatorSet(operatorSet);

        require(_isOperatorSetRegistered[operatorSetHash], OperatorSetNotRegistered());
        require(_operatorSetConfigs[operatorSetHash].owner == msg.sender, NotOperatorSetOwner());

        delete _isOperatorSetRegistered[operatorSetHash];
        delete _operatorSetConfigs[operatorSetHash];
        delete _operatorTableCalculators[operatorSetHash];

        emit OperatorSetRemoved(operatorSet.avs, operatorSet.id);
    }

    /**
     * @notice Updates the operator set configuration
     * @param operatorSet The operator set to update
     * @param operatorSetConfig The new configuration
     * @dev Only the current operator set owner can update the config
     */
    function setOperatorSetConfig(
        OperatorSet calldata operatorSet,
        ICrossChainRegistryTypes.OperatorSetConfig calldata operatorSetConfig
    ) external onlyWhenNotPaused(PAUSED_OPERATOR_SET_CONFIG) {
        require(operatorSetConfig.owner != address(0), InvalidOwner());

        bytes32 operatorSetHash = _hashOperatorSet(operatorSet);

        require(_isOperatorSetRegistered[operatorSetHash], OperatorSetNotRegistered());
        require(_operatorSetConfigs[operatorSetHash].owner == msg.sender, NotOperatorSetOwner());

        _operatorSetConfigs[operatorSetHash] = operatorSetConfig;

        emit OperatorSetConfigUpdated(
            operatorSet.avs,
            operatorSet.id,
            operatorSetConfig.owner,
            operatorSetConfig.maxStalenessPeriod
        );
    }

    /**
     * @notice Updates the operator table calculator for an operator set
     * @param operatorSet The operator set to update
     * @param operatorTableCalculator The new operator table calculator
     * @dev Only the operator set owner can update the calculator
     */
    function setOperatorTableCalculator(
        OperatorSet calldata operatorSet,
        IOperatorTableCalculator operatorTableCalculator
    ) external onlyWhenNotPaused(PAUSED_OPERATOR_SET_CONFIG) {
        require(address(operatorTableCalculator) != address(0), InvalidOperatorTableCalculator());

        bytes32 operatorSetHash = _hashOperatorSet(operatorSet);

        require(_isOperatorSetRegistered[operatorSetHash], OperatorSetNotRegistered());
        require(_operatorSetConfigs[operatorSetHash].owner == msg.sender, NotOperatorSetOwner());

        _operatorTableCalculators[operatorSetHash] = operatorTableCalculator;

        emit OperatorTableCalculatorUpdated(
            operatorSet.avs, operatorSet.id, address(operatorTableCalculator)
        );
    }

    // =============================================================
    //                    CHAIN WHITELIST MANAGEMENT
    // =============================================================

    /**
     * @notice Adds chain IDs to the whitelist
     * @param chainIds Array of chain IDs to whitelist
     * @dev Only contract owner can modify whitelist
     */
    function addChainIDsToWhitelist(
        uint256[] calldata chainIds
    ) external onlyOwner onlyWhenNotPaused(PAUSED_CHAIN_WHITELIST) {
        require(chainIds.length > 0, EmptyChainIds());

        for (uint256 i = 0; i < chainIds.length; i++) {
            require(!_whitelistedChainIds[chainIds[i]], ChainIdAlreadyWhitelisted());
            _whitelistedChainIds[chainIds[i]] = true;
            _supportedChainIds.push(chainIds[i]);
        }

        emit ChainIdsWhitelisted(chainIds);
    }

    /**
     * @notice Removes chain IDs from the whitelist
     * @param chainIds Array of chain IDs to remove
     * @dev Only contract owner can modify whitelist
     */
    function removeChainIDsFromWhitelist(
        uint256[] calldata chainIds
    ) external onlyOwner onlyWhenNotPaused(PAUSED_CHAIN_WHITELIST) {
        require(chainIds.length > 0, EmptyChainIds());

        for (uint256 i = 0; i < chainIds.length; i++) {
            require(_whitelistedChainIds[chainIds[i]], ChainIdNotWhitelisted());
            _whitelistedChainIds[chainIds[i]] = false;

            // remove from array
            _removeChainIdFromArray(chainIds[i]);
        }

        emit ChainIdsRemovedFromWhitelist(chainIds);
    }

    // =============================================================
    //                        VIEW FUNCTIONS
    // =============================================================

    /**
     * @notice Returns the operator set configuration
     * @param operatorSet The operator set to query
     * @return The operator set configuration
     */
    function getOperatorSetConfig(
        OperatorSet calldata operatorSet
    ) external view returns (ICrossChainRegistryTypes.OperatorSetConfig memory) {
        bytes32 operatorSetHash = _hashOperatorSet(operatorSet);
        require(_isOperatorSetRegistered[operatorSetHash], OperatorSetNotRegistered());
        return _operatorSetConfigs[operatorSetHash];
    }

    /**
     * @notice Returns the operator table calculator for an operator set
     * @param operatorSet The operator set to query
     * @return The operator table calculator address
     */
    function getOperatorTableCalculator(
        OperatorSet calldata operatorSet
    ) external view returns (IOperatorTableCalculator) {
        bytes32 operatorSetHash = _hashOperatorSet(operatorSet);
        require(_isOperatorSetRegistered[operatorSetHash], OperatorSetNotRegistered());
        return _operatorTableCalculators[operatorSetHash];
    }

    /**
     * @notice Calculates the operator table bytes for an operator set
     * @param operatorSet The operator set to calculate for
     * @return The encoded operator table bytes
     */
    function calculateOperatorTableBytes(
        OperatorSet calldata operatorSet
    ) external view returns (bytes memory) {
        bytes32 operatorSetHash = _hashOperatorSet(operatorSet);
        require(_isOperatorSetRegistered[operatorSetHash], OperatorSetNotRegistered());

        IOperatorTableCalculator calculator = _operatorTableCalculators[operatorSetHash];
        return calculator.calculateOperatorTableBytes(operatorSet);
    }

    /**
     * @notice Checks if an operator set has an active registration
     * @param operatorSet The operator set to check
     * @return True if registered, false otherwise
     */
    function hasActiveGenerationReservation(
        OperatorSet calldata operatorSet
    ) external view returns (bool) {
        return _isOperatorSetRegistered[_hashOperatorSet(operatorSet)];
    }

    /**
     * @notice Returns all supported destination chain IDs
     * @return Array of whitelisted chain IDs
     */
    function getSupportedChains() external view returns (uint256[] memory) {
        return _supportedChainIds;
    }

    /**
     * @notice Checks if a chain ID is whitelisted
     * @param chainId The chain ID to check
     * @return True if whitelisted, false otherwise
     */
    function isChainIdWhitelisted(
        uint256 chainId
    ) external view returns (bool) {
        return _whitelistedChainIds[chainId];
    }

    // =============================================================
    //                      INTERNAL FUNCTIONS
    // =============================================================

    /**
     * @notice Computes the hash of an operator set for storage keys
     * @param operatorSet The operator set to hash
     * @return The keccak256 hash
     */
    function _hashOperatorSet(
        OperatorSet calldata operatorSet
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(operatorSet.avs, operatorSet.id));
    }

    /**
     * @notice Removes a chain ID from the supported chains array
     * @param chainId The chain ID to remove
     */
    function _removeChainIdFromArray(
        uint256 chainId
    ) internal {
        uint256 length = _supportedChainIds.length;
        for (uint256 i = 0; i < length; i++) {
            if (_supportedChainIds[i] == chainId) {
                _supportedChainIds[i] = _supportedChainIds[length - 1];
                _supportedChainIds.pop();
                break;
            }
        }
    }
}
