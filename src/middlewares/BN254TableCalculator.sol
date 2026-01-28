// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@eigenlayer/contracts/permissions/Pausable.sol";
import "@eigenlayer/contracts/mixins/SemVerMixin.sol";

import {OperatorSet} from "@eigenlayer/contracts/libraries/OperatorSetLib.sol";
import {BN254} from "@eigenlayer/contracts/libraries/BN254.sol";
import {
    IOperatorTableCalculator,
    IOperatorTableCalculatorTypes
} from "@eigenlayer/contracts/interfaces/IOperatorTableCalculator.sol";

/**
 * @title BN254TableCalculator
 * @notice Operator table calculator deployed on Ethereum (source chain) for use with
 *         NewtonCrossChainRegistry to handle L2 destinations EigenLayer doesn't support
 * @dev This contract is deployed on Ethereum mainnet/Sepolia alongside NewtonCrossChainRegistry.
 *      It provides operator stake weight management and BLS key aggregation without requiring
 *      AllocationManager or KeyRegistrar dependencies.
 */
contract BN254TableCalculator is
    Initializable,
    OwnableUpgradeable,
    Pausable,
    SemVerMixin,
    IOperatorTableCalculator
{
    using BN254 for BN254.G1Point;

    // =============================================================
    //                           CONSTANTS
    // =============================================================

    /// @notice Pause flag for operator updates
    uint8 public constant PAUSED_OPERATOR_UPDATES = 0;

    // =============================================================
    //                           ERRORS
    // =============================================================

    /// @notice Thrown when operator is not registered
    error OperatorNotRegistered(address operator);

    /// @notice Thrown when operator is already registered
    error OperatorAlreadyRegistered(address operator);

    /// @notice Thrown when operator set is not configured
    error OperatorSetNotConfigured();

    /// @notice Thrown when arrays have mismatched lengths
    error ArrayLengthMismatch();

    /// @notice Thrown when BLS public key is invalid
    error InvalidBLSPubkey();

    /// @notice Thrown when weights array is empty
    error EmptyWeights();

    /// @notice Thrown when max operators limit reached
    error MaxOperatorsReached();

    /// @notice Thrown when operator set is already configured
    error OperatorSetAlreadyConfigured();

    // =============================================================
    //                           EVENTS
    // =============================================================

    /// @notice Emitted when an operator is registered
    event OperatorRegistered(address indexed operator, BN254.G1Point pubkey, uint256[] weights);

    /// @notice Emitted when an operator is deregistered
    event OperatorDeregistered(address indexed operator);

    /// @notice Emitted when operator weights are updated
    event OperatorWeightsUpdated(
        address indexed operator, uint256[] oldWeights, uint256[] newWeights
    );

    /// @notice Emitted when operator BLS key is updated
    event OperatorPubkeyUpdated(
        address indexed operator, BN254.G1Point oldPubkey, BN254.G1Point newPubkey
    );

    /// @notice Emitted when operator info tree root is set
    event OperatorInfoTreeRootSet(
        address indexed avs, uint32 indexed operatorSetId, bytes32 operatorInfoTreeRoot
    );

    // =============================================================
    //                           STRUCTS
    // =============================================================

    /// @notice Operator data storage
    struct OperatorData {
        BN254.G1Point pubkey;
        uint256[] weights;
        bool isRegistered;
        uint256 index; // index in operators array
    }

    /// @notice Operator set configuration
    struct OperatorSetData {
        address[] operators;
        BN254.G1Point aggregatePubkey;
        uint256[] totalWeights;
        bytes32 operatorInfoTreeRoot;
        bool isConfigured;
    }

    // =============================================================
    //                           STORAGE
    // =============================================================

    /// @notice Maximum number of operators per operator set
    uint256 public constant MAX_OPERATORS = 256;

    /// @notice Mapping from operator set hash to operator set data
    mapping(bytes32 => OperatorSetData) internal _operatorSetData;

    /// @notice Mapping from operator set hash => operator address => operator data
    mapping(bytes32 => mapping(address => OperatorData)) internal _operatorData;

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
     * @notice Initializes the BN254TableCalculator
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
    //                 OPERATOR SET CONFIGURATION
    // =============================================================

    /**
     * @notice Configures an operator set for the first time
     * @param operatorSet The operator set to configure
     * @param numWeightTypes The number of weight types to track
     */
    function configureOperatorSet(
        OperatorSet calldata operatorSet,
        uint256 numWeightTypes
    ) external onlyOwner {
        bytes32 opSetHash = _hashOperatorSet(operatorSet);

        OperatorSetData storage data = _operatorSetData[opSetHash];
        require(!data.isConfigured, OperatorSetAlreadyConfigured());

        data.isConfigured = true;
        data.totalWeights = new uint256[](numWeightTypes);
        data.aggregatePubkey = BN254.G1Point(0, 0);
    }

    // =============================================================
    //                    OPERATOR MANAGEMENT
    // =============================================================

    /**
     * @notice Registers an operator with their BLS public key and weights
     * @param operatorSet The operator set to register in
     * @param operator The operator address
     * @param pubkey The operator's BLS G1 public key
     * @param weights The operator's weights
     */
    function registerOperator(
        OperatorSet calldata operatorSet,
        address operator,
        BN254.G1Point calldata pubkey,
        uint256[] calldata weights
    ) external onlyOwner onlyWhenNotPaused(PAUSED_OPERATOR_UPDATES) {
        require(pubkey.X != 0 || pubkey.Y != 0, InvalidBLSPubkey());
        require(weights.length > 0, EmptyWeights());

        bytes32 opSetHash = _hashOperatorSet(operatorSet);
        OperatorSetData storage setData = _operatorSetData[opSetHash];
        require(setData.isConfigured, OperatorSetNotConfigured());
        require(setData.operators.length < MAX_OPERATORS, MaxOperatorsReached());

        OperatorData storage opData = _operatorData[opSetHash][operator];
        require(!opData.isRegistered, OperatorAlreadyRegistered(operator));
        require(weights.length == setData.totalWeights.length, ArrayLengthMismatch());

        // Register operator
        opData.isRegistered = true;
        opData.pubkey = pubkey;
        opData.weights = weights;
        opData.index = setData.operators.length;
        setData.operators.push(operator);

        // Update aggregate pubkey
        if (setData.aggregatePubkey.X == 0 && setData.aggregatePubkey.Y == 0) {
            setData.aggregatePubkey = pubkey;
        } else {
            setData.aggregatePubkey = setData.aggregatePubkey.plus(pubkey);
        }

        // Update total weights
        for (uint256 i = 0; i < weights.length; i++) {
            setData.totalWeights[i] += weights[i];
        }

        emit OperatorRegistered(operator, pubkey, weights);
    }

    /**
     * @notice Deregisters an operator from an operator set
     * @param operatorSet The operator set to deregister from
     * @param operator The operator address to deregister
     */
    function deregisterOperator(
        OperatorSet calldata operatorSet,
        address operator
    ) external onlyOwner onlyWhenNotPaused(PAUSED_OPERATOR_UPDATES) {
        bytes32 opSetHash = _hashOperatorSet(operatorSet);
        OperatorSetData storage setData = _operatorSetData[opSetHash];
        require(setData.isConfigured, OperatorSetNotConfigured());

        OperatorData storage opData = _operatorData[opSetHash][operator];
        require(opData.isRegistered, OperatorNotRegistered(operator));

        // Subtract from aggregate pubkey (negate and add)
        BN254.G1Point memory negatedPubkey = opData.pubkey.negate();
        setData.aggregatePubkey = setData.aggregatePubkey.plus(negatedPubkey);

        // Subtract from total weights
        for (uint256 i = 0; i < opData.weights.length; i++) {
            setData.totalWeights[i] -= opData.weights[i];
        }

        // Remove from operators array (swap and pop)
        uint256 lastIndex = setData.operators.length - 1;
        if (opData.index != lastIndex) {
            address lastOperator = setData.operators[lastIndex];
            setData.operators[opData.index] = lastOperator;
            _operatorData[opSetHash][lastOperator].index = opData.index;
        }
        setData.operators.pop();

        // Clear operator data
        delete _operatorData[opSetHash][operator];

        emit OperatorDeregistered(operator);
    }

    /**
     * @notice Updates an operator's weights
     * @param operatorSet The operator set
     * @param operator The operator address
     * @param newWeights The new weights
     */
    function updateOperatorWeights(
        OperatorSet calldata operatorSet,
        address operator,
        uint256[] calldata newWeights
    ) external onlyOwner onlyWhenNotPaused(PAUSED_OPERATOR_UPDATES) {
        bytes32 opSetHash = _hashOperatorSet(operatorSet);
        OperatorSetData storage setData = _operatorSetData[opSetHash];
        require(setData.isConfigured, OperatorSetNotConfigured());

        OperatorData storage opData = _operatorData[opSetHash][operator];
        require(opData.isRegistered, OperatorNotRegistered(operator));
        require(newWeights.length == setData.totalWeights.length, ArrayLengthMismatch());

        uint256[] memory oldWeights = opData.weights;

        // Update total weights
        for (uint256 i = 0; i < newWeights.length; i++) {
            setData.totalWeights[i] = setData.totalWeights[i] - oldWeights[i] + newWeights[i];
        }

        // Update operator weights
        opData.weights = newWeights;

        emit OperatorWeightsUpdated(operator, oldWeights, newWeights);
    }

    /**
     * @notice Updates an operator's BLS public key
     * @param operatorSet The operator set
     * @param operator The operator address
     * @param newPubkey The new BLS public key
     */
    function updateOperatorPubkey(
        OperatorSet calldata operatorSet,
        address operator,
        BN254.G1Point calldata newPubkey
    ) external onlyOwner onlyWhenNotPaused(PAUSED_OPERATOR_UPDATES) {
        require(newPubkey.X != 0 || newPubkey.Y != 0, InvalidBLSPubkey());

        bytes32 opSetHash = _hashOperatorSet(operatorSet);
        OperatorSetData storage setData = _operatorSetData[opSetHash];
        require(setData.isConfigured, OperatorSetNotConfigured());

        OperatorData storage opData = _operatorData[opSetHash][operator];
        require(opData.isRegistered, OperatorNotRegistered(operator));

        BN254.G1Point memory oldPubkey = opData.pubkey;

        // Update aggregate pubkey
        BN254.G1Point memory negatedOld = oldPubkey.negate();
        setData.aggregatePubkey = setData.aggregatePubkey.plus(negatedOld).plus(newPubkey);

        // Update operator pubkey
        opData.pubkey = newPubkey;

        emit OperatorPubkeyUpdated(operator, oldPubkey, newPubkey);
    }

    /**
     * @notice Sets the operator info tree root (computed off-chain)
     * @param operatorSet The operator set
     * @param operatorInfoTreeRoot The merkle root of operator info tree
     * @dev This root is computed off-chain per ELIP-008 specification
     */
    function setOperatorInfoTreeRoot(
        OperatorSet calldata operatorSet,
        bytes32 operatorInfoTreeRoot
    ) external onlyOwner {
        bytes32 opSetHash = _hashOperatorSet(operatorSet);
        OperatorSetData storage setData = _operatorSetData[opSetHash];
        require(setData.isConfigured, OperatorSetNotConfigured());

        setData.operatorInfoTreeRoot = operatorInfoTreeRoot;

        emit OperatorInfoTreeRootSet(operatorSet.avs, operatorSet.id, operatorInfoTreeRoot);
    }

    // =============================================================
    //               IOperatorTableCalculator INTERFACE
    // =============================================================

    /**
     * @notice Calculates the operator table bytes for an operator set
     * @param operatorSet The operator set to calculate for
     * @return operatorTableBytes The ABI-encoded BN254OperatorSetInfo
     */
    function calculateOperatorTableBytes(
        OperatorSet calldata operatorSet
    ) external view override returns (bytes memory operatorTableBytes) {
        bytes32 opSetHash = _hashOperatorSet(operatorSet);
        OperatorSetData storage setData = _operatorSetData[opSetHash];
        require(setData.isConfigured, OperatorSetNotConfigured());

        IOperatorTableCalculatorTypes.BN254OperatorSetInfo memory info =
            IOperatorTableCalculatorTypes.BN254OperatorSetInfo({
                operatorInfoTreeRoot: setData.operatorInfoTreeRoot,
                numOperators: setData.operators.length,
                aggregatePubkey: setData.aggregatePubkey,
                totalWeights: setData.totalWeights
            });

        return abi.encode(info);
    }

    /**
     * @notice Gets all operator weights for an operator set
     * @param operatorSet The operator set to query
     * @return operators The operator addresses
     * @return weights The 2D weights array
     */
    function getOperatorSetWeights(
        OperatorSet calldata operatorSet
    ) external view override returns (address[] memory operators, uint256[][] memory weights) {
        bytes32 opSetHash = _hashOperatorSet(operatorSet);
        OperatorSetData storage setData = _operatorSetData[opSetHash];
        require(setData.isConfigured, OperatorSetNotConfigured());

        uint256 numOperators = setData.operators.length;
        operators = new address[](numOperators);
        weights = new uint256[][](numOperators);

        for (uint256 i = 0; i < numOperators; i++) {
            address op = setData.operators[i];
            operators[i] = op;
            weights[i] = _operatorData[opSetHash][op].weights;
        }
    }

    /**
     * @notice Gets the weights for a specific operator
     * @param operatorSet The operator set to query
     * @param operator The operator address
     * @return weights The operator's weights
     */
    function getOperatorWeights(
        OperatorSet calldata operatorSet,
        address operator
    ) external view override returns (uint256[] memory weights) {
        bytes32 opSetHash = _hashOperatorSet(operatorSet);
        OperatorData storage opData = _operatorData[opSetHash][operator];
        require(opData.isRegistered, OperatorNotRegistered(operator));
        return opData.weights;
    }

    // =============================================================
    //                        VIEW FUNCTIONS
    // =============================================================

    /**
     * @notice Returns the operator set info
     * @param operatorSet The operator set to query
     * @return info The BN254OperatorSetInfo struct
     */
    function getOperatorSetInfo(
        OperatorSet calldata operatorSet
    ) external view returns (IOperatorTableCalculatorTypes.BN254OperatorSetInfo memory info) {
        bytes32 opSetHash = _hashOperatorSet(operatorSet);
        OperatorSetData storage setData = _operatorSetData[opSetHash];
        require(setData.isConfigured, OperatorSetNotConfigured());

        return IOperatorTableCalculatorTypes.BN254OperatorSetInfo({
            operatorInfoTreeRoot: setData.operatorInfoTreeRoot,
            numOperators: setData.operators.length,
            aggregatePubkey: setData.aggregatePubkey,
            totalWeights: setData.totalWeights
        });
    }

    /**
     * @notice Returns the operator info
     * @param operatorSet The operator set
     * @param operator The operator address
     * @return info The BN254OperatorInfo struct
     */
    function getOperatorInfo(
        OperatorSet calldata operatorSet,
        address operator
    ) external view returns (IOperatorTableCalculatorTypes.BN254OperatorInfo memory info) {
        bytes32 opSetHash = _hashOperatorSet(operatorSet);
        OperatorData storage opData = _operatorData[opSetHash][operator];
        require(opData.isRegistered, OperatorNotRegistered(operator));

        return IOperatorTableCalculatorTypes.BN254OperatorInfo({
            pubkey: opData.pubkey, weights: opData.weights
        });
    }

    /**
     * @notice Returns all operators in an operator set
     * @param operatorSet The operator set to query
     * @return operators Array of operator addresses
     */
    function getOperators(
        OperatorSet calldata operatorSet
    ) external view returns (address[] memory operators) {
        bytes32 opSetHash = _hashOperatorSet(operatorSet);
        OperatorSetData storage setData = _operatorSetData[opSetHash];
        require(setData.isConfigured, OperatorSetNotConfigured());
        return setData.operators;
    }

    /**
     * @notice Checks if an operator is registered
     * @param operatorSet The operator set
     * @param operator The operator address
     * @return True if registered
     */
    function isOperatorRegistered(
        OperatorSet calldata operatorSet,
        address operator
    ) external view returns (bool) {
        bytes32 opSetHash = _hashOperatorSet(operatorSet);
        return _operatorData[opSetHash][operator].isRegistered;
    }

    /**
     * @notice Checks if an operator set is configured
     * @param operatorSet The operator set
     * @return True if configured
     */
    function isOperatorSetConfigured(
        OperatorSet calldata operatorSet
    ) external view returns (bool) {
        bytes32 opSetHash = _hashOperatorSet(operatorSet);
        return _operatorSetData[opSetHash].isConfigured;
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
}
