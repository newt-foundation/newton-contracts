// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {stdJson} from "forge-std/StdJson.sol";

import {UpgradeableProxyLib} from "./UpgradeableProxyLib.sol";
import {CoreDeploymentLib} from "./CoreDeploymentLib.sol";
import {DeploymentLib} from "./DeploymentLib.sol";

// EigenLayer imports
import {IPauserRegistry} from "@eigenlayer/contracts/interfaces/IPauserRegistry.sol";
import {PauserRegistry} from "@eigenlayer/contracts/permissions/PauserRegistry.sol";
import {OperatorSet} from "@eigenlayer/contracts/libraries/OperatorSetLib.sol";
import {
    IOperatorTableCalculator
} from "@eigenlayer/contracts/interfaces/IOperatorTableCalculator.sol";
import {
    IOperatorTableCalculatorTypes
} from "@eigenlayer/contracts/interfaces/IOperatorTableCalculator.sol";
import {ICrossChainRegistryTypes} from "@eigenlayer/contracts/interfaces/ICrossChainRegistry.sol";
import {IKeyRegistrarTypes} from "@eigenlayer/contracts/interfaces/IKeyRegistrar.sol";
import {BN254} from "@eigenlayer/contracts/libraries/BN254.sol";

// EigenLayer middleware imports
import {
    IBLSApkRegistry,
    IIndexRegistry,
    IStakeRegistry
} from "@eigenlayer-middleware/src/SlashingRegistryCoordinator.sol";
import {
    ISlashingRegistryCoordinator
} from "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {ISocketRegistry, SocketRegistry} from "@eigenlayer-middleware/src/SocketRegistry.sol";
import {IAllocationManager} from "@eigenlayer/contracts/interfaces/IAllocationManager.sol";

// EigenLayer multichain imports
import {
    OperatorTableUpdater,
    IOperatorTableUpdater
} from "@eigenlayer/contracts/multichain/OperatorTableUpdater.sol";
import {
    BN254CertificateVerifier,
    IBN254CertificateVerifier
} from "@eigenlayer/contracts/multichain/BN254CertificateVerifier.sol";
import {
    ECDSACertificateVerifier,
    IECDSACertificateVerifier
} from "@eigenlayer/contracts/multichain/ECDSACertificateVerifier.sol";

// Newton source chain imports
import {NewtonCrossChainRegistry} from "../../src/middlewares/NewtonCrossChainRegistry.sol";
import {BN254TableCalculator} from "../../src/middlewares/BN254TableCalculator.sol";

// Newton destination chain imports
import {NewtonProverDestTaskManager} from "../../src/NewtonProverDestTaskManager.sol";
import {IdentityRegistry} from "../../src/core/IdentityRegistry.sol";
import {ChallengeVerifier} from "../../src/middlewares/ChallengeVerifier.sol";
import {RegoVerifier} from "../../src/middlewares/RegoVerifier.sol";
import {AttestationValidator} from "../../src/middlewares/AttestationValidator.sol";
import {OperatorRegistry} from "../../src/middlewares/OperatorRegistry.sol";
import {
    DestinationTaskResponseHandler
} from "../../src/middlewares/DestinationTaskResponseHandler.sol";
import {ICertificateVerifier} from "../../src/interfaces/ICertificateVerifier.sol";
import {ECDSAOperatorTableUpdater} from "../../src/middlewares/ECDSAOperatorTableUpdater.sol";

// Newton libraries
import {ChainLib} from "../../src/libraries/ChainLib.sol";
import {PROTOCOL_VERSION} from "../../src/libraries/ProtocolVersion.sol";

/**
 * @title NewtonCrossChainDeploymentLib
 * @notice Unified deployment library for Newton's cross-chain infrastructure
 * @dev Handles both source chain (Ethereum) and destination chain (L2s) deployments:
 *
 *      **Source Chain (Ethereum mainnet/Sepolia):**
 *      - Deploys NewtonCrossChainRegistry and BN254TableCalculator
 *      - Used for pushing operator state to non-EigenLayer L2 destinations
 *      - EigenLayer-supported destinations (Base) use EL's CrossChainRegistry
 *
 *      **Destination Chain (L2s):**
 *      - Deploys OperatorTableUpdater and certificate verifiers
 *      - Deploys Newton AVS contracts (TaskManager, ChallengeVerifier, etc.)
 *      - On EL-supported destinations, reuses existing EL multichain contracts
 *      - On non-EL destinations, deploys full multichain infrastructure
 */
library NewtonCrossChainDeploymentLib {
    using stdJson for *;
    using Strings for *;
    using UpgradeableProxyLib for address;

    // =============================================================
    //                           CONSTANTS
    // =============================================================

    /// @notice Forge VM cheatcode access
    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @notice JSON output path pattern for deployments
    // solhint-disable-next-line gas-small-strings
    string internal constant DEPLOYMENTS_PATH = "script/deployments/newton-cross-chain/";

    // =============================================================
    //                           STRUCTS
    // =============================================================

    /// @notice Cross-chain configuration for source chains deploying Newton's cross-chain infrastructure
    /// @dev These fields are optional in newton_prover_config.*.json.
    ///      Their presence indicates the chain is a source chain for cross-chain transport.
    struct CrossChainConfig {
        /// @notice Destination chain IDs to whitelist for cross-chain transport
        uint256[] destinationChainIds;
        /// @notice Maximum staleness period for operator table updates (in seconds)
        uint32 maxStalenessPeriod;
        /// @notice Operator set ID for cross-chain transport
        uint32 operatorSetId;
        /// @notice Whether cross-chain config exists for this chain
        bool exists;
    }

    /// @notice Source chain deployment data (Ethereum mainnet/Sepolia)
    /// @dev Contains NewtonCrossChainRegistry and BN254TableCalculator for pushing
    ///      operator state to non-EigenLayer L2 destinations
    struct SourceDeploymentData {
        /// @notice NewtonCrossChainRegistry proxy address
        address crossChainRegistry;
        /// @notice NewtonCrossChainRegistry implementation address
        address crossChainRegistryImpl;
        /// @notice BN254TableCalculator proxy address
        address operatorTableCalculator;
        /// @notice BN254TableCalculator implementation address
        address operatorTableCalculatorImpl;
        /// @notice Chain ID where contracts are deployed
        uint256 chainId;
    }

    /// @notice Destination chain deployment data (L2s: Base, Arbitrum, Optimism, Polygon)
    /// @dev Contains multichain infrastructure for receiving operator state from source chain
    struct DestinationDeploymentData {
        // Proxy admin and pauser
        address proxyAdmin;
        address pauserRegistry;
        // EigenLayer multichain contracts (may be reused from existing EL deployment)
        address operatorTableUpdater;
        address operatorTableUpdaterImpl;
        address bn254CertificateVerifier;
        address bn254CertificateVerifierImpl;
        address ecdsaCertificateVerifier;
        address ecdsaCertificateVerifierImpl;
        // Newton AVS contracts
        address newtonProverTaskManager;
        address newtonProverTaskManagerImpl;
        address challengeVerifier;
        address challengeVerifierImpl;
        address regoVerifier;
        address regoVerifierImpl;
        address attestationValidator;
        address attestationValidatorImpl;
        address socketRegistry;
        address socketRegistryImpl;
        address operatorRegistry;
        address operatorRegistryImpl;
        address identityRegistry;
        // Source chain reference
        uint256 sourceChainId;
        address sourceChainAvsAddress;
    }

    // =============================================================
    //                           ERRORS
    // =============================================================

    /// @notice Thrown when deployment is attempted on a non-source chain (must be Ethereum)
    error NotSourceChain();

    /// @notice Thrown when owner address is zero
    error InvalidOwner();

    /// @notice Thrown when pauser registry address is zero
    error InvalidPauserRegistry();

    /// @notice Thrown when proxy admin address is zero
    error InvalidProxyAdmin();

    /// @notice Thrown when deployment config file does not exist
    error DeploymentConfigDoesNotExist();

    /// @notice Thrown when EigenLayer-supported destination has no existing deployment
    /// @dev EigenLayer-supported destinations (Base/Base Sepolia) require pre-deployed
    ///      multichain contracts from EigenLayer infrastructure. This error indicates
    ///      the required deployment JSON was not found.
    error EigenLayerDeploymentNotFound(uint256 chainId, string deploymentEnv);

    // =============================================================
    //                  CONFIG READING FUNCTIONS
    // =============================================================

    /// @notice Reads cross-chain configuration from newton_prover_config.*.json
    /// @param chainId Chain ID to read configuration for
    /// @param env Deployment environment (e.g., "stagef", "prod")
    /// @return data CrossChainConfig with exists=true if crossChain fields are present
    /// @dev The presence of crossChain fields indicates this chain is a source chain
    ///      for Newton's cross-chain transport infrastructure
    function readCrossChainConfigJson(
        uint256 chainId,
        string memory env
    ) internal returns (CrossChainConfig memory data) {
        string memory fileName = string.concat("newton_prover_config.", env, ".json");
        require(VM.exists(fileName), DeploymentConfigDoesNotExist());
        string memory json = VM.readFile(fileName);
        string memory keyPrefix = string.concat(".", VM.toString(chainId), ".crossChain");

        // Check if crossChain section exists by trying to read a field
        // If the key doesn't exist, readUintOr returns the default value
        uint256 maxStaleness = json.readUintOr(string.concat(keyPrefix, ".maxStalenessPeriod"), 0);

        // If maxStalenessPeriod is 0 and no destination chain IDs, assume no cross-chain config
        uint256[] memory defaultChainIds = new uint256[](0);
        data.destinationChainIds =
            json.readUintArrayOr(string.concat(keyPrefix, ".destinationChainIds"), defaultChainIds);

        // Cross-chain config exists if either maxStalenessPeriod > 0 or destinationChainIds is non-empty
        data.exists = maxStaleness > 0 || data.destinationChainIds.length > 0;

        if (data.exists) {
            data.maxStalenessPeriod = uint32(maxStaleness);
            data.operatorSetId =
                uint32(json.readUintOr(string.concat(keyPrefix, ".operatorSetId"), 0));
        }

        return data;
    }

    // =============================================================
    //                  SOURCE CHAIN DEPLOYMENT FUNCTIONS
    // =============================================================

    /**
     * @notice Deploys Newton's cross-chain infrastructure on Ethereum (source chain)
     * @param pauserRegistry The pauser registry to use for contracts requiring Pausable
     * @param owner Owner address for the deployed contracts
     * @param proxyAdmin Proxy admin address for upgradeable contracts
     * @param initialPausedStatus Initial paused status for contracts
     * @return data Deployed contract addresses
     * @dev This deploys NewtonCrossChainRegistry and BN254TableCalculator on Ethereum
     *      to handle cross-chain transport to L2s that EigenLayer doesn't natively support.
     */
    function deploySourceChainContracts(
        IPauserRegistry pauserRegistry,
        address owner,
        address proxyAdmin,
        uint256 initialPausedStatus
    ) internal returns (SourceDeploymentData memory data) {
        // Validate we're on a source chain (Ethereum mainnet, Sepolia, or local)
        require(ChainLib.isSourceChain(), NotSourceChain());
        require(owner != address(0), InvalidOwner());
        require(proxyAdmin != address(0), InvalidProxyAdmin());
        require(address(pauserRegistry) != address(0), InvalidPauserRegistry());

        data.chainId = block.chainid;

        // Deploy BN254TableCalculator implementation
        data.operatorTableCalculatorImpl =
            address(new BN254TableCalculator(pauserRegistry, PROTOCOL_VERSION));

        // Deploy BN254TableCalculator proxy and initialize
        data.operatorTableCalculator = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        UpgradeableProxyLib.upgradeAndCall(
            data.operatorTableCalculator,
            data.operatorTableCalculatorImpl,
            abi.encodeCall(BN254TableCalculator.initialize, (owner, initialPausedStatus))
        );

        // Deploy NewtonCrossChainRegistry implementation
        data.crossChainRegistryImpl =
            address(new NewtonCrossChainRegistry(pauserRegistry, PROTOCOL_VERSION));

        // Deploy NewtonCrossChainRegistry proxy and initialize
        data.crossChainRegistry = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        UpgradeableProxyLib.upgradeAndCall(
            data.crossChainRegistry,
            data.crossChainRegistryImpl,
            abi.encodeCall(NewtonCrossChainRegistry.initialize, (owner, initialPausedStatus))
        );

        return data;
    }

    /**
     * @notice Configures the deployed source chain cross-chain infrastructure
     * @param data Source deployment data with contract addresses
     * @param destinationChainIds Destination chain IDs to whitelist
     * @dev Must be called after deploySourceChainContracts and requires owner to be msg.sender
     */
    function configureSourceChainContracts(
        SourceDeploymentData memory data,
        uint256[] memory destinationChainIds
    ) internal {
        NewtonCrossChainRegistry registry = NewtonCrossChainRegistry(data.crossChainRegistry);

        // Whitelist destination chain IDs if provided
        if (destinationChainIds.length > 0) {
            registry.addChainIDsToWhitelist(destinationChainIds);
        }
    }

    /**
     * @notice Registers an operator set for cross-chain transport
     * @param data Source deployment data with contract addresses
     * @param operatorSet The operator set to register
     * @param owner Owner address for the operator set configuration
     * @param maxStalenessPeriod Maximum staleness period for operator table updates
     */
    function registerOperatorSet(
        SourceDeploymentData memory data,
        OperatorSet memory operatorSet,
        address owner,
        uint32 maxStalenessPeriod
    ) internal {
        NewtonCrossChainRegistry registry = NewtonCrossChainRegistry(data.crossChainRegistry);
        IOperatorTableCalculator calculator = IOperatorTableCalculator(data.operatorTableCalculator);

        ICrossChainRegistryTypes.OperatorSetConfig memory operatorSetConfig =
            ICrossChainRegistryTypes.OperatorSetConfig({
                owner: owner, maxStalenessPeriod: maxStalenessPeriod
            });

        registry.createGenerationReservation(operatorSet, calculator, operatorSetConfig);
    }

    // =============================================================
    //                DESTINATION CHAIN DEPLOYMENT FUNCTIONS
    // =============================================================

    /**
     * @notice Deploys Newton AVS contracts on a destination chain (L2)
     * @param proxyAdmin Proxy admin address for upgradeable contracts
     * @param sourceChainId Chain ID of the source chain (auto-derived if 0)
     * @param sourceChainAvsAddress Address of Newton AVS ServiceManager on source chain
     * @param admin Admin address for deployed contracts
     * @param config Newton Prover configuration containing aggregator and window settings
     * @return result DestinationDeploymentData struct containing all deployed contract addresses
     * @dev If an existing deployment exists (existingDeployment.operatorTableUpdater != 0),
     *      the multichain infrastructure contracts are reused. Otherwise, new contracts are deployed.
     *      OperatorTableUpdater type is selected based on chain:
     *      - ECDSAOperatorTableUpdater for local and non-EL destinations
     *      - OperatorTableUpdater for EL-supported destinations (Base)
     */
    function deployDestinationContracts(
        address proxyAdmin,
        uint256 sourceChainId,
        address sourceChainAvsAddress,
        address admin,
        DeploymentLib.NewtonProverSetupConfig memory config,
        string memory deploymentEnv
    ) internal returns (DestinationDeploymentData memory result) {
        result.proxyAdmin = proxyAdmin;
        result.sourceChainId = sourceChainId != 0 ? sourceChainId : ChainLib.getSourceChainId();
        result.sourceChainAvsAddress = sourceChainAvsAddress;

        // Chain-aware deployment logic for EigenLayer multichain contracts
        // - EigenLayer-supported destinations (Base/Base Sepolia): Must reuse existing deployment
        // - Non-EigenLayer destinations (including local anvil): Always deploy fresh
        if (ChainLib.isEigenLayerSupportedDestination(block.chainid)) {
            // EigenLayer-supported destination: require existing deployment
            DestinationDeploymentData memory existingDeployment =
                tryReadDestinationDeploymentJson(block.chainid);

            if (existingDeployment.operatorTableUpdater != address(0)) {
                // Reuse existing EigenLayer multichain contracts
                result.pauserRegistry = existingDeployment.pauserRegistry;
                result.operatorTableUpdater = existingDeployment.operatorTableUpdater;
                result.bn254CertificateVerifier = existingDeployment.bn254CertificateVerifier;
                result.ecdsaCertificateVerifier = existingDeployment.ecdsaCertificateVerifier;
                result.operatorTableUpdaterImpl = existingDeployment.operatorTableUpdaterImpl;
                result.bn254CertificateVerifierImpl =
                existingDeployment.bn254CertificateVerifierImpl;
                result.ecdsaCertificateVerifierImpl =
                existingDeployment.ecdsaCertificateVerifierImpl;
            } else {
                // EigenLayer-supported destination requires pre-deployed contracts
                revert EigenLayerDeploymentNotFound(block.chainid, deploymentEnv);
            }
        } else {
            // Non-EigenLayer destination (including local anvil): always deploy fresh
            // Deploy pauser registry
            result.pauserRegistry = address(
                new PauserRegistry(
                    new address[](0), // empty array for pausers
                    proxyAdmin // proxyAdmin as the unpauser
                )
            );

            // Deploy empty proxies for EigenLayer multichain contracts
            result.operatorTableUpdater = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
            result.bn254CertificateVerifier = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
            result.ecdsaCertificateVerifier = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);

            // Deploy EigenLayer multichain implementations
            result.bn254CertificateVerifierImpl = address(
                new BN254CertificateVerifier(
                    IOperatorTableUpdater(result.operatorTableUpdater), PROTOCOL_VERSION
                )
            );

            result.ecdsaCertificateVerifierImpl = address(
                new ECDSACertificateVerifier(
                    IOperatorTableUpdater(result.operatorTableUpdater), PROTOCOL_VERSION
                )
            );

            // Select OperatorTableUpdater type based on chain
            // EigenLayer's Generator only operates on Base/Base Sepolia
            // For local and non-EL destinations, use ECDSAOperatorTableUpdater
            if (ChainLib.requiresECDSAOperatorTableUpdater()) {
                result.operatorTableUpdaterImpl = address(
                    new ECDSAOperatorTableUpdater(
                        IBN254CertificateVerifier(result.bn254CertificateVerifier),
                        IECDSACertificateVerifier(result.ecdsaCertificateVerifier),
                        IPauserRegistry(result.pauserRegistry),
                        PROTOCOL_VERSION
                    )
                );
            } else {
                result.operatorTableUpdaterImpl = address(
                    new OperatorTableUpdater(
                        IBN254CertificateVerifier(result.bn254CertificateVerifier),
                        IECDSACertificateVerifier(result.ecdsaCertificateVerifier),
                        IPauserRegistry(result.pauserRegistry),
                        PROTOCOL_VERSION
                    )
                );
            }

            // Initialize OperatorTableUpdater
            bytes memory operatorTableUpdaterInitCall = abi.encodeWithSignature(
                "initialize(address,uint256)",
                admin,
                0 // initialPausedStatus
            );
            UpgradeableProxyLib.upgradeAndCall(
                result.operatorTableUpdater,
                result.operatorTableUpdaterImpl,
                operatorTableUpdaterInitCall
            );

            UpgradeableProxyLib.upgrade(
                result.bn254CertificateVerifier, result.bn254CertificateVerifierImpl
            );
            UpgradeableProxyLib.upgrade(
                result.ecdsaCertificateVerifier, result.ecdsaCertificateVerifierImpl
            );
        }

        // Deploy empty proxies for Newton AVS contracts
        result.newtonProverTaskManager = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.challengeVerifier = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.regoVerifier = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.attestationValidator = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.operatorRegistry = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.socketRegistry = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);

        // Deploy destination operator registry implementation
        result.operatorRegistryImpl = address(
            new OperatorRegistry(
                IStakeRegistry(address(0)), // address(0) for destination chains
                IBLSApkRegistry(address(0)), // address(0) for destination chains
                IIndexRegistry(address(0)), // address(0) for destination chains
                ISocketRegistry(result.socketRegistry),
                IAllocationManager(address(0)), // address(0) for destination chains
                IPauserRegistry(result.pauserRegistry),
                PROTOCOL_VERSION
            )
        );

        // Deploy destination socket registry implementation
        result.socketRegistryImpl =
            address(new SocketRegistry(ISlashingRegistryCoordinator(result.operatorRegistry)));

        // Deploy Newton AVS implementations
        result.newtonProverTaskManagerImpl = address(
            new NewtonProverDestTaskManager(
                OperatorRegistry(result.operatorRegistry),
                IPauserRegistry(result.pauserRegistry),
                PROTOCOL_VERSION
            )
        );

        result.challengeVerifierImpl = address(
            new ChallengeVerifier(
                address(0), // serviceManager (address(0) for destination chains)
                result.newtonProverTaskManager,
                address(0), // registryCoordinator (address(0) for destination chains)
                address(0), // blsApkRegistry (address(0) for destination chains)
                address(0), // allocationManager (address(0) for destination chains)
                address(0), // instantSlasher (address(0) for destination chains)
                result.regoVerifier,
                result.attestationValidator,
                result.operatorRegistry
            )
        );

        result.regoVerifierImpl = address(new RegoVerifier());

        result.attestationValidatorImpl = address(
            new AttestationValidator(result.newtonProverTaskManager, result.operatorRegistry)
        );

        // Initialize Newton AVS proxies
        bytes memory operatorRegistryInitCall = abi.encodeWithSignature(
            "initialize(address,address,address,uint256,address)",
            admin,
            address(0),
            address(0),
            0,
            address(0)
        );
        UpgradeableProxyLib.upgradeAndCall(
            result.operatorRegistry, result.operatorRegistryImpl, operatorRegistryInitCall
        );
        UpgradeableProxyLib.upgrade(result.socketRegistry, result.socketRegistryImpl);

        // Deploy DestinationTaskResponseHandler for certificate verification
        address taskResponseHandler = address(
            new DestinationTaskResponseHandler(
                ICertificateVerifier(result.bn254CertificateVerifier), result.sourceChainAvsAddress
            )
        );

        bytes memory taskManagerInitCall = abi.encodeWithSignature(
            "initialize(address,address,address,address,address,address,address,address,uint32,uint32)",
            admin, // initialOwner
            config.aggregatorAddr, // aggregator (DEPRECATED)
            result.sourceChainAvsAddress, // serviceManager (source chain AVS)
            result.bn254CertificateVerifier, // certificateVerifier
            result.operatorRegistry,
            taskResponseHandler, // taskResponseHandler
            result.challengeVerifier,
            result.attestationValidator,
            config.taskResponseWindowBlock, // taskResponseWindowBlock
            config.epochBlocks // epochBlocks
        );
        UpgradeableProxyLib.upgradeAndCall(
            result.newtonProverTaskManager, result.newtonProverTaskManagerImpl, taskManagerInitCall
        );

        // Set taskCreationBufferWindow (not included in initialize, requires separate setter call)
        // Note: During broadcast, the deployer (who is the owner) is already msg.sender
        NewtonProverDestTaskManager(result.newtonProverTaskManager)
            .updateTaskCreationBufferWindow(config.taskCreationBufferWindow);

        bytes memory challengeVerifierInitCall = abi.encodeWithSignature(
            "initialize(bool,uint32,uint32,address)", false, uint32(100), uint32(30), admin
        );
        UpgradeableProxyLib.upgradeAndCall(
            result.challengeVerifier, result.challengeVerifierImpl, challengeVerifierInitCall
        );

        bytes memory regoVerifierInitCall = abi.encodeWithSignature(
            "initialize(address,bytes32,address)", address(0), bytes32(0), admin
        );
        UpgradeableProxyLib.upgradeAndCall(
            result.regoVerifier, result.regoVerifierImpl, regoVerifierInitCall
        );

        bytes memory attestationValidatorInitCall =
            abi.encodeWithSignature("initialize(address)", admin);
        UpgradeableProxyLib.upgradeAndCall(
            result.attestationValidator,
            result.attestationValidatorImpl,
            attestationValidatorInitCall
        );

        return result;
    }

    /**
     * @notice Initialize operator table for local test environment
     * @param data Destination deployment data containing operator table updater address
     * @param sourceChainAvsAddress AVS address on the source chain for operator set
     * @param admin Admin address for the operator set configuration
     * @dev Creates a test operator table with empty root for local development.
     *      Only callable on local anvil chains (31337, 31338).
     */
    function initializeTestOperatorTable(
        DestinationDeploymentData memory data,
        address sourceChainAvsAddress,
        address admin
    ) internal {
        require(ChainLib.isLocal(), "Only for local tests");

        OperatorSet memory operatorSet = OperatorSet({avs: sourceChainAvsAddress, id: 0});

        uint32 referenceTimestamp = uint32(block.timestamp);
        uint32 referenceBlockNumber = uint32(block.number);

        IOperatorTableCalculatorTypes.BN254OperatorSetInfo memory operatorSetInfo =
            IOperatorTableCalculatorTypes.BN254OperatorSetInfo({
                operatorInfoTreeRoot: bytes32(0),
                numOperators: 0,
                aggregatePubkey: BN254.G1Point(0, 0),
                totalWeights: new uint256[](1)
            });

        ICrossChainRegistryTypes.OperatorSetConfig memory operatorSetConfig =
            ICrossChainRegistryTypes.OperatorSetConfig({
                owner: admin,
                maxStalenessPeriod: 0 // don't check staleness
            });

        ECDSAOperatorTableUpdater.OperatorTableData memory tableData =
            ECDSAOperatorTableUpdater.OperatorTableData({
                operatorSet: operatorSet,
                curveType: IKeyRegistrarTypes.CurveType.BN254,
                operatorSetConfig: operatorSetConfig,
                operatorTableInfo: abi.encode(operatorSetInfo)
            });
        bytes memory operatorTableBytes = abi.encode(tableData);

        bytes32 operatorTableLeaf = ECDSAOperatorTableUpdater(data.operatorTableUpdater)
            .calculateOperatorTableLeaf(operatorTableBytes);

        bytes32 globalTableRoot = operatorTableLeaf;

        ECDSAOperatorTableUpdater(data.operatorTableUpdater)
            .confirmGlobalTableRoot(globalTableRoot, referenceTimestamp, referenceBlockNumber);

        ECDSAOperatorTableUpdater(data.operatorTableUpdater)
            .updateOperatorTable(
                referenceTimestamp, globalTableRoot, 0, new bytes(0), operatorTableBytes
            );
    }

    /**
     * @notice Upgrades Newton AVS contracts on a destination chain
     * @param deploymentData Existing deployment data with proxy addresses to upgrade
     * @param config Newton Prover configuration for task window settings
     * @param admin Admin address for newly deployed contracts
     * @return Updated DestinationDeploymentData with new implementation addresses
     */
    function upgradeDestinationContracts(
        DestinationDeploymentData memory deploymentData,
        DeploymentLib.NewtonProverSetupConfig memory config,
        address admin
    ) internal returns (DestinationDeploymentData memory) {
        DestinationDeploymentData memory result = deploymentData;

        address proxyAdmin =
            address(UpgradeableProxyLib.getProxyAdmin(result.newtonProverTaskManager));

        // Deploy or upgrade IdentityRegistry
        if (result.identityRegistry == address(0)) {
            result.identityRegistry = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
            address identityRegistryImpl = address(new IdentityRegistry());
            UpgradeableProxyLib.upgradeAndCall(
                result.identityRegistry,
                identityRegistryImpl,
                abi.encodeCall(IdentityRegistry.initialize, (admin))
            );
        } else {
            IdentityRegistry identityRegistryImpl = new IdentityRegistry();
            UpgradeableProxyLib.upgrade(result.identityRegistry, address(identityRegistryImpl));
        }

        // Upgrade ChallengeVerifier
        ChallengeVerifier challengeVerifierImpl = new ChallengeVerifier(
            address(0),
            result.newtonProverTaskManager,
            address(0),
            address(0),
            address(0),
            address(0),
            result.regoVerifier,
            result.attestationValidator,
            result.operatorRegistry
        );
        result.challengeVerifierImpl = address(challengeVerifierImpl);
        UpgradeableProxyLib.upgrade(result.challengeVerifier, address(challengeVerifierImpl));

        // Upgrade RegoVerifier
        RegoVerifier regoVerifierImpl = new RegoVerifier();
        result.regoVerifierImpl = address(regoVerifierImpl);
        UpgradeableProxyLib.upgrade(result.regoVerifier, address(regoVerifierImpl));

        // Upgrade AttestationValidator
        AttestationValidator attestationValidatorImpl =
            new AttestationValidator(result.newtonProverTaskManager, result.operatorRegistry);
        result.attestationValidatorImpl = address(attestationValidatorImpl);
        UpgradeableProxyLib.upgrade(result.attestationValidator, address(attestationValidatorImpl));

        // Upgrade NewtonProverDestTaskManager
        NewtonProverDestTaskManager newtonProverDestTaskManagerImpl = new NewtonProverDestTaskManager(
            OperatorRegistry(result.operatorRegistry),
            IPauserRegistry(result.pauserRegistry),
            PROTOCOL_VERSION
        );
        result.newtonProverTaskManagerImpl = address(newtonProverDestTaskManagerImpl);
        UpgradeableProxyLib.upgrade(
            result.newtonProverTaskManager, result.newtonProverTaskManagerImpl
        );

        // Deploy new DestinationTaskResponseHandler and update TaskManager
        // DestinationTaskResponseHandler is standalone (not upgradeable), so we deploy a new
        // instance when its implementation changes and update the TaskManager to use it
        address newTaskResponseHandler = address(
            new DestinationTaskResponseHandler(
                ICertificateVerifier(result.bn254CertificateVerifier), result.sourceChainAvsAddress
            )
        );
        NewtonProverDestTaskManager(result.newtonProverTaskManager)
            .updateTaskResponseHandler(newTaskResponseHandler);

        // Update TaskManager configuration
        NewtonProverDestTaskManager(result.newtonProverTaskManager)
            .updateTaskResponseWindowBlock(config.taskResponseWindowBlock);
        NewtonProverDestTaskManager(result.newtonProverTaskManager)
            .updateEpochBlocks(config.epochBlocks);

        return result;
    }

    // =============================================================
    //                        JSON UTILITIES
    // =============================================================

    // -------------------- Source Chain JSON --------------------

    /**
     * @notice Writes source chain deployment data to a JSON file
     * @param data Source deployment data to write
     * @dev Writes to script/deployments/newton-cross-chain/{chainId}-{env}.json
     *      Uses DEPLOYMENT_ENV environment variable (defaults to "stagef")
     */
    function writeSourceDeploymentJson(
        SourceDeploymentData memory data
    ) internal {
        string memory env = VM.envOr("DEPLOYMENT_ENV", string("stagef"));

        string memory addresses = "addresses";
        addresses.serialize("crossChainRegistry", data.crossChainRegistry);
        addresses.serialize("crossChainRegistryImpl", data.crossChainRegistryImpl);
        addresses.serialize("operatorTableCalculator", data.operatorTableCalculator);
        string memory addressesJson =
            addresses.serialize("operatorTableCalculatorImpl", data.operatorTableCalculatorImpl);

        string memory root = "root";
        root.serialize("chainId", data.chainId);
        root.serialize("deploymentType", string("source"));
        string memory finalJson = root.serialize("addresses", addressesJson);

        string memory outputPath =
            string.concat(DEPLOYMENTS_PATH, data.chainId.toString(), "-", env, ".json");

        VM.writeJson(finalJson, outputPath);
        // solhint-disable-next-line no-console
        console2.log("Source deployment written to:", outputPath);
    }

    /**
     * @notice Reads source chain deployment data from a JSON file
     * @param chainId Chain ID for the input file name
     * @return data Source deployment data read from file
     */
    function readSourceDeploymentJson(
        uint256 chainId
    ) internal view returns (SourceDeploymentData memory data) {
        string memory env = VM.envOr("DEPLOYMENT_ENV", string("stagef"));

        string memory inputPath =
            string.concat(DEPLOYMENTS_PATH, chainId.toString(), "-", env, ".json");

        string memory json = VM.readFile(inputPath);

        data.crossChainRegistry = json.readAddress(".addresses.crossChainRegistry");
        data.crossChainRegistryImpl = json.readAddress(".addresses.crossChainRegistryImpl");
        data.operatorTableCalculator = json.readAddress(".addresses.operatorTableCalculator");
        data.operatorTableCalculatorImpl =
            json.readAddress(".addresses.operatorTableCalculatorImpl");
        data.chainId = json.readUint(".chainId");

        return data;
    }

    // -------------------- Destination Chain JSON --------------------

    /**
     * @notice Writes destination chain deployment data to a JSON file
     * @param data Destination deployment data to write
     * @dev Writes to script/deployments/newton-cross-chain/{chainId}-{env}.json
     */
    function writeDestinationDeploymentJson(
        DestinationDeploymentData memory data
    ) internal {
        string memory env = VM.envOr("DEPLOYMENT_ENV", string("stagef"));
        string memory deploymentData = _generateDestinationDeploymentJson(data);

        string memory outputPath =
            string.concat(DEPLOYMENTS_PATH, block.chainid.toString(), "-", env, ".json");

        if (!VM.exists(DEPLOYMENTS_PATH)) {
            VM.createDir(DEPLOYMENTS_PATH, true);
        }

        VM.writeFile(outputPath, deploymentData);

        // solhint-disable-next-line no-console, gas-small-strings
        console2.log("Destination deployment written to:", outputPath);
    }

    /**
     * @notice Reads destination chain deployment data from a JSON file
     * @param chainId Chain ID for the input file name
     * @return data Destination deployment data read from file
     */
    function readDestinationDeploymentJson(
        uint256 chainId
    ) internal returns (DestinationDeploymentData memory data) {
        string memory env = VM.envOr("DEPLOYMENT_ENV", string("stagef"));

        string memory inputPath =
            string.concat(DEPLOYMENTS_PATH, chainId.toString(), "-", env, ".json");

        require(VM.exists(inputPath), "Deployment file does not exist");

        string memory json = VM.readFile(inputPath);

        data.proxyAdmin = json.readAddressOr(".addresses.proxyAdmin", address(0));
        data.pauserRegistry = json.readAddressOr(".addresses.pauserRegistry", address(0));
        data.operatorTableUpdater =
            json.readAddressOr(".addresses.operatorTableUpdater", address(0));
        data.operatorTableUpdaterImpl =
            json.readAddressOr(".addresses.operatorTableUpdaterImpl", address(0));
        data.bn254CertificateVerifier =
            json.readAddressOr(".addresses.bn254CertificateVerifier", address(0));
        data.bn254CertificateVerifierImpl =
            json.readAddressOr(".addresses.bn254CertificateVerifierImpl", address(0));
        data.ecdsaCertificateVerifier =
            json.readAddressOr(".addresses.ecdsaCertificateVerifier", address(0));
        data.ecdsaCertificateVerifierImpl =
            json.readAddressOr(".addresses.ecdsaCertificateVerifierImpl", address(0));
        data.newtonProverTaskManager =
            json.readAddressOr(".addresses.newtonProverTaskManager", address(0));
        data.newtonProverTaskManagerImpl =
            json.readAddressOr(".addresses.newtonProverTaskManagerImpl", address(0));
        data.challengeVerifier = json.readAddressOr(".addresses.challengeVerifier", address(0));
        data.challengeVerifierImpl =
            json.readAddressOr(".addresses.challengeVerifierImpl", address(0));
        data.regoVerifier = json.readAddressOr(".addresses.regoVerifier", address(0));
        data.regoVerifierImpl = json.readAddressOr(".addresses.regoVerifierImpl", address(0));
        data.attestationValidator =
            json.readAddressOr(".addresses.attestationValidator", address(0));
        data.attestationValidatorImpl =
            json.readAddressOr(".addresses.attestationValidatorImpl", address(0));
        data.socketRegistry = json.readAddressOr(".addresses.socketRegistry", address(0));
        data.socketRegistryImpl = json.readAddressOr(".addresses.socketRegistryImpl", address(0));
        data.operatorRegistry = json.readAddressOr(".addresses.operatorRegistry", address(0));
        data.operatorRegistryImpl =
            json.readAddressOr(".addresses.operatorRegistryImpl", address(0));
        data.sourceChainId = json.readUintOr(".sourceChainId", 0);

        return data;
    }

    /**
     * @notice Tries to read destination chain deployment data from a JSON file
     * @dev Returns empty struct if file doesn't exist (for fresh deployments)
     * @param chainId Chain ID for the input file name
     * @return data Destination deployment data (empty if file doesn't exist)
     */
    function tryReadDestinationDeploymentJson(
        uint256 chainId
    ) internal returns (DestinationDeploymentData memory data) {
        string memory env = VM.envOr("DEPLOYMENT_ENV", string("stagef"));

        string memory inputPath =
            string.concat(DEPLOYMENTS_PATH, chainId.toString(), "-", env, ".json");

        // Return empty struct if deployment file doesn't exist (fresh deployment)
        if (!VM.exists(inputPath)) {
            return data;
        }

        // File exists, delegate to the strict reader
        return readDestinationDeploymentJson(chainId);
    }

    function _generateDestinationDeploymentJson(
        DestinationDeploymentData memory data
    ) private view returns (string memory) {
        return string.concat(
            '{"lastUpdate":{"timestamp":"',
            VM.toString(block.timestamp),
            '","block_number":"',
            VM.toString(block.number),
            '"},"type":"destination","sourceChainId":"',
            VM.toString(data.sourceChainId),
            '","addresses":',
            _generateDestinationContractsJson(data),
            "}"
        );
    }

    function _generateDestinationContractsJson(
        DestinationDeploymentData memory data
    ) private pure returns (string memory) {
        return string.concat(
            '{"proxyAdmin":"',
            data.proxyAdmin.toHexString(),
            '","pauserRegistry":"',
            data.pauserRegistry.toHexString(),
            '","operatorTableUpdater":"',
            data.operatorTableUpdater.toHexString(),
            '","operatorTableUpdaterImpl":"',
            data.operatorTableUpdaterImpl.toHexString(),
            '","bn254CertificateVerifier":"',
            data.bn254CertificateVerifier.toHexString(),
            '","bn254CertificateVerifierImpl":"',
            data.bn254CertificateVerifierImpl.toHexString(),
            '","ecdsaCertificateVerifier":"',
            data.ecdsaCertificateVerifier.toHexString(),
            '","ecdsaCertificateVerifierImpl":"',
            data.ecdsaCertificateVerifierImpl.toHexString(),
            _generateDestinationContractsJson2(data)
        );
    }

    function _generateDestinationContractsJson2(
        DestinationDeploymentData memory data
    ) private pure returns (string memory) {
        return string.concat(
            '","newtonProverTaskManager":"',
            data.newtonProverTaskManager.toHexString(),
            '","newtonProverTaskManagerImpl":"',
            data.newtonProverTaskManagerImpl.toHexString(),
            '","challengeVerifier":"',
            data.challengeVerifier.toHexString(),
            '","challengeVerifierImpl":"',
            data.challengeVerifierImpl.toHexString(),
            '","regoVerifier":"',
            data.regoVerifier.toHexString(),
            '","regoVerifierImpl":"',
            data.regoVerifierImpl.toHexString(),
            '","attestationValidator":"',
            data.attestationValidator.toHexString(),
            '","attestationValidatorImpl":"',
            data.attestationValidatorImpl.toHexString(),
            '","socketRegistry":"',
            data.socketRegistry.toHexString(),
            '","socketRegistryImpl":"',
            data.socketRegistryImpl.toHexString(),
            '","operatorRegistry":"',
            data.operatorRegistry.toHexString(),
            '","operatorRegistryImpl":"',
            data.operatorRegistryImpl.toHexString(),
            '"}'
        );
    }

    // -------------------- Common Utilities --------------------

    /**
     * @notice Checks if deployment data exists for a chain
     * @param chainId Chain ID to check
     * @return exists True if deployment data exists
     */
    function deploymentExists(
        uint256 chainId
    ) internal view returns (bool exists) {
        string memory env = VM.envOr("DEPLOYMENT_ENV", string("stagef"));

        string memory inputPath =
            string.concat(DEPLOYMENTS_PATH, chainId.toString(), "-", env, ".json");

        try VM.readFile(inputPath) returns (string memory) {
            return true;
        } catch {
            return false;
        }
    }

    // =============================================================
    //                       HELPER FUNCTIONS
    // =============================================================

    /**
     * @notice Determines if the current chain requires Newton's cross-chain registry
     * @return required True if Newton's registry should be deployed
     */
    function requiresNewtonRegistry() internal view returns (bool) {
        return ChainLib.requiresNewtonCrossChainRegistry();
    }

    /**
     * @notice Gets the deployed cross-chain registry address for a chain
     * @param chainId Chain ID to query
     * @return registry Address of the cross-chain registry (Newton or EigenLayer)
     * @dev Returns zero address if no deployment exists. Not marked view as it uses VM.readFile.
     */
    function getCrossChainRegistry(
        uint256 chainId
    ) internal returns (address registry) {
        // All cross-chain contracts are stored in newton-cross-chain/
        if (deploymentExists(chainId)) {
            SourceDeploymentData memory data = readSourceDeploymentJson(chainId);
            return data.crossChainRegistry;
        }
        return address(0);
    }

    /**
     * @notice Gets the operator table calculator address for a chain
     * @param chainId Chain ID to query
     * @return calculator Address of the operator table calculator
     * @dev Returns zero address if no deployment exists. Not marked view as it uses VM.readFile.
     */
    function getOperatorTableCalculator(
        uint256 chainId
    ) internal returns (address calculator) {
        if (deploymentExists(chainId)) {
            SourceDeploymentData memory data = readSourceDeploymentJson(chainId);
            return data.operatorTableCalculator;
        }
        return address(0);
    }

    // =============================================================
    //                     VALIDATION FUNCTIONS
    // =============================================================

    /**
     * @notice Validates that source deployment data is complete and valid
     * @param data Source deployment data to validate
     * @return valid True if all addresses are non-zero
     */
    function validateSourceDeployment(
        SourceDeploymentData memory data
    ) internal pure returns (bool valid) {
        return data.crossChainRegistry != address(0) && data.crossChainRegistryImpl != address(0)
            && data.operatorTableCalculator != address(0)
            && data.operatorTableCalculatorImpl != address(0) && data.chainId != 0;
    }
}
