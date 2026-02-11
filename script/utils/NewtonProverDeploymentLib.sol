// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IAVSDirectory} from "@eigenlayer/contracts/interfaces/IAVSDirectory.sol";
import {ISocketRegistry, SocketRegistry} from "@eigenlayer-middleware/src/SocketRegistry.sol";
import {
    ISlashingRegistryCoordinator
} from "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {
    SlashingRegistryCoordinator
} from "@eigenlayer-middleware/src/SlashingRegistryCoordinator.sol";
import {OperatorRegistry} from "../../src/middlewares/OperatorRegistry.sol";
import {SourceTaskResponseHandler} from "../../src/middlewares/SourceTaskResponseHandler.sol";
import {ChallengeVerifier} from "../../src/middlewares/ChallengeVerifier.sol";
import {RegoVerifier} from "../../src/middlewares/RegoVerifier.sol";
import {AttestationValidator} from "../../src/middlewares/AttestationValidator.sol";
import {IdentityRegistry} from "../../src/core/IdentityRegistry.sol";
import {IPermissionController} from "@eigenlayer/contracts/interfaces/IPermissionController.sol";
import {
    PROTOCOL_VERSION,
    MIN_COMPATIBLE_POLICY_VERSION,
    MIN_COMPATIBLE_POLICY_DATA_VERSION
} from "../../src/libraries/ProtocolVersion.sol";
import {NewtonProverServiceManager} from "../../src/NewtonProverServiceManager.sol";
import {INewtonProverTaskManager} from "../../src/interfaces/INewtonProverTaskManager.sol";
import {NewtonProverTaskManager} from "../../src/NewtonProverTaskManager.sol";
import {IDelegationManager} from "@eigenlayer/contracts/interfaces/IDelegationManager.sol";
import {UpgradeableProxyLib} from "./UpgradeableProxyLib.sol";
import {DeploymentLib} from "./DeploymentLib.sol";
import {CoreDeploymentLib} from "./CoreDeploymentLib.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {BLSApkRegistry} from "@eigenlayer-middleware/src/BLSApkRegistry.sol";
import {IndexRegistry} from "@eigenlayer-middleware/src/IndexRegistry.sol";
import {InstantSlasher} from "@eigenlayer-middleware/src/slashers/InstantSlasher.sol";
import {StakeRegistry} from "@eigenlayer-middleware/src/StakeRegistry.sol";
import {IAllocationManager} from "@eigenlayer/contracts/interfaces/IAllocationManager.sol";
import {IStrategyManager} from "@eigenlayer/contracts/interfaces/IStrategyManager.sol";
import {IKeyRegistrar} from "@eigenlayer/contracts/interfaces/IKeyRegistrar.sol";
import {
    BN254TableCalculator
} from "@eigenlayer-middleware/src/middlewareV2/tableCalculator/BN254TableCalculator.sol";
import {CoreDeploymentLib} from "./CoreDeploymentLib.sol";
import {
    IBLSApkRegistry,
    IIndexRegistry,
    IStakeRegistry
} from "@eigenlayer-middleware/src/SlashingRegistryCoordinator.sol";
import {
    PauserRegistry,
    IPauserRegistry
} from "@eigenlayer/contracts/permissions/PauserRegistry.sol";
import {OperatorStateRetriever} from "@eigenlayer-middleware/src/OperatorStateRetriever.sol";

library NewtonProverDeploymentLib {
    using stdJson for *;
    using Strings for *;
    using UpgradeableProxyLib for address;

    error BlsApkRegistryNotDeployed();
    error StakeRegistryNotDeployed();
    error DelegationManagerNotDeployed();
    error ContractNotDeployed(string contractName, address contractAddress);
    error ValidationFailed(string reason);

    string internal constant MIDDLEWARE_VERSION = "v2.0.0";
    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function deployContracts(
        address proxyAdmin,
        CoreDeploymentLib.DeploymentData memory core,
        address strategy,
        DeploymentLib.NewtonProverSetupConfig memory config,
        address admin
    ) internal returns (DeploymentLib.DeploymentData memory) {
        address avsdirectory = core.avsDirectory;

        DeploymentLib.DeploymentData memory result;

        // First, deploy upgradeable proxy contracts that will point to the implementations.
        result.newtonProverServiceManager = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.newtonProverTaskManager = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);

        result.stakeRegistry = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.operatorRegistry = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.blsApkRegistry = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.indexRegistry = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.socketRegistry = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.slasher = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.challengeVerifier = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.regoVerifier = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.attestationValidator = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        OperatorStateRetriever operatorStateRetriever = new OperatorStateRetriever();
        result.strategy = strategy;
        result.operatorStateRetriever = address(operatorStateRetriever);

        // Deploy Eigenlayer Middleware contracts
        address stakeRegistryImpl = address(
            new StakeRegistry(
                ISlashingRegistryCoordinator(result.operatorRegistry),
                IDelegationManager(core.delegationManager),
                IAVSDirectory(core.avsDirectory),
                IAllocationManager(core.allocationManager)
            )
        );
        result.stakeRegistryImpl = stakeRegistryImpl;

        address blsApkRegistryImpl =
            address(new BLSApkRegistry(ISlashingRegistryCoordinator(result.operatorRegistry)));
        result.blsApkRegistryImpl = blsApkRegistryImpl;

        address indexRegistryimpl =
            address(new IndexRegistry(ISlashingRegistryCoordinator(result.operatorRegistry)));
        result.indexRegistryImpl = indexRegistryimpl;

        address instantSlasherImpl = address(
            new InstantSlasher(
                IAllocationManager(core.allocationManager),
                IStrategyManager(core.strategyManager),
                ISlashingRegistryCoordinator(result.operatorRegistry),
                result.challengeVerifier
            )
        );
        result.instantSlasherImpl = instantSlasherImpl;

        address operatorRegistryImpl = address(
            new OperatorRegistry(
                IStakeRegistry(result.stakeRegistry),
                IBLSApkRegistry(result.blsApkRegistry),
                IIndexRegistry(result.indexRegistry),
                ISocketRegistry(result.socketRegistry),
                IAllocationManager(core.allocationManager),
                IPauserRegistry(core.pauserRegistry),
                MIDDLEWARE_VERSION
            )
        );
        result.operatorRegistryImpl = operatorRegistryImpl;

        bytes memory upgradeCall = abi.encodeCall(
            SlashingRegistryCoordinator.initialize,
            // _initialOwner, _churnApprover, _ejector, _initialPausedStatus, _avs
            (admin, admin, admin, 0, result.newtonProverServiceManager)
        );

        address[] memory pausers = new address[](2);
        pausers[0] = admin;
        pausers[1] = admin;
        PauserRegistry pausercontract = new PauserRegistry(pausers, admin);
        result.pauserRegistry = address(pausercontract);

        UpgradeableProxyLib.upgrade(result.slasher, instantSlasherImpl);
        UpgradeableProxyLib.upgradeAndCall(
            result.operatorRegistry, operatorRegistryImpl, upgradeCall
        );

        UpgradeableProxyLib.upgrade(result.stakeRegistry, stakeRegistryImpl);
        UpgradeableProxyLib.upgrade(result.blsApkRegistry, blsApkRegistryImpl);
        UpgradeableProxyLib.upgrade(result.indexRegistry, indexRegistryimpl);

        address socketRegistryImpl =
            address(new SocketRegistry(ISlashingRegistryCoordinator(result.operatorRegistry)));
        result.socketRegistryImpl = socketRegistryImpl;
        UpgradeableProxyLib.upgrade(result.socketRegistry, socketRegistryImpl);

        // Deploy NewtonProver avs contracts - TaskManager first since other contracts depend on it
        // Now the operatorRegistry proxy is fully initialized, so we can create TaskManager
        NewtonProverTaskManager newtonProverTaskManagerImpl = new NewtonProverTaskManager(
            OperatorRegistry(result.operatorRegistry),
            IPauserRegistry(address(pausercontract)),
            PROTOCOL_VERSION
        );
        result.newtonProverTaskManagerImpl = address(newtonProverTaskManagerImpl);

        // Deploy RegoVerifier implementation
        address regoVerifierImpl = address(new RegoVerifier());
        result.regoVerifierImpl = regoVerifierImpl;

        NewtonProverServiceManager newtonProverServiceManagerImpl = new NewtonProverServiceManager(
            (IAVSDirectory(avsdirectory)),
            ISlashingRegistryCoordinator(result.operatorRegistry),
            IStakeRegistry(result.stakeRegistry),
            core.rewardsCoordinator,
            IAllocationManager(core.allocationManager),
            IPermissionController(core.permissionController),
            INewtonProverTaskManager(result.newtonProverTaskManager)
        );
        result.newtonProverServiceManagerImpl = address(newtonProverServiceManagerImpl);

        bytes memory servicemanagerupgradecall =
            abi.encodeCall(NewtonProverServiceManager.initialize, (admin, admin));
        UpgradeableProxyLib.upgradeAndCall(
            result.newtonProverServiceManager,
            address(newtonProverServiceManagerImpl),
            servicemanagerupgradecall
        );

        // Deploy AttestationValidator implementation
        address attestationValidatorImpl = address(
            new AttestationValidator(result.newtonProverTaskManager, result.operatorRegistry)
        );
        result.attestationValidatorImpl = attestationValidatorImpl;

        // Deploy ChallengeVerifier implementation
        address challengeVerifierImpl = address(
            new ChallengeVerifier(
                result.newtonProverServiceManager,
                result.newtonProverTaskManager,
                result.operatorRegistry,
                result.blsApkRegistry,
                core.allocationManager,
                result.slasher,
                result.regoVerifier,
                result.attestationValidator,
                result.operatorRegistry
            )
        );
        result.challengeVerifierImpl = challengeVerifierImpl;

        // deploy the IdentityRegistry
        result.identityRegistry = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        address identityRegistryImpl = address(new IdentityRegistry());
        UpgradeableProxyLib.upgradeAndCall(
            result.identityRegistry,
            identityRegistryImpl,
            abi.encodeCall(IdentityRegistry.initialize, (admin))
        );
        result.identityRegistryImpl = address(identityRegistryImpl);

        // deploy SourceTaskResponseHandler for BLS signature verification on source chains
        result.taskResponseHandler = address(
            new SourceTaskResponseHandler(ISlashingRegistryCoordinator(result.operatorRegistry))
        );

        bytes memory taskmanagerupgradecall = abi.encodeCall(
            NewtonProverTaskManager.initialize,
            (
                admin,
                config.aggregatorAddr,
                result.newtonProverServiceManager,
                result.operatorRegistry,
                result.taskResponseHandler,
                result.challengeVerifier,
                result.attestationValidator,
                config.taskResponseWindowBlock,
                config.epochBlocks
            )
        );
        UpgradeableProxyLib.upgradeAndCall(
            result.newtonProverTaskManager,
            address(newtonProverTaskManagerImpl),
            (taskmanagerupgradecall)
        );

        // Set taskCreationBufferWindow (not included in initialize, requires separate setter call)
        // Note: During broadcast, the deployer (who is the owner) is already msg.sender
        NewtonProverTaskManager(result.newtonProverTaskManager)
            .updateTaskCreationBufferWindow(config.taskCreationBufferWindow);

        // Initialize ChallengeVerifier
        bytes memory challengeVerifierInitCall = abi.encodeCall(
            ChallengeVerifier.initialize,
            (
                config.isChallengeEnabled,
                config.taskChallengeWindowBlock,
                config.taskResponseWindowBlock,
                admin
            )
        );
        UpgradeableProxyLib.upgradeAndCall(
            result.challengeVerifier, challengeVerifierImpl, challengeVerifierInitCall
        );

        // Initialize RegoVerifier
        bytes memory regoVerifierInitCall = abi.encodeCall(
            RegoVerifier.initialize, (config.sp1Verifier, config.sp1ProgramVkey, admin)
        );
        UpgradeableProxyLib.upgradeAndCall(
            result.regoVerifier, regoVerifierImpl, regoVerifierInitCall
        );

        // Initialize AttestationValidator
        bytes memory attestationValidatorInitCall =
            abi.encodeCall(AttestationValidator.initialize, (admin));
        UpgradeableProxyLib.upgradeAndCall(
            result.attestationValidator, attestationValidatorImpl, attestationValidatorInitCall
        );

        // TableCalculator for multichain transport
        if (core.keyRegistrar != address(0) && core.allocationManager != address(0)) {
            result.operatorTableCalculator = address(
                new BN254TableCalculator(
                    IKeyRegistrar(core.keyRegistrar),
                    IAllocationManager(core.allocationManager),
                    0 // LOOKAHEAD_BLOCKS
                )
            );
        }

        verifyDeployment(result);

        return result;
    }

    function upgradeContracts(
        CoreDeploymentLib.DeploymentData memory core,
        DeploymentLib.DeploymentData memory deploymentData,
        DeploymentLib.NewtonProverSetupConfig memory config,
        address admin
    ) internal returns (DeploymentLib.DeploymentData memory) {
        address avsdirectory = core.avsDirectory;

        DeploymentLib.DeploymentData memory result = deploymentData;

        // Get the ProxyAdmin from an existing proxy
        address proxyAdmin =
            address(UpgradeableProxyLib.getProxyAdmin(result.newtonProverServiceManager));

        /* Deploy or upgrade IdentityRegistry */
        if (result.identityRegistry == address(0)) {
            result.identityRegistry = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
            address identityRegistryImpl = address(new IdentityRegistry());
            result.identityRegistryImpl = address(identityRegistryImpl);
            UpgradeableProxyLib.upgradeAndCall(
                result.identityRegistry,
                identityRegistryImpl,
                abi.encodeCall(IdentityRegistry.initialize, (admin))
            );
        } else {
            // Upgrade existing contract
            IdentityRegistry identityRegistryImpl = new IdentityRegistry();
            result.identityRegistryImpl = address(identityRegistryImpl);
            UpgradeableProxyLib.upgrade(result.identityRegistry, address(identityRegistryImpl));
        }

        /* Deploy newton prover service & task manager implementations */

        /* Upgrade Newton Operator Registry */
        OperatorRegistry operatorRegistryImpl = new OperatorRegistry(
            IStakeRegistry(result.stakeRegistry),
            IBLSApkRegistry(result.blsApkRegistry),
            IIndexRegistry(result.indexRegistry),
            ISocketRegistry(result.socketRegistry),
            IAllocationManager(core.allocationManager),
            IPauserRegistry(core.pauserRegistry),
            MIDDLEWARE_VERSION
        );
        result.operatorRegistryImpl = address(operatorRegistryImpl);
        UpgradeableProxyLib.upgrade(result.operatorRegistry, result.operatorRegistryImpl);

        /* Upgrade AttestationValidator */
        AttestationValidator attestationValidatorImpl =
            new AttestationValidator(result.newtonProverTaskManager, result.operatorRegistry);
        result.attestationValidatorImpl = address(attestationValidatorImpl);
        UpgradeableProxyLib.upgrade(result.attestationValidator, address(attestationValidatorImpl));

        /* Upgrade ChallengeVerifier */
        ChallengeVerifier challengeVerifierImpl = new ChallengeVerifier(
            result.newtonProverServiceManager,
            result.newtonProverTaskManager,
            result.operatorRegistry,
            result.blsApkRegistry,
            core.allocationManager,
            result.slasher,
            result.regoVerifier,
            result.attestationValidator,
            result.operatorRegistry
        );
        result.challengeVerifierImpl = address(challengeVerifierImpl);
        UpgradeableProxyLib.upgrade(result.challengeVerifier, address(challengeVerifierImpl));

        /* Upgrade RegoVerifier */
        RegoVerifier regoVerifierImpl = new RegoVerifier();
        result.regoVerifierImpl = address(regoVerifierImpl);
        UpgradeableProxyLib.upgrade(result.regoVerifier, address(regoVerifierImpl));

        /* Upgrade NewtonProverServiceManager */
        NewtonProverServiceManager newtonProverServiceManagerImpl = new NewtonProverServiceManager(
            (IAVSDirectory(avsdirectory)),
            ISlashingRegistryCoordinator(result.operatorRegistry),
            IStakeRegistry(result.stakeRegistry),
            core.rewardsCoordinator,
            IAllocationManager(core.allocationManager),
            IPermissionController(core.permissionController),
            INewtonProverTaskManager(result.newtonProverTaskManager)
        );
        result.newtonProverServiceManagerImpl = address(newtonProverServiceManagerImpl);

        UpgradeableProxyLib.upgrade(
            result.newtonProverServiceManager, address(newtonProverServiceManagerImpl)
        );

        /* Upgrade NewtonProverTaskManager */
        NewtonProverTaskManager newtonProverTaskManagerImpl = new NewtonProverTaskManager(
            OperatorRegistry(result.operatorRegistry),
            IPauserRegistry(result.pauserRegistry),
            PROTOCOL_VERSION
        );
        result.newtonProverTaskManagerImpl = address(newtonProverTaskManagerImpl);

        UpgradeableProxyLib.upgrade(
            result.newtonProverTaskManager, address(newtonProverTaskManagerImpl)
        );

        /* Update NewtonProverTaskManager config */
        NewtonProverTaskManager(result.newtonProverTaskManager)
            .updateTaskResponseWindowBlock(config.taskResponseWindowBlock);
        NewtonProverTaskManager(result.newtonProverTaskManager)
            .updateEpochBlocks(config.epochBlocks);
        NewtonProverTaskManager(result.newtonProverTaskManager)
            .updateTaskCreationBufferWindow(config.taskCreationBufferWindow);

        /* Deploy new SourceTaskResponseHandler and update TaskManager */
        // SourceTaskResponseHandler is standalone (not upgradeable), so we deploy a new instance
        // when its implementation changes and update the TaskManager to use it
        address newTaskResponseHandler = address(
            new SourceTaskResponseHandler(ISlashingRegistryCoordinator(result.operatorRegistry))
        );
        result.taskResponseHandler = newTaskResponseHandler;
        NewtonProverTaskManager(result.newtonProverTaskManager)
            .updateTaskResponseHandler(newTaskResponseHandler);

        verifyDeployment(result);

        return result;
    }

    /// @notice Helper function to validate individual contracts
    function _validateContract(
        string memory contractName,
        address contractAddress
    ) private view {
        if (contractAddress == address(0)) {
            revert ContractNotDeployed(contractName, contractAddress);
        }

        uint256 codeSize;
        assembly {
            codeSize := extcodesize(contractAddress)
        }

        if (codeSize == 0) {
            revert ContractNotDeployed(contractName, contractAddress);
        }

        // solhint-disable-next-line no-console
        console2.log(string.concat("[OK] ", contractName, " validated:"), contractAddress);
    }

    function verifyDeployment(
        DeploymentLib.DeploymentData memory result
    ) internal view {
        // Core service contracts validation
        _validateContract("NewtonProverServiceManager", result.newtonProverServiceManager);
        _validateContract("NewtonProverTaskManager", result.newtonProverTaskManager);
        _validateContract("OperatorRegistry", result.operatorRegistry);
        _validateContract("ChallengeVerifier", result.challengeVerifier);
        _validateContract("RegoVerifier", result.regoVerifier);
        _validateContract("AttestationValidator", result.attestationValidator);

        // Registry contracts validation
        _validateContract("BLSApkRegistry", result.blsApkRegistry);
        _validateContract("IndexRegistry", result.indexRegistry);
        _validateContract("StakeRegistry", result.stakeRegistry);
        _validateContract("SocketRegistry", result.socketRegistry);
        _validateContract("OperatorStateRetriever", result.operatorStateRetriever);

        // Additional infrastructure
        _validateContract("PauserRegistry", result.pauserRegistry);
        _validateContract("IdentityRegistry", result.identityRegistry);
        _validateContract("Slasher", result.slasher);

        // Verify Eigenlayer Middleware contracts
        IBLSApkRegistry blsapkregistry =
            ISlashingRegistryCoordinator(result.operatorRegistry).blsApkRegistry();
        require(address(blsapkregistry) != address(0), BlsApkRegistryNotDeployed());
        IStakeRegistry stakeregistry =
            ISlashingRegistryCoordinator(result.operatorRegistry).stakeRegistry();
        require(address(stakeregistry) != address(0), StakeRegistryNotDeployed());
        IDelegationManager delegationmanager = IStakeRegistry(address(stakeregistry)).delegation();
        require(address(delegationmanager) != address(0), DelegationManagerNotDeployed());

        // solhint-disable-next-line no-console
        console2.log("[SUCCESS] All contract deployments verified");
    }
}
