// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ChainLib} from "../../src/libraries/ChainLib.sol";
import {IAVSDirectory} from "@eigenlayer/contracts/interfaces/IAVSDirectory.sol";
import {ISocketRegistry, SocketRegistry} from "@eigenlayer-middleware/src/SocketRegistry.sol";
import {ISlashingRegistryCoordinator} from
    "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {SlashingRegistryCoordinator} from
    "@eigenlayer-middleware/src/SlashingRegistryCoordinator.sol";
import {IPermissionController} from "@eigenlayer/contracts/interfaces/IPermissionController.sol";
import {INewtonProverTaskManager} from "../../src/interfaces/INewtonProverTaskManager.sol";
import {IDelegationManager} from "@eigenlayer/contracts/interfaces/IDelegationManager.sol";
import {UpgradeableProxyLib} from "./UpgradeableProxyLib.sol";
import {CoreDeploymentLib} from "./CoreDeploymentLib.sol";
import {ChainLib} from "../../src/libraries/ChainLib.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {BLSApkRegistry} from "@eigenlayer-middleware/src/BLSApkRegistry.sol";
import {IndexRegistry} from "@eigenlayer-middleware/src/IndexRegistry.sol";
import {InstantSlasher} from "@eigenlayer-middleware/src/slashers/InstantSlasher.sol";
import {StakeRegistry} from "@eigenlayer-middleware/src/StakeRegistry.sol";
import {IAllocationManager} from "@eigenlayer/contracts/interfaces/IAllocationManager.sol";
import {CoreDeploymentLib} from "./CoreDeploymentLib.sol";
import {
    IBLSApkRegistry,
    IIndexRegistry,
    IStakeRegistry
} from "@eigenlayer-middleware/src/SlashingRegistryCoordinator.sol";
import {IStakeRegistryTypes} from "@eigenlayer-middleware/src/interfaces/IStakeRegistry.sol";
import {
    PauserRegistry, IPauserRegistry
} from "@eigenlayer/contracts/permissions/PauserRegistry.sol";
import {OperatorStateRetriever} from "@eigenlayer-middleware/src/OperatorStateRetriever.sol";

library NewtonProverDeploymentLib {
    using stdJson for *;
    using Strings for *;
    using UpgradeableProxyLib for address;

    error DeploymentFileDoesNotExist();
    error BlsApkRegistryNotDeployed();
    error StakeRegistryNotDeployed();
    error DelegationManagerNotDeployed();
    error ContractNotDeployed(string contractName, address contractAddress);
    error ValidationFailed(string reason);

    string internal constant MIDDLEWARE_VERSION = "v1.5.0-testnet-final";
    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    struct DeploymentData {
        address newtonProverServiceManager;
        address newtonProverServiceManagerImpl;
        address newtonProverTaskManager;
        address newtonProverTaskManagerImpl;
        address slashingRegistryCoordinator;
        address slashingRegistryCoordinatorImpl;
        address operatorStateRetriever;
        address blsApkRegistry;
        address blsApkRegistryImpl;
        address indexRegistry;
        address indexRegistryImpl;
        address stakeRegistry;
        address stakeRegistryImpl;
        address socketRegistry;
        address socketRegistryImpl;
        address strategy;
        address pauserRegistry;
        address token;
        address tokenImpl;
        address slasher;
        address instantSlasherImpl;
    }

    struct NewtonProverSetupConfig {
        address token;
        address tokenImpl;
        uint256 numQuorums;
        uint256[] operatorParams;
        uint96 minimumStake;
        uint32 lookAheadPeriod;
        address operatorAddr;
        address operator2Addr;
        address taskGeneratorAddr;
        address aggregatorAddr;
    }

    function getTaskManagerConfig()
        internal
        view
        returns (INewtonProverTaskManager.TaskManagerConfig memory)
    {
        ChainLib.requireSupportedChain();
        if (ChainLib.isMainnet()) {
            // solhint-disable-next-line no-console
            console2.log("Mainnet task manager config");
            return INewtonProverTaskManager.TaskManagerConfig({
                taskResponseWindowBlock: 30,
                taskChallengeWindowBlock: 0,
                isChallengeEnabled: false
            });
        }

        // solhint-disable-next-line no-console
        console2.log("Non-mainnet task manager config");
        return INewtonProverTaskManager.TaskManagerConfig({
            taskResponseWindowBlock: 30,
            taskChallengeWindowBlock: 30,
            isChallengeEnabled: true
        });
    }

    function readDeploymentJson(
        uint256 chainId
    ) internal returns (DeploymentData memory) {
        return _readDeploymentJson("script/deployments/newton-prover/", chainId);
    }

    function readNewtonProverConfigJson(
        string memory directoryPath
    ) internal returns (NewtonProverSetupConfig memory) {
        string memory fileName = string.concat(directoryPath, ".json");
        require(VM.exists(fileName), DeploymentFileDoesNotExist());
        string memory json = VM.readFile(fileName);

        NewtonProverSetupConfig memory data;
        data.token = json.readAddressOr(".token", address(0));
        data.tokenImpl = json.readAddressOr(".tokenImpl", address(0));
        data.numQuorums = json.readUint(".num_quorums");
        data.operatorParams = json.readUintArray(".operator_params");
        data.aggregatorAddr = json.readAddressOr(".aggregator_addr", address(0));
        data.operatorAddr = json.readAddressOr(".operator_addr", address(0));
        data.taskGeneratorAddr = json.readAddressOr(".task_generator_addr", address(0));
        data.operator2Addr = json.readAddressOr(".operator_2_addr", address(0));
        return data;
    }

    function _readDeploymentJson(
        string memory directoryPath,
        uint256 chainId
    ) internal returns (DeploymentData memory) {
        string memory fileName = string.concat(directoryPath, VM.toString(chainId), ".json");

        require(VM.exists(fileName), DeploymentFileDoesNotExist());

        string memory json = VM.readFile(fileName);

        DeploymentData memory data;
        data.newtonProverServiceManager = json.readAddress(".addresses.newtonProverServiceManager");
        data.newtonProverServiceManagerImpl =
            json.readAddress(".addresses.newtonProverServiceManagerImpl");
        data.newtonProverTaskManager = json.readAddress(".addresses.newtonProverTaskManager");
        data.newtonProverTaskManagerImpl =
            json.readAddress(".addresses.newtonProverTaskManagerImpl");
        data.slashingRegistryCoordinator = json.readAddress(".addresses.registryCoordinator");
        data.slashingRegistryCoordinatorImpl =
            json.readAddress(".addresses.slashingRegistryCoordinatorImpl");
        data.operatorStateRetriever = json.readAddress(".addresses.operatorStateRetriever");
        data.blsApkRegistry = json.readAddress(".addresses.blsApkRegistry");
        data.blsApkRegistryImpl = json.readAddress(".addresses.blsApkRegistryImpl");
        data.indexRegistry = json.readAddress(".addresses.indexRegistry");
        data.indexRegistryImpl = json.readAddress(".addresses.indexRegistryImpl");
        data.stakeRegistry = json.readAddress(".addresses.stakeRegistry");
        data.stakeRegistryImpl = json.readAddress(".addresses.stakeRegistryImpl");
        data.socketRegistry = json.readAddress(".addresses.socketRegistry");
        data.socketRegistryImpl = json.readAddress(".addresses.socketRegistryImpl");
        data.strategy = json.readAddress(".addresses.strategy");
        data.pauserRegistry = json.readAddress(".addresses.pauserRegistry");
        data.token = json.readAddress(".addresses.token");
        data.tokenImpl = json.readAddress(".addresses.tokenImpl");
        data.slasher = json.readAddress(".addresses.slasher");
        data.instantSlasherImpl = json.readAddress(".addresses.instantSlasherImpl");

        return data;
    }

    /// write to default output path
    function writeDeploymentJson(
        DeploymentData memory data
    ) internal {
        writeDeploymentJson("script/deployments/newton-prover/", block.chainid, data);
    }

    function writeDeploymentJson(
        string memory outputPath,
        uint256 chainId,
        DeploymentData memory data
    ) internal {
        address proxyAdmin =
            address(UpgradeableProxyLib.getProxyAdmin(data.newtonProverServiceManager));

        string memory deploymentData = _generateDeploymentJson(data, proxyAdmin);

        string memory fileName = string.concat(outputPath, VM.toString(chainId), ".json");
        if (!VM.exists(outputPath)) {
            VM.createDir(outputPath, true);
        }

        VM.writeFile(fileName, deploymentData);
        // solhint-disable-next-line no-console
        console2.log("Deployment artifacts written to:", fileName);
    }

    function _generateDeploymentJson(
        DeploymentData memory data,
        address proxyAdmin
    ) private view returns (string memory) {
        return string.concat(
            '{"lastUpdate":{"timestamp":"',
            VM.toString(block.timestamp),
            '","block_number":"',
            VM.toString(block.number),
            '"},"addresses":',
            _generateContractsJson(data, proxyAdmin),
            "}"
        );
    }

    function _generateContractsJson(
        DeploymentData memory data,
        address proxyAdmin
    ) private view returns (string memory) {
        return string.concat(
            '{"proxyAdmin":"',
            proxyAdmin.toHexString(),
            '","newtonProverServiceManager":"',
            data.newtonProverServiceManager.toHexString(),
            '","newtonProverServiceManagerImpl":"',
            data.newtonProverServiceManager.getImplementation().toHexString(),
            '","newtonProverTaskManager":"',
            data.newtonProverTaskManager.toHexString(),
            '","newtonProverTaskManagerImpl":"',
            data.newtonProverTaskManager.getImplementation().toHexString(),
            '","registryCoordinator":"',
            data.slashingRegistryCoordinator.toHexString(),
            '","slashingRegistryCoordinatorImpl":"',
            data.slashingRegistryCoordinator.getImplementation().toHexString(),
            '","blsApkRegistry":"',
            data.blsApkRegistry.toHexString(),
            '","blsApkRegistryImpl":"',
            data.blsApkRegistry.getImplementation().toHexString(),
            '","indexRegistry":"',
            data.indexRegistry.toHexString(),
            '","indexRegistryImpl":"',
            data.indexRegistry.getImplementation().toHexString(),
            '","stakeRegistry":"',
            data.stakeRegistry.toHexString(),
            '","stakeRegistryImpl":"',
            data.stakeRegistry.getImplementation().toHexString(),
            '","socketRegistry":"',
            data.socketRegistry.toHexString(),
            '","socketRegistryImpl":"',
            data.socketRegistry.getImplementation().toHexString(),
            '","operatorStateRetriever":"',
            data.operatorStateRetriever.toHexString(),
            '","strategy":"',
            data.strategy.toHexString(),
            '","pauserRegistry":"',
            data.pauserRegistry.toHexString(),
            '","token":"',
            data.token.toHexString(),
            '","tokenImpl":"',
            data.tokenImpl.toHexString(),
            '","slasher":"',
            data.slasher.toHexString(),
            '","instantSlasherImpl":"',
            data.slasher.getImplementation().toHexString(),
            '"}'
        );
    }

    /// @notice Helper function to validate individual contracts
    function _validateContract(string memory contractName, address contractAddress) private view {
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
        DeploymentData memory result
    ) internal view {
        // Core service contracts validation
        _validateContract("NewtonProverServiceManager", result.newtonProverServiceManager);
        _validateContract("NewtonProverTaskManager", result.newtonProverTaskManager);
        _validateContract("SlashingRegistryCoordinator", result.slashingRegistryCoordinator);

        // Registry contracts validation
        _validateContract("BLSApkRegistry", result.blsApkRegistry);
        _validateContract("IndexRegistry", result.indexRegistry);
        _validateContract("StakeRegistry", result.stakeRegistry);
        _validateContract("SocketRegistry", result.socketRegistry);
        _validateContract("OperatorStateRetriever", result.operatorStateRetriever);

        // Additional infrastructure
        _validateContract("PauserRegistry", result.pauserRegistry);
        _validateContract("Slasher", result.slasher);

        // Verify Eigenlayer Middleware contracts
        IBLSApkRegistry blsapkregistry =
            ISlashingRegistryCoordinator(result.slashingRegistryCoordinator).blsApkRegistry();
        require(address(blsapkregistry) != address(0), BlsApkRegistryNotDeployed());
        IStakeRegistry stakeregistry =
            ISlashingRegistryCoordinator(result.slashingRegistryCoordinator).stakeRegistry();
        require(address(stakeregistry) != address(0), StakeRegistryNotDeployed());
        IDelegationManager delegationmanager = IStakeRegistry(address(stakeregistry)).delegation();
        require(address(delegationmanager) != address(0), DelegationManagerNotDeployed());

        // solhint-disable-next-line no-console
        console2.log("[SUCCESS] All contract deployments verified");
    }
}
