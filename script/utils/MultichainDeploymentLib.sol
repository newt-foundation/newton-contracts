// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {DeploymentLib} from "./DeploymentLib.sol";
import {CoreDeploymentLib} from "./CoreDeploymentLib.sol";
import {
    IBLSApkRegistry,
    IIndexRegistry,
    IStakeRegistry
} from "@eigenlayer-middleware/src/SlashingRegistryCoordinator.sol";
import {ISocketRegistry} from "@eigenlayer-middleware/src/SocketRegistry.sol";
import {IAllocationManager} from "@eigenlayer/contracts/interfaces/IAllocationManager.sol";
import {UpgradeableProxyLib} from "./UpgradeableProxyLib.sol";
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
import {PauserRegistry} from "@eigenlayer/contracts/permissions/PauserRegistry.sol";
import {IPauserRegistry} from "@eigenlayer/contracts/interfaces/IPauserRegistry.sol";
import {NewtonProverDestTaskManager} from "../../src/NewtonProverDestTaskManager.sol";
import {ChallengeVerifier} from "../../src/middlewares/ChallengeVerifier.sol";
import {RegoVerifier} from "../../src/middlewares/RegoVerifier.sol";
import {AttestationValidator} from "../../src/middlewares/AttestationValidator.sol";
import {OperatorRegistry} from "../../src/middlewares/OperatorRegistry.sol";
import {
    DestinationTaskResponseHandler
} from "../../src/middlewares/DestinationTaskResponseHandler.sol";
import {ICertificateVerifier} from "../../src/interfaces/ICertificateVerifier.sol";

library MultichainDeploymentLib {
    using stdJson for *;
    using Strings for *;
    using UpgradeableProxyLib for address;

    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    error DeploymentFileDoesNotExist();

    struct DeploymentData {
        // eigenlayer multichain contracts
        address proxyAdmin;
        address pauserRegistry;
        address operatorTableUpdater;
        address operatorTableUpdaterImpl;
        address bn254CertificateVerifier;
        address bn254CertificateVerifierImpl;
        address ecdsaCertificateVerifier;
        address ecdsaCertificateVerifierImpl;
        // newton avs contracts
        address newtonProverTaskManager;
        address newtonProverTaskManagerImpl;
        address challengeVerifier;
        address challengeVerifierImpl;
        address regoVerifier;
        address regoVerifierImpl;
        address attestationValidator;
        address attestationValidatorImpl;
        address operatorRegistry;
        address operatorRegistryImpl;
        uint256 sourceChainId;
    }

    function deployContracts(
        address proxyAdmin,
        uint256 sourceChainId,
        address admin
    ) internal returns (DeploymentData memory) {
        DeploymentData memory result;
        result.proxyAdmin = proxyAdmin;
        result.sourceChainId = sourceChainId;

        // deploy pauser registry
        result.pauserRegistry = address(
            new PauserRegistry(
                new address[](0), // empty array for pausers
                proxyAdmin // proxyAdmin as the unpauser
            )
        );

        // deploy empty proxies for eigenlayer multichain contracts
        result.operatorTableUpdater = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.bn254CertificateVerifier = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.ecdsaCertificateVerifier = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);

        // deploy eigenlayer multichain implementations
        result.bn254CertificateVerifierImpl = address(
            new BN254CertificateVerifier(
                IOperatorTableUpdater(result.operatorTableUpdater), "1.0.0"
            )
        );

        result.ecdsaCertificateVerifierImpl = address(
            new ECDSACertificateVerifier(
                IOperatorTableUpdater(result.operatorTableUpdater), "1.0.0"
            )
        );

        result.operatorTableUpdaterImpl = address(
            new OperatorTableUpdater(
                IBN254CertificateVerifier(result.bn254CertificateVerifier),
                IECDSACertificateVerifier(result.ecdsaCertificateVerifier),
                IPauserRegistry(result.pauserRegistry),
                "1.0.0"
            )
        );

        // upgrade eigenlayer proxies
        UpgradeableProxyLib.upgrade(result.operatorTableUpdater, result.operatorTableUpdaterImpl);
        UpgradeableProxyLib.upgrade(
            result.bn254CertificateVerifier, result.bn254CertificateVerifierImpl
        );
        UpgradeableProxyLib.upgrade(
            result.ecdsaCertificateVerifier, result.ecdsaCertificateVerifierImpl
        );

        // deploy empty proxies for newton avs contracts
        result.newtonProverTaskManager = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.challengeVerifier = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.regoVerifier = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.attestationValidator = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.operatorRegistry = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);

        // deploy destination operator registry implementation
        result.operatorRegistryImpl = address(
            new OperatorRegistry(
                IStakeRegistry(address(0)), // address(0) for destination chains
                IBLSApkRegistry(address(0)), // address(0) for destination chains
                IIndexRegistry(address(0)), // address(0) for destination chains
                ISocketRegistry(address(0)), // address(0) for destination chains
                IAllocationManager(address(0)), // address(0) for destination chains
                IPauserRegistry(result.pauserRegistry),
                "1.0.0-destination"
            )
        );

        // deploy newton avs implementations
        result.newtonProverTaskManagerImpl = address(
            new NewtonProverDestTaskManager(
                OperatorRegistry(result.operatorRegistry), IPauserRegistry(result.pauserRegistry)
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

        // upgrade newton avs proxies
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

        // deploy DestinationTaskResponseHandler for certificate verification on destination chains
        address taskResponseHandler = address(
            new DestinationTaskResponseHandler(
                ICertificateVerifier(result.bn254CertificateVerifier)
            )
        );

        bytes memory taskManagerInitCall = abi.encodeWithSignature(
            "initialize(address,address,address,address,address,address,address,uint32)",
            admin, // initialOwner
            admin, // aggregator
            result.bn254CertificateVerifier, // certificateVerifier
            result.operatorRegistry,
            taskResponseHandler, // taskResponseHandler
            result.challengeVerifier,
            result.attestationValidator,
            uint32(30) // taskResponseWindowBlock
        );
        UpgradeableProxyLib.upgradeAndCall(
            result.newtonProverTaskManager, result.newtonProverTaskManagerImpl, taskManagerInitCall
        );

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

    function upgradeContracts(
        CoreDeploymentLib.DeploymentData memory core,
        DeploymentData memory deploymentData,
        DeploymentLib.NewtonProverSetupConfig memory config
    ) internal returns (DeploymentData memory) {
        address avsdirectory = core.avsDirectory;

        DeploymentData memory result = deploymentData;

        /* Deploy newton prover service & task manager implementations */

        /* Upgrade ChallengeVerifier */
        ChallengeVerifier challengeVerifierImpl = new ChallengeVerifier(
            address(0), // serviceManager (address(0) for destination chains)
            result.newtonProverTaskManager,
            address(0), // registryCoordinator (address(0) for destination chains)
            address(0), // blsApkRegistry (address(0) for destination chains)
            address(0), // allocationManager (address(0) for destination chains)
            address(0), // instantSlasher (address(0) for destination chains)
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

        /* Upgrade AttestationValidator */
        AttestationValidator attestationValidatorImpl =
            new AttestationValidator(result.newtonProverTaskManager, result.operatorRegistry);
        result.attestationValidatorImpl = address(attestationValidatorImpl);

        UpgradeableProxyLib.upgrade(result.attestationValidator, address(attestationValidatorImpl));

        /* Upgrade NewtonProverTaskManager */
        NewtonProverDestTaskManager(result.newtonProverTaskManager)
            .updateTaskResponseWindowBlock(config.taskResponseWindowBlock);

        return result;
    }

    function readDeploymentJson(
        uint256 chainId
    ) internal returns (DeploymentData memory) {
        string memory env = VM.envOr("DEPLOYMENT_ENV", string("stagef"));
        return _readDeploymentJson("script/deployments/multichain-destination/", chainId, env);
    }

    function _readDeploymentJson(
        string memory directoryPath,
        uint256 chainId,
        string memory env
    ) internal returns (DeploymentData memory) {
        string memory fileName =
            string.concat(directoryPath, VM.toString(chainId), "-", env, ".json");

        require(VM.exists(fileName), DeploymentFileDoesNotExist());

        string memory json = VM.readFile(fileName);

        DeploymentData memory data;
        data.proxyAdmin = json.readAddress(".addresses.proxyAdmin");
        data.pauserRegistry = json.readAddress(".addresses.pauserRegistry");
        data.operatorTableUpdater = json.readAddress(".addresses.operatorTableUpdater");
        data.operatorTableUpdaterImpl = json.readAddress(".addresses.operatorTableUpdaterImpl");
        data.bn254CertificateVerifier = json.readAddress(".addresses.bn254CertificateVerifier");
        data.bn254CertificateVerifierImpl =
            json.readAddress(".addresses.bn254CertificateVerifierImpl");
        data.ecdsaCertificateVerifier = json.readAddress(".addresses.ecdsaCertificateVerifier");
        data.ecdsaCertificateVerifierImpl =
            json.readAddress(".addresses.ecdsaCertificateVerifierImpl");
        data.newtonProverTaskManager = json.readAddress(".addresses.newtonProverTaskManager");
        data.newtonProverTaskManagerImpl =
            json.readAddress(".addresses.newtonProverTaskManagerImpl");
        data.challengeVerifier = json.readAddress(".addresses.challengeVerifier");
        data.challengeVerifierImpl = json.readAddress(".addresses.challengeVerifierImpl");
        data.regoVerifier = json.readAddress(".addresses.regoVerifier");
        data.regoVerifierImpl = json.readAddress(".addresses.regoVerifierImpl");
        data.attestationValidator = json.readAddress(".addresses.attestationValidator");
        data.attestationValidatorImpl = json.readAddress(".addresses.attestationValidatorImpl");
        data.operatorRegistry = json.readAddress(".addresses.operatorRegistry");
        data.operatorRegistryImpl = json.readAddress(".addresses.operatorRegistryImpl");
        data.sourceChainId = json.readUint(".sourceChainId");

        return data;
    }

    function writeDeploymentJson(
        DeploymentData memory data
    ) internal {
        string memory env = VM.envOr("DEPLOYMENT_ENV", string("stagef"));
        writeDeploymentJson("script/deployments/multichain-destination/", block.chainid, data, env);
    }

    function writeDeploymentJson(
        string memory outputPath,
        uint256 chainId,
        DeploymentData memory data,
        string memory env
    ) internal {
        string memory deploymentData = _generateDeploymentJson(data);

        string memory fileName = string.concat(outputPath, VM.toString(chainId), "-", env, ".json");
        if (!VM.exists(outputPath)) {
            VM.createDir(outputPath, true);
        }

        VM.writeFile(fileName, deploymentData);
        // solhint-disable-next-line no-console
        console2.log("Deployment artifacts written to:", fileName);
    }

    function _generateDeploymentJson(
        DeploymentData memory data
    ) private view returns (string memory) {
        return string.concat(
            '{"lastUpdate":{"timestamp":"',
            VM.toString(block.timestamp),
            '","block_number":"',
            VM.toString(block.number),
            '"},"sourceChainId":"',
            VM.toString(data.sourceChainId),
            '","addresses":',
            _generateContractsJson(data),
            "}"
        );
    }

    function _generateContractsJson(
        DeploymentData memory data
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
            '","operatorRegistry":"',
            data.operatorRegistry.toHexString(),
            '","operatorRegistryImpl":"',
            data.operatorRegistryImpl.toHexString(),
            '"}'
        );
    }
}
