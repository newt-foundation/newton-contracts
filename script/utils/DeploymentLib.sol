// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {UpgradeableProxyLib} from "./UpgradeableProxyLib.sol";

library DeploymentLib {
    using stdJson for *;
    using Strings for *;
    using UpgradeableProxyLib for address;

    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    error DeploymentConfigDoesNotExist();
    error DeploymentFileDoesNotExist();

    struct DeploymentData {
        address newtonProverServiceManager;
        address newtonProverServiceManagerImpl;
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
        address taskGeneratorAddr;
        address aggregatorAddr;
        uint32 taskResponseWindowBlock;
        uint32 taskChallengeWindowBlock;
        bool isChallengeEnabled;
        address sp1Verifier;
        bytes32 sp1ProgramVkey;
    }

    struct NewtonStakingConfig {
        address token;
        address tokenImpl;
        uint256 numQuorums;
        uint256[] operatorParams;
        uint96 minimumStake;
        uint32 lookAheadPeriod;
        address operatorAddr;
        address operator2Addr;
    }

    function readDeploymentJson(
        uint256 chainId
    ) internal returns (DeploymentData memory) {
        string memory env = VM.envOr("DEPLOYMENT_ENV", string("stagef"));
        return _readDeploymentJson("script/deployments/newton-prover/", chainId, env);
    }

    function readNewtonStakingConfigJson(
        string memory directoryPath
    ) internal returns (NewtonStakingConfig memory) {
        string memory fileName = string.concat(directoryPath, ".json");
        require(VM.exists(fileName), DeploymentConfigDoesNotExist());
        string memory json = VM.readFile(fileName);

        NewtonStakingConfig memory data;
        data.token = json.readAddressOr(".token", address(0));
        data.tokenImpl = json.readAddressOr(".tokenImpl", address(0));
        data.numQuorums = json.readUint(".num_quorums");
        data.operatorParams = json.readUintArray(".operator_params");
        data.operatorAddr = json.readAddressOr(".operator_addr", address(0));
        data.operator2Addr = json.readAddressOr(".operator_2_addr", address(0));
        return data;
    }

    function readNewtonProverConfigJson(
        string memory directoryPath
    ) internal returns (NewtonProverSetupConfig memory) {
        string memory fileName = string.concat(directoryPath, ".json");
        require(VM.exists(fileName), DeploymentConfigDoesNotExist());
        string memory json = VM.readFile(fileName);

        NewtonProverSetupConfig memory data;
        data.aggregatorAddr = json.readAddressOr(".aggregator_addr", address(0));
        data.taskGeneratorAddr = json.readAddressOr(".task_generator_addr", address(0));
        data.taskResponseWindowBlock = uint32(json.readUintOr(".task_response_window_block", 30));
        data.taskChallengeWindowBlock = uint32(json.readUintOr(".task_challenge_window_block", 30));
        data.isChallengeEnabled = json.readBoolOr(".is_challenge_enabled", false);
        data.sp1Verifier = json.readAddressOr(".sp1_verifier", address(0));
        data.sp1ProgramVkey = json.readBytes32Or(".sp1_program_vkey", bytes32(0));
        return data;
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
        data.newtonProverServiceManager = json.readAddress(".addresses.newtonProverServiceManager");
        data.newtonProverServiceManagerImpl =
            json.readAddress(".addresses.newtonProverServiceManagerImpl");
        data.newtonProverTaskManager = json.readAddress(".addresses.newtonProverTaskManager");
        data.newtonProverTaskManagerImpl =
            json.readAddress(".addresses.newtonProverTaskManagerImpl");
        data.challengeVerifier = json.readAddressOr(".addresses.challengeVerifier", address(0));
        data.challengeVerifierImpl =
            json.readAddressOr(".addresses.challengeVerifierImpl", address(0));
        data.attestationValidator =
            json.readAddressOr(".addresses.attestationValidator", address(0));
        data.attestationValidatorImpl =
            json.readAddressOr(".addresses.attestationValidatorImpl", address(0));
        data.operatorRegistry = json.readAddress(".addresses.operatorRegistry");
        data.operatorRegistryImpl = json.readAddress(".addresses.operatorRegistryImpl");
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
        data.regoVerifier = json.readAddressOr(".addresses.regoVerifier", address(0));
        data.regoVerifierImpl = json.readAddressOr(".addresses.regoVerifierImpl", address(0));

        return data;
    }

    /// write to default output path
    function writeDeploymentJson(
        DeploymentData memory data
    ) internal {
        string memory env = VM.envOr("DEPLOYMENT_ENV", string("stagef"));
        writeDeploymentJson("script/deployments/newton-prover/", block.chainid, data, env);
    }

    function writeDeploymentJson(
        string memory outputPath,
        uint256 chainId,
        DeploymentData memory data,
        string memory env
    ) internal {
        address proxyAdmin =
            address(UpgradeableProxyLib.getProxyAdmin(data.newtonProverServiceManager));

        string memory deploymentData = _generateDeploymentJson(data, proxyAdmin);

        string memory fileName = string.concat(outputPath, VM.toString(chainId), "-", env, ".json");
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
        string memory challengeVerifier = "";
        string memory challengeVerifierImpl = "";
        string memory attestationValidator = "";
        string memory attestationValidatorImpl = "";
        string memory regoVerifier = "";
        string memory regoVerifierImpl = "";
        if (data.challengeVerifier != address(0)) {
            challengeVerifier = data.challengeVerifier.toHexString();
            challengeVerifierImpl = data.challengeVerifier.getImplementation().toHexString();
        }
        if (data.attestationValidator != address(0)) {
            attestationValidator = data.attestationValidator.toHexString();
            attestationValidatorImpl = data.attestationValidator.getImplementation().toHexString();
        }
        if (data.regoVerifier != address(0)) {
            regoVerifier = data.regoVerifier.toHexString();
            regoVerifierImpl = data.regoVerifier.getImplementation().toHexString();
        }
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
            '","challengeVerifier":"',
            challengeVerifier,
            '","challengeVerifierImpl":"',
            challengeVerifierImpl,
            '","regoVerifier":"',
            regoVerifier,
            '","regoVerifierImpl":"',
            regoVerifierImpl,
            '","attestationValidator":"',
            attestationValidator,
            '","attestationValidatorImpl":"',
            attestationValidatorImpl,
            '","operatorRegistry":"',
            data.operatorRegistry.toHexString(),
            '","operatorRegistryImpl":"',
            data.operatorRegistry.getImplementation().toHexString(),
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
}
