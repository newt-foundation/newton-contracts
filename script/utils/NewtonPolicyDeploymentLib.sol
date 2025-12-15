// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {NewtonPolicyDataFactory} from "../../src/core/NewtonPolicyDataFactory.sol";
import {NewtonPolicyFactory} from "../../src/core/NewtonPolicyFactory.sol";
import {NewtonPolicyData} from "../../src/core/NewtonPolicyData.sol";
import {NewtonPolicy} from "../../src/core/NewtonPolicy.sol";
import {INewtonPolicy} from "../../src/interfaces/INewtonPolicy.sol";
import {INewtonPolicyData} from "../../src/interfaces/INewtonPolicyData.sol";
import {MockNewtonPolicyClient} from "../../examples/mock/MockNewtonPolicyClient.sol";
import {NewtonPolicyLib} from "./NewtonPolicyLib.sol";
import {UpgradeableProxyLib} from "./UpgradeableProxyLib.sol";
import {ArrayLib} from "./ArrayLib.sol";

library NewtonPolicyDeploymentLib {
    using stdJson for *;
    using Strings for *;
    using UpgradeableProxyLib for address;
    using ArrayLib for address[];

    /* ERRORS */
    error DeploymentFileDoesNotExist();
    error ContractNotDeployed(string contractName, address contractAddress);
    error ValidationFailed(string reason);
    error TaskGeneratorAddressesEmpty();
    error AttesterCannotBeZero();

    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    struct DeploymentData {
        address policyFactory;
        address policyFactoryImpl;
        address policy;
        address policyImplementation;
        address policyDataFactory;
        address policyDataFactoryImpl;
        address policyData;
        address policyDataImplementation;
        address policyClient;
        address policyClientImpl;
        bytes32 policyId;
    }

    /// @notice Deploy a single policy using existing policy data factory and policy factory
    function deployPolicy(
        address owner,
        DeploymentData memory deploymentData,
        NewtonPolicyLib.PolicyCids memory policyCids,
        address[] memory taskGenerators,
        uint32 policyDataExpireAfter
    ) internal returns (DeploymentData memory) {
        require(taskGenerators.length > 0, TaskGeneratorAddressesEmpty());
        require(policyCids.attester != address(0), AttesterCannotBeZero());

        address[] memory attesters = new address[](1);
        attesters[0] = policyCids.attester;
        attesters = attesters.addToArray(taskGenerators);

        DeploymentData memory result = deploymentData;

        address policyData = NewtonPolicyDataFactory(result.policyDataFactory)
            .deployPolicyData(
                policyCids.wasmCid,
                policyCids.secretsSchemaCid,
                policyDataExpireAfter,
                policyCids.policyDataMetadataCid,
                owner
            );
        result.policyData = policyData;
        result.policyDataImplementation =
            NewtonPolicyDataFactory(result.policyDataFactory).implementation();

        INewtonPolicyData(policyData)
            .setAttestationInfo(
                INewtonPolicyData.AttestationInfo({
                    attesters: attesters,
                    attestationType: INewtonPolicyData.AttestationType.ECDSA,
                    verifier: address(0),
                    verificationKey: bytes32(0)
                })
            );

        address[] memory policyDataArray = new address[](1);
        policyDataArray[0] = policyData;

        address policy = NewtonPolicyFactory(result.policyFactory)
            .deployPolicy(
                policyCids.entrypoint,
                policyCids.policyCid,
                policyCids.schemaCid,
                policyDataArray,
                policyCids.policyMetadataCid,
                owner
            );
        result.policy = policy;
        result.policyImplementation = NewtonPolicyFactory(result.policyFactory).implementation();

        verifyDeployment(result);

        return result;
    }

    /// @notice Complete deployment of all policy related contracts including factories
    function deployContracts(
        address proxyAdmin,
        NewtonPolicyLib.PolicyCids memory policyCids,
        address admin,
        address newtonProverTaskManager,
        string memory policyParams,
        address[] memory taskGenerators,
        uint32 policyDataExpireAfter
    ) internal returns (DeploymentData memory) {
        require(taskGenerators.length > 0, TaskGeneratorAddressesEmpty());
        require(policyCids.attester != address(0), AttesterCannotBeZero());

        DeploymentData memory result;

        // Deploy Policy related contracts
        result.policyFactory = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.policyDataFactory = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);

        result.policyDataFactoryImpl = address(new NewtonPolicyDataFactory());
        bytes memory policyDataFactoryUpgradeCall =
            abi.encodeCall(NewtonPolicyDataFactory.initialize, (admin));
        UpgradeableProxyLib.upgradeAndCall(
            result.policyDataFactory, result.policyDataFactoryImpl, policyDataFactoryUpgradeCall
        );

        address[] memory attesters = new address[](1);
        attesters[0] = policyCids.attester;
        attesters = attesters.addToArray(taskGenerators);

        address policyData = NewtonPolicyDataFactory(result.policyDataFactory)
            .deployPolicyData(
                policyCids.wasmCid,
                policyCids.secretsSchemaCid,
                policyDataExpireAfter,
                policyCids.policyDataMetadataCid,
                admin
            );
        if (policyData == address(0) || policyData.code.length == 0) {
            revert ContractNotDeployed("PolicyData", policyData);
        }

        result.policyData = policyData;
        result.policyDataImplementation =
            NewtonPolicyDataFactory(result.policyDataFactory).implementation();
        if (
            result.policyDataImplementation == address(0)
                || result.policyDataImplementation.code.length == 0
        ) {
            revert ContractNotDeployed("PolicyDataImplementation", result.policyDataImplementation);
        }

        INewtonPolicyData(policyData)
            .setAttestationInfo(
                INewtonPolicyData.AttestationInfo({
                    attesters: attesters,
                    attestationType: INewtonPolicyData.AttestationType.ECDSA,
                    verifier: address(0),
                    verificationKey: bytes32(0)
                })
            );

        string memory entrypoint = policyCids.entrypoint;
        string memory policyCid = policyCids.policyCid;
        string memory schemaCid = policyCids.schemaCid;
        string memory policyMetadataCid = policyCids.policyMetadataCid;
        address[] memory policyDataArray = new address[](1);
        policyDataArray[0] = policyData;

        result.policyFactoryImpl = address(new NewtonPolicyFactory());
        bytes memory policyFactoryUpgradeCall =
            abi.encodeCall(NewtonPolicyFactory.initialize, (admin));
        UpgradeableProxyLib.upgradeAndCall(
            result.policyFactory, result.policyFactoryImpl, policyFactoryUpgradeCall
        );

        address policy = NewtonPolicyFactory(result.policyFactory)
            .deployPolicy(
                entrypoint, policyCid, schemaCid, policyDataArray, policyMetadataCid, admin
            );

        result.policy = policy;
        result.policyImplementation = NewtonPolicyFactory(result.policyFactory).implementation();
        if (
            result.policyImplementation == address(0)
                || result.policyImplementation.code.length == 0
        ) {
            revert ContractNotDeployed("PolicyImplementation", result.policyImplementation);
        }

        result.policyClient = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.policyClientImpl = address(new MockNewtonPolicyClient());
        bytes memory upgradeCall = abi.encodeCall(
            MockNewtonPolicyClient.initialize, (newtonProverTaskManager, result.policy, admin)
        );
        UpgradeableProxyLib.upgradeAndCall(
            result.policyClient, result.policyClientImpl, upgradeCall
        );

        result.policyId = MockNewtonPolicyClient(result.policyClient)
            .setPolicy(
                INewtonPolicy.PolicyConfig({
                    policyParams: bytes(policyParams), expireAfter: uint32(1 minutes)
                })
            );

        verifyDeployment(result);

        return result;
    }

    /// @notice Upgrade policy and policy data factories and deploy new policy and policy data
    function upgradeContracts(
        DeploymentData memory deploymentData,
        NewtonPolicyLib.PolicyCids memory policyCids,
        address admin,
        address newtonProverTaskManager,
        string memory policyParams,
        address[] memory taskGenerators,
        uint32 policyDataExpireAfter
    ) internal returns (DeploymentData memory) {
        require(taskGenerators.length > 0, TaskGeneratorAddressesEmpty());
        require(policyCids.attester != address(0), AttesterCannotBeZero());

        DeploymentData memory result = deploymentData;

        // Upgrade PolicyDataFactory
        result.policyDataFactoryImpl = address(new NewtonPolicyDataFactory());
        UpgradeableProxyLib.upgrade(result.policyDataFactory, result.policyDataFactoryImpl);

        // IMPORTANT: Upgrading the factory proxy does NOT re-run `initialize()`, so the factory's
        // persisted `implementation` address remains whatever it was before. Rotate it explicitly
        // so newly deployed PolicyData proxies use the latest `NewtonPolicyData` bytecode.
        NewtonPolicyDataFactory(result.policyDataFactory)
            .setImplementation(address(new NewtonPolicyData()));

        address[] memory attesters = new address[](1);
        attesters[0] = policyCids.attester;
        attesters = attesters.addToArray(taskGenerators);

        address policyData = NewtonPolicyDataFactory(result.policyDataFactory)
            .deployPolicyData(
                policyCids.wasmCid,
                policyCids.secretsSchemaCid,
                policyDataExpireAfter,
                policyCids.policyDataMetadataCid,
                admin
            );
        result.policyData = policyData;
        result.policyDataImplementation =
            NewtonPolicyDataFactory(result.policyDataFactory).implementation();

        INewtonPolicyData(policyData)
            .setAttestationInfo(
                INewtonPolicyData.AttestationInfo({
                    attesters: attesters,
                    attestationType: INewtonPolicyData.AttestationType.ECDSA,
                    verifier: address(0),
                    verificationKey: bytes32(0)
                })
            );

        string memory entrypoint = policyCids.entrypoint;
        string memory policyCid = policyCids.policyCid;
        string memory schemaCid = policyCids.schemaCid;
        string memory policyMetadataCid = policyCids.policyMetadataCid;
        address[] memory policyDataArray = new address[](1);
        policyDataArray[0] = policyData;

        // Upgrade PolicyFactory
        result.policyFactoryImpl = address(new NewtonPolicyFactory());
        UpgradeableProxyLib.upgrade(result.policyFactory, result.policyFactoryImpl);

        // Same rationale as above: rotate the persisted `implementation` so newly deployed Policy
        // proxies use the latest `NewtonPolicy` bytecode (avoids ERC-165 interface-id drift).
        NewtonPolicyFactory(result.policyFactory).setImplementation(address(new NewtonPolicy()));

        address policy = NewtonPolicyFactory(result.policyFactory)
            .deployPolicy(
                entrypoint, policyCid, schemaCid, policyDataArray, policyMetadataCid, admin
            );
        result.policy = policy;
        result.policyImplementation = NewtonPolicyFactory(result.policyFactory).implementation();

        address proxyAdmin = address(UpgradeableProxyLib.getProxyAdmin(result.policyFactory));
        result.policyClient = UpgradeableProxyLib.setUpEmptyProxy(proxyAdmin);
        result.policyClientImpl = address(new MockNewtonPolicyClient());
        bytes memory upgradeCall = abi.encodeCall(
            MockNewtonPolicyClient.initialize, (newtonProverTaskManager, result.policy, admin)
        );
        UpgradeableProxyLib.upgradeAndCall(
            result.policyClient, result.policyClientImpl, upgradeCall
        );

        result.policyId = MockNewtonPolicyClient(result.policyClient)
            .setPolicy(
                INewtonPolicy.PolicyConfig({
                    policyParams: bytes(policyParams), expireAfter: uint32(1 minutes)
                })
            );

        verifyDeployment(result);

        return result;
    }

    function readDeploymentJson(
        uint256 chainId
    ) internal returns (DeploymentData memory) {
        string memory env = VM.envOr("DEPLOYMENT_ENV", string("stagef"));
        return _readDeploymentJson("script/deployments/policy/", chainId, env);
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
        data.policyFactory = json.readAddress(".addresses.policyFactory");
        data.policyFactoryImpl = json.readAddress(".addresses.policyFactoryImpl");
        data.policy = json.readAddress(".addresses.policy");
        data.policyImplementation = json.readAddress(".addresses.policyImplementation");
        data.policyDataFactory = json.readAddress(".addresses.policyDataFactory");
        data.policyDataFactoryImpl = json.readAddress(".addresses.policyDataFactoryImpl");
        data.policyData = json.readAddress(".addresses.policyData");
        data.policyDataImplementation = json.readAddress(".addresses.policyDataImplementation");
        data.policyClient = json.readAddress(".addresses.policyClient");
        data.policyClientImpl = json.readAddress(".addresses.policyClientImpl");
        data.policyId = json.readBytes32(".addresses.policyId");

        return data;
    }

    /// write to default output path
    function writeDeploymentJson(
        DeploymentData memory data
    ) internal {
        string memory env = VM.envOr("DEPLOYMENT_ENV", string("stagef"));
        writeDeploymentJson("script/deployments/policy/", block.chainid, data, env);
    }

    function writeDeploymentJson(
        string memory outputPath,
        uint256 chainId,
        DeploymentData memory data,
        string memory env
    ) internal {
        address proxyAdmin = address(UpgradeableProxyLib.getProxyAdmin(data.policyFactory));

        string memory deploymentData = _generateDeploymentJson(data, proxyAdmin);

        string memory fileName = string.concat(outputPath, VM.toString(chainId), "-", env, ".json");
        if (!VM.exists(outputPath)) {
            VM.createDir(outputPath, true);
        }

        VM.writeFile(fileName, deploymentData);
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
        string memory json = '{"proxyAdmin":"';
        json = string.concat(json, proxyAdmin.toHexString());
        json = string.concat(json, '","policyFactory":"', data.policyFactory.toHexString());
        json = string.concat(
            json, '","policyFactoryImpl":"', data.policyFactory.getImplementation().toHexString()
        );
        json = string.concat(json, '","policy":"', data.policy.toHexString());
        json = string.concat(
            json, '","policyImplementation":"', data.policyImplementation.toHexString()
        );
        json = string.concat(json, '","policyDataFactory":"', data.policyDataFactory.toHexString());
        json = string.concat(
            json,
            '","policyDataFactoryImpl":"',
            data.policyDataFactory.getImplementation().toHexString()
        );
        json = string.concat(json, '","policyData":"', data.policyData.toHexString());
        json = string.concat(
            json, '","policyDataImplementation":"', data.policyDataImplementation.toHexString()
        );
        json = string.concat(json, '","policyClient":"', data.policyClient.toHexString());
        json = string.concat(json, '","policyClientImpl":"', data.policyClientImpl.toHexString());
        json = string.concat(json, '","policyId":"', VM.toString(data.policyId));
        json = string.concat(json, '"}');

        return json;
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
    }

    function verifyDeployment(
        DeploymentData memory result
    ) internal view {
        // Policy system validation
        _validateContract("PolicyFactory", result.policyFactory);
        _validateContract("PolicyFactoryImpl", result.policyFactoryImpl);
        _validateContract("Policy", result.policy);
        _validateContract("PolicyImplementation", result.policyImplementation);
        _validateContract("PolicyDataFactory", result.policyDataFactory);
        _validateContract("PolicyDataFactoryImpl", result.policyDataFactoryImpl);
        _validateContract("PolicyData", result.policyData);
        _validateContract("PolicyDataImplementation", result.policyDataImplementation);
        _validateContract("PolicyClient", result.policyClient);
        _validateContract("PolicyClientImpl", result.policyClientImpl);
    }
}
