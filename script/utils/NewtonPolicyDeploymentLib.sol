// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {NewtonPolicyDataFactory} from "../../src/core/NewtonPolicyDataFactory.sol";
import {NewtonPolicyFactory} from "../../src/core/NewtonPolicyFactory.sol";
import {INewtonPolicyData} from "../../src/interfaces/INewtonPolicyData.sol";
import {NewtonPolicyLib} from "./NewtonPolicyLib.sol";
import {UpgradeableProxyLib} from "./UpgradeableProxyLib.sol";

library NewtonPolicyDeploymentLib {
    using stdJson for *;
    using Strings for *;

    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    error NewtonPolicyLib__PolicyParamNotFound();
    error NewtonPolicyLib__PolicyUrisNotFound();
    error NewtonPolicyLib__DeploymentFileDoesNotExist();
    error NewtonPolicyLib__ContractNotDeployed(string contractName, address contractAddress);

    struct PolicyDeploymentData {
        address proxyAdmin;
        address policy;
        address policyImplementation;
    }

    struct CoreDeploymentData {
        address proxyAdmin;
        address newtonProverServiceManager;
        address newtonProverTaskManager;
        address policyFactory;
        address policyFactoryImpl;
        address policyDataFactory;
        address policyDataFactoryImpl;
    }

    function deployPolicy(
        address owner,
        NewtonPolicyDeploymentLib.CoreDeploymentData memory deploymentData,
        string memory policyUrisPath
    ) internal returns (PolicyDeploymentData memory) {
        require(VM.exists(policyUrisPath), NewtonPolicyLib__PolicyUrisNotFound());

        address policyFactory = deploymentData.policyFactory;
        address policyDataFactory = deploymentData.policyDataFactory;

        NewtonPolicyLib.PolicyUris memory policyUris =
            NewtonPolicyLib.readPolicyUris(policyUrisPath);

        uint256 expireAfter = 4 minutes;

        address[] memory attesters = new address[](1);

        // solhint-disable-next-line no-console
        attesters[0] = policyUris.attester;

        address policyData = NewtonPolicyDataFactory(policyDataFactory).deployPolicyData(
            policyUris.policyDataLocation,
            policyUris.policyDataArgs,
            uint32(expireAfter),
            policyUris.policyDataMetadataUri,
            owner
        );

        INewtonPolicyData(policyData).setAttestationInfo(
            INewtonPolicyData.AttestationInfo({
                attesters: attesters,
                attestationType: INewtonPolicyData.AttestationType.ECDSA,
                verifier: address(0),
                verificationKey: bytes32(0)
            })
        );

        address[] memory policyDataArray = new address[](1);
        policyDataArray[0] = policyData;

        address policy = NewtonPolicyFactory(policyFactory).deployPolicy(
            policyUris.entrypoint,
            policyUris.policyUri,
            policyUris.schemaUri,
            policyDataArray,
            policyUris.policyMetadataUri,
            owner
        );
        address policyImplementation = NewtonPolicyFactory(policyFactory).implementation();

        return PolicyDeploymentData({
            proxyAdmin: deploymentData.proxyAdmin,
            policy: policy,
            policyImplementation: policyImplementation
        });
    }

    function readCoreDeploymentJson(
        uint256 chainId
    ) internal returns (CoreDeploymentData memory) {
        return _readCoreDeploymentJson("script/deployments/newton-prover/", chainId);
    }

    function _readCoreDeploymentJson(
        string memory directoryPath,
        uint256 chainId
    ) internal returns (CoreDeploymentData memory) {
        string memory fileName = string.concat(directoryPath, VM.toString(chainId), ".json");

        require(VM.exists(fileName), NewtonPolicyLib__DeploymentFileDoesNotExist());

        string memory json = VM.readFile(fileName);

        CoreDeploymentData memory data;
        data.proxyAdmin = json.readAddress(".addresses.proxyAdmin");
        data.newtonProverServiceManager = json.readAddress(".addresses.newtonProverServiceManager");
        data.newtonProverTaskManager = json.readAddress(".addresses.newtonProverTaskManager");
        data.policyFactory = json.readAddress(".addresses.policyFactory");
        data.policyFactoryImpl = json.readAddress(".addresses.policyFactoryImpl");
        data.policyDataFactory = json.readAddress(".addresses.policyDataFactory");
        data.policyDataFactoryImpl = json.readAddress(".addresses.policyDataFactoryImpl");

        return data;
    }

    /// write to default output path
    function writePolicyDeploymentJson(
        PolicyDeploymentData memory data
    ) internal {
        writePolicyDeploymentJson("script/deployments/policy/", block.chainid, data);
    }

    function writePolicyDeploymentJson(
        string memory outputPath,
        uint256 chainId,
        PolicyDeploymentData memory data
    ) internal {
        address proxyAdmin = data.proxyAdmin;

        string memory deploymentData = _generatePolicyDeploymentJson(data, proxyAdmin);

        string memory fileName = string.concat(outputPath, VM.toString(chainId), ".json");
        if (!VM.exists(outputPath)) {
            VM.createDir(outputPath, true);
        }

        VM.writeFile(fileName, deploymentData);
        // solhint-disable-next-line no-console
        console2.log("Deployment artifacts written to:", fileName);
    }

    function _generatePolicyDeploymentJson(
        PolicyDeploymentData memory data,
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
        PolicyDeploymentData memory data,
        address proxyAdmin
    ) private view returns (string memory) {
        return string.concat(
            '{"proxyAdmin":"',
            proxyAdmin.toHexString(),
            '","policy":"',
            data.policy.toHexString(),
            '","policyImplementation":"',
            data.policyImplementation.toHexString(),
            '"}'
        );
    }

    /// @notice Helper function to validate individual contracts
    function _validateContract(string memory contractName, address contractAddress) private view {
        if (contractAddress == address(0)) {
            revert NewtonPolicyLib__ContractNotDeployed(contractName, contractAddress);
        }

        uint256 codeSize;
        assembly {
            codeSize := extcodesize(contractAddress)
        }

        if (codeSize == 0) {
            revert NewtonPolicyLib__ContractNotDeployed(contractName, contractAddress);
        }

        // solhint-disable-next-line no-console
        console2.log(string.concat("[OK] ", contractName, " validated:"), contractAddress);
    }
}
