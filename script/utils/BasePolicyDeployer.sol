// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";

import {NewtonPolicyDeploymentLib} from "./NewtonPolicyDeploymentLib.sol";
import {NewtonPolicyLib} from "./NewtonPolicyLib.sol";
import {DeploymentLib} from "./DeploymentLib.sol";
import {AdminLib} from "./AdminLib.sol";

/// @title BasePolicyDeployer
/// @notice Abstract base contract with shared setup logic for policy deployers.
/// @dev Provides common configuration loading and utility functions.
abstract contract BasePolicyDeployer is Script {
    error FactoriesNotDeployed();

    address internal _deployer;
    string internal _policyCidsPath;
    string internal _policyParamPath;
    string internal _operatorsConfigPath;
    bool internal _upgrade;

    /// @notice Load deployer private key
    function _loadDeployer() internal {
        _deployer = vm.rememberKey(vm.envUint("PRIVATE_KEY"));
        vm.label(_deployer, "Deployer");
    }

    /// @notice Load policy CIDs path with optional default
    function _loadPolicyCidsPath(
        string memory defaultPath
    ) internal {
        try vm.envString("POLICY_CIDS_PATH") returns (string memory envPath) {
            _policyCidsPath = bytes(envPath).length > 0 ? envPath : defaultPath;
        } catch {
            _policyCidsPath = defaultPath;
        }
    }

    /// @notice Load policy params path with optional default
    function _loadPolicyParamPath(
        string memory defaultPath
    ) internal {
        try vm.envString("POLICY_PARAM_PATH") returns (string memory envPath) {
            _policyParamPath = bytes(envPath).length > 0 ? envPath : defaultPath;
        } catch {
            _policyParamPath = defaultPath;
        }
    }

    /// @notice Load operators config path with optional default
    function _loadOperatorsConfigPath(
        string memory defaultPath
    ) internal {
        try vm.envString("OPERATORS_CONFIG_PATH") returns (string memory operatorsConfigPath) {
            _operatorsConfigPath =
                bytes(operatorsConfigPath).length > 0 ? operatorsConfigPath : defaultPath;
        } catch {
            _operatorsConfigPath = defaultPath;
        }
    }

    /// @notice Load upgrade flag from environment
    function _loadUpgradeFlag() internal {
        try vm.envString("UPGRADE") returns (string memory upgrade) {
            _upgrade = keccak256(bytes(upgrade)) == keccak256(bytes("true"));
        } catch {
            _upgrade = false;
        }
    }

    /// @notice Read existing deployment data and verify factories exist
    function _readAndVerifyFactories()
        internal
        returns (NewtonPolicyDeploymentLib.DeploymentData memory)
    {
        NewtonPolicyDeploymentLib.DeploymentData memory existingData =
            NewtonPolicyDeploymentLib.readDeploymentJson(block.chainid);

        require(existingData.policyFactory != address(0), FactoriesNotDeployed());
        require(existingData.policyDataFactory != address(0), FactoriesNotDeployed());

        return existingData;
    }

    /// @notice Read policy CIDs from configured path
    function _readPolicyCids() internal returns (NewtonPolicyLib.PolicyCids memory) {
        return NewtonPolicyLib.readPolicyCids(_policyCidsPath);
    }

    /// @notice Read operators from configured path
    /// @dev Operators are added as attesters since they sign attestations in consensus mode
    function _readOperators() internal returns (address[] memory) {
        return AdminLib.readAddresses(_operatorsConfigPath, block.chainid).operator;
    }

    /// @notice Read task generators from configured path
    /// @dev Task generators are added as attesters since they sign attestations in non-consensus mode
    function _readTaskGenerators() internal returns (address[] memory) {
        return AdminLib.readAddresses(_operatorsConfigPath, block.chainid).taskGenerator;
    }

    /// @notice Read policy params from configured path
    function _readPolicyParams() internal returns (string memory) {
        return NewtonPolicyLib.readPolicyParam(_policyParamPath);
    }

    /// @notice Pretty print deployment data for console output
    function _prettyPrintDeploymentJson(
        NewtonPolicyDeploymentLib.DeploymentData memory deploymentData
    ) internal pure returns (string memory) {
        string memory json = "{\n";

        json = string.concat(
            json, "  \"policyFactory\": \"", vm.toString(deploymentData.policyFactory), "\",\n"
        );
        json = string.concat(
            json,
            "  \"policyFactoryImpl\": \"",
            vm.toString(deploymentData.policyFactoryImpl),
            "\",\n"
        );
        json = string.concat(json, "  \"policy\": \"", vm.toString(deploymentData.policy), "\",\n");
        json = string.concat(
            json,
            "  \"policyImplementation\": \"",
            vm.toString(deploymentData.policyImplementation),
            "\",\n"
        );
        json = string.concat(
            json,
            "  \"policyDataFactory\": \"",
            vm.toString(deploymentData.policyDataFactory),
            "\",\n"
        );
        json = string.concat(
            json,
            "  \"policyDataFactoryImpl\": \"",
            vm.toString(deploymentData.policyDataFactoryImpl),
            "\",\n"
        );
        json = string.concat(
            json, "  \"policyData\": \"", vm.toString(deploymentData.policyData), "\",\n"
        );
        json = string.concat(
            json,
            "  \"policyDataImplementation\": \"",
            vm.toString(deploymentData.policyDataImplementation),
            "\",\n"
        );
        json = string.concat(
            json, "  \"policyClient\": \"", vm.toString(deploymentData.policyClient), "\",\n"
        );
        json = string.concat(
            json,
            "  \"policyClientImpl\": \"",
            vm.toString(deploymentData.policyClientImpl),
            "\",\n"
        );
        json =
            string.concat(json, "  \"policyId\": \"", vm.toString(deploymentData.policyId), "\"\n");
        json = string.concat(json, "}");

        return json;
    }
}
