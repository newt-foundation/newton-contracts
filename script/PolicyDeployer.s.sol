// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import "forge-std/Test.sol";

import {NewtonPolicyDeploymentLib} from "../script/utils/NewtonPolicyDeploymentLib.sol";
import {NewtonPolicyLib} from "../script/utils/NewtonPolicyLib.sol";
import {AdminLib} from "../script/utils/AdminLib.sol";

// # To deploy and verify our contract
// forge script script/PolicyDeployer.s.sol:PolicyDeployer --rpc-url $RPC_URL  --private-key $PRIVATE_KEY --broadcast -vvvv

// solhint-disable-next-line max-states-count
contract PolicyDeployer is Script {
    address internal _deployer;
    string internal _policyCidsPath;
    string internal _taskGeneratorsPath;

    error PolicyCidsPathNotSet();
    error TaskGeneratorsPathNotSet();

    function setUp() public virtual {
        _deployer = vm.rememberKey(vm.envUint("PRIVATE_KEY"));
        vm.label(_deployer, "Deployer");

        string memory policyCidsPath = vm.envString("POLICY_CIDS_PATH");
        require(bytes(policyCidsPath).length > 0, PolicyCidsPathNotSet());
        _policyCidsPath = policyCidsPath;

        try vm.envString("TASK_GENERATORS_PATH") returns (string memory taskGeneratorsPath) {
            _taskGeneratorsPath =
                bytes(taskGeneratorsPath).length > 0 ? taskGeneratorsPath : "admin_script.json";
        } catch {
            _taskGeneratorsPath = "admin_script.json";
        }
    }

    function run() external {
        vm.startBroadcast(_deployer);

        NewtonPolicyDeploymentLib.DeploymentData memory deploymentData =
            NewtonPolicyDeploymentLib.readDeploymentJson(block.chainid);

        // Read policy cids from file
        NewtonPolicyLib.PolicyCids memory policyCids =
            NewtonPolicyLib.readPolicyCids(_policyCidsPath);

        address[] memory taskGenerators =
        AdminLib.readAddresses(_taskGeneratorsPath, block.chainid).taskGenerator;

        NewtonPolicyDeploymentLib.DeploymentData memory policyDeploymentData =
            NewtonPolicyDeploymentLib.deployPolicy(
                _deployer, deploymentData, policyCids, taskGenerators, uint32(300 seconds)
            );

        // solhint-disable-next-line no-console
        console2.log(_prettyPrintDeploymentJson(policyDeploymentData));

        vm.stopBroadcast();
    }

    function _prettyPrintDeploymentJson(
        NewtonPolicyDeploymentLib.DeploymentData memory deploymentData
    ) private pure returns (string memory) {
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
            "\"\n"
        );
        json = string.concat(json, "}");

        return json;
    }
}
