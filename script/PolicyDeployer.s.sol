// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import "forge-std/Test.sol";

import {NewtonPolicyDeploymentLib} from "./utils/NewtonPolicyDeploymentLib.sol";
import {NewtonPolicyLib} from "./utils/NewtonPolicyLib.sol";
import {AdminLib} from "../script/utils/AdminLib.sol";

// # To deploy and verify our contract
// forge script script/PolicyDeployer.s.sol:PolicyDeployer --rpc-url $RPC_URL  --private-key $PRIVATE_KEY --broadcast -vvvv

// solhint-disable-next-line max-states-count
contract PolicyDeployer is Script {
    address internal _deployer;
    string internal _policyCidsPath;

    error PolicyCidsPathNotSet();

    function setUp() public virtual {
        _deployer = vm.rememberKey(vm.envUint("PRIVATE_KEY"));
        vm.label(_deployer, "Deployer");

        string memory policyCidsPath = vm.envString("POLICY_CIDS_PATH");
        require(bytes(policyCidsPath).length > 0, PolicyCidsPathNotSet());
        _policyCidsPath = policyCidsPath;
    }

    function run() external {
        vm.startBroadcast(_deployer);

        NewtonPolicyDeploymentLib.DeploymentData memory deploymentData =
            NewtonPolicyDeploymentLib.readDeploymentJson(block.chainid);

        // Read policy cids from file
        NewtonPolicyLib.PolicyCids memory policyCids =
            NewtonPolicyLib.readPolicyCids(_policyCidsPath);

        string memory taskGeneratorsPath =
            string.concat("script/deployments/config/", vm.toString(block.chainid), ".json");

        address[] memory taskGenerators =
            AdminLib.readAddresses(taskGeneratorsPath, true).taskGenerator;

        NewtonPolicyDeploymentLib.DeploymentData memory policyDeploymentData =
        NewtonPolicyDeploymentLib.deployPolicy(
            _deployer, deploymentData, policyCids, taskGenerators, uint32(600 seconds)
        );

        // solhint-disable-next-line no-console
        console2.log(_prettyPrintDeploymentJson(policyDeploymentData));

        vm.stopBroadcast();
    }

    function _prettyPrintDeploymentJson(
        NewtonPolicyDeploymentLib.DeploymentData memory deploymentData
    ) private pure returns (string memory) {
        string memory json = "{\n";
        json = string.concat(json, "  \"policy\": \"", vm.toString(deploymentData.policy), "\",\n");
        json = string.concat(
            json, "  \"policyData\": \"", vm.toString(deploymentData.policyData), "\",\n"
        );
        json = string.concat(json, "}");

        return json;
    }
}
