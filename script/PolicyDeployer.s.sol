// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import "forge-std/Test.sol";

import {NewtonProverDeploymentLib} from "./utils/NewtonProverDeploymentLib.sol";
import {NewtonPolicyDeploymentLib} from "./utils/NewtonPolicyDeploymentLib.sol";

// # To deploy and verify our contract
// forge script script/PolicyDeployer.s.sol:PolicyDeployer --rpc-url $RPC_URL  --private-key $PRIVATE_KEY --broadcast -vvvv

// solhint-disable-next-line max-states-count
contract PolicyDeployer is Script {
    address internal _deployer;
    string internal _policyCidsPath;

    error policyCidsPathNotSet();

    function setUp() public virtual {
        _deployer = vm.rememberKey(vm.envUint("PRIVATE_KEY"));
        vm.label(_deployer, "Deployer");

        string memory policyCidsPath = vm.envString("POLICY_CIDS_PATH");
        require(bytes(policyCidsPath).length > 0, policyCidsPathNotSet());
        _policyCidsPath = policyCidsPath;
    }

    function run() external {
        vm.startBroadcast(_deployer);

        NewtonProverDeploymentLib.DeploymentData memory deploymentData =
            NewtonProverDeploymentLib.readDeploymentJson(block.chainid);

        NewtonPolicyDeploymentLib.DeploymentData memory policyDeploymentData =
            NewtonPolicyDeploymentLib.deployPolicy(_deployer, deploymentData, _policyCidsPath);

        // solhint-disable-next-line no-console
        console2.log("Policy:", address(policyDeploymentData.policy));
        // solhint-disable-next-line no-console
        console2.log("Policy Implementation:", address(policyDeploymentData.policyImplementation));

        vm.stopBroadcast();
    }
}
