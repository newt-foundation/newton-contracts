// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import "forge-std/Test.sol";

import {NewtonPolicyDeploymentLib} from "../script/utils/NewtonPolicyDeploymentLib.sol";

// # To deploy and verify our contract
// forge script script/PolicyDeployer.s.sol:PolicyDeployer --rpc-url $RPC_URL  --private-key $PRIVATE_KEY --broadcast -vvvv

// solhint-disable-next-line max-states-count
contract PolicyDeployer is Script {
    address internal _deployer;
    string internal _policyUrisPath;

    error PolicyUrisPathNotSet();

    function setUp() public virtual {
        _deployer = vm.rememberKey(vm.envUint("PRIVATE_KEY"));
        vm.label(_deployer, "Deployer");

        string memory policyUrisPath = vm.envString("POLICY_URIS_PATH");
        require(bytes(policyUrisPath).length > 0, PolicyUrisPathNotSet());
        _policyUrisPath = policyUrisPath;
    }

    function run() external {
        vm.startBroadcast(_deployer);

        NewtonPolicyDeploymentLib.CoreDeploymentData memory coreDeploymentData =
            NewtonPolicyDeploymentLib.readCoreDeploymentJson(block.chainid);

        NewtonPolicyDeploymentLib.PolicyDeploymentData memory policyDeploymentData =
            NewtonPolicyDeploymentLib.deployPolicy(_deployer, coreDeploymentData, _policyUrisPath);

        // solhint-disable-next-line no-console
        console2.log("Policy:", address(policyDeploymentData.policy));
        // solhint-disable-next-line no-console
        console2.log("Policy Implementation:", address(policyDeploymentData.policyImplementation));

        vm.stopBroadcast();
    }
}
