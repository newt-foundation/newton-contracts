// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Test.sol";

import {NewtonPolicyDeploymentLib} from "./utils/NewtonPolicyDeploymentLib.sol";
import {BasePolicyDeployer} from "./utils/BasePolicyDeployer.sol";

// # To deploy and verify our contract
// forge script script/PolicyDeployer.s.sol:PolicyDeployer --rpc-url $RPC_URL  --private-key $PRIVATE_KEY --broadcast -vvvv

/// @title PolicyDeployer
/// @notice Deploys a new policy and policy data using existing factories.
/// @dev For production use - does not deploy MockNewtonPolicyClient.
contract PolicyDeployer is BasePolicyDeployer {
    error PolicyCidsPathNotSet();

    function setUp() public virtual {
        _loadDeployer();

        // Policy CIDs path is required for production deployments
        string memory policyCidsPath = vm.envString("POLICY_CIDS_PATH");
        require(bytes(policyCidsPath).length > 0, PolicyCidsPathNotSet());
        _policyCidsPath = policyCidsPath;

        // Operators config path defaults to newton_prover_config based on environment
        string memory env = vm.envOr("DEPLOYMENT_ENV", string("stagef"));
        _loadOperatorsConfigPath(string.concat("newton_prover_config.", env, ".json"));
    }

    function run() external {
        vm.startBroadcast(_deployer);

        NewtonPolicyDeploymentLib.DeploymentData memory existingData = _readAndVerifyFactories();

        NewtonPolicyDeploymentLib.DeploymentData memory policyDeploymentData =
            NewtonPolicyDeploymentLib.deployPolicy(
                _deployer, existingData, _readPolicyCids(), _readOperators(), uint32(300 seconds)
            );

        // solhint-disable-next-line no-console
        console2.log(_prettyPrintDeploymentJson(policyDeploymentData));

        vm.stopBroadcast();
    }
}
