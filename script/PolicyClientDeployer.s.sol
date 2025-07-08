// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import "forge-std/Test.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import {ExamplePolicyClient} from "../src/examples/ExamplePolicyClient.sol";
import {INewtonPolicy} from "../src/interfaces/INewtonPolicy.sol";
import {NewtonPolicyLib} from "./utils/NewtonPolicyLib.sol";
import {UpgradeableProxyLib} from "./utils/UpgradeableProxyLib.sol";
import {NewtonPolicyDeploymentLib} from "./utils/NewtonPolicyDeploymentLib.sol";

// # To deploy and verify our contract
// forge script script/PolicyClientDeployer.s.sol:PolicyClientDeployer --rpc-url $RPC_URL  --private-key $PRIVATE_KEY --broadcast -vvvv

// solhint-disable-next-line max-states-count
contract PolicyClientDeployer is Script {
    using UpgradeableProxyLib for address;

    address internal _deployer;
    address internal _policyAddress;
    string internal _policyParamPath;
    string internal _policyUrisPath;
    address internal _proxyAdmin;

    error PolicyParamPathNotSet();
    error PolicyAddressNotSet();

    function setUp() public virtual {
        _deployer = vm.rememberKey(vm.envUint("PRIVATE_KEY"));
        vm.label(_deployer, "Deployer");

        string memory envPolicyParamPath = vm.envString("POLICY_PARAM_PATH");
        require(bytes(envPolicyParamPath).length > 0, PolicyParamPathNotSet());
        _policyParamPath = envPolicyParamPath;

        address policyAddress = vm.envAddress("POLICY_ADDRESS");
        require(policyAddress != address(0), PolicyAddressNotSet());
        _policyAddress = policyAddress;
    }

    function run() external {
        vm.startBroadcast(_deployer);

        // Deploy ProxyAdmin with the correct owner (the deployer)
        _proxyAdmin = UpgradeableProxyLib.deployProxyAdmin();

        NewtonPolicyDeploymentLib.CoreDeploymentData memory coreDeploymentData =
            NewtonPolicyDeploymentLib.readCoreDeploymentJson(block.chainid);

        address newtonProverTaskManager = coreDeploymentData.newtonProverTaskManager;

        address policyClient = UpgradeableProxyLib.setUpEmptyProxy(_proxyAdmin);
        address policyClientImpl = address(new ExamplePolicyClient());
        bytes memory upgradeCall = abi.encodeCall(
            ExamplePolicyClient.initialize, (newtonProverTaskManager, _policyAddress, _deployer)
        );
        UpgradeableProxyLib.upgradeAndCall(policyClient, policyClientImpl, upgradeCall);

        string memory policyParams = NewtonPolicyLib.readPolicyParam(_policyParamPath);
        uint256 expireAfter = 1 minutes;
        bytes32 policyId = ExamplePolicyClient(policyClient).setPolicy(
            INewtonPolicy.PolicyConfig({
                policyParams: bytes(policyParams),
                expireAfter: uint32(expireAfter)
            })
        );

        // solhint-disable-next-line no-console
        console2.log("Policy:", address(_policyAddress));
        // solhint-disable-next-line no-console
        console2.log("PolicyId:", Strings.toHexString(uint256(policyId)));
        // solhint-disable-next-line no-console
        console2.log("PolicyClient:", address(policyClient));
        // solhint-disable-next-line no-console
        console2.log("PolicyClient Implementation:", address(policyClientImpl));
        // solhint-disable-next-line no-console
        console2.log("PolicyClient Owner:", _deployer);

        vm.stopBroadcast();
    }
}
