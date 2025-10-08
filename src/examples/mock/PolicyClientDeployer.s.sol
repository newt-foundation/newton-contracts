// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import "forge-std/Test.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import {DeploymentLib} from "../../../script/utils/DeploymentLib.sol";
import {MockNewtonPolicyClient} from "./MockNewtonPolicyClient.sol";
import {INewtonPolicy} from "../../interfaces/INewtonPolicy.sol";
import {NewtonPolicyLib} from "../../../script/utils/NewtonPolicyLib.sol";
import {UpgradeableProxyLib} from "../../../script/utils/UpgradeableProxyLib.sol";

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

    struct DeploymentData {
        address policyAddress;
        bytes32 policyId;
        address policyClient;
        address policyClientImpl;
        address policyClientOwner;
    }

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

        DeploymentLib.DeploymentData memory deploymentData =
            DeploymentLib.readDeploymentJson(block.chainid);

        address newtonProverTaskManager = deploymentData.newtonProverTaskManager;

        address policyClient = UpgradeableProxyLib.setUpEmptyProxy(_proxyAdmin);
        address policyClientImpl = address(new MockNewtonPolicyClient());
        bytes memory upgradeCall = abi.encodeCall(
            MockNewtonPolicyClient.initialize, (newtonProverTaskManager, _policyAddress, _deployer)
        );
        UpgradeableProxyLib.upgradeAndCall(policyClient, policyClientImpl, upgradeCall);

        string memory policyParams = NewtonPolicyLib.readPolicyParam(_policyParamPath);
        uint256 expireAfter = 1 minutes;
        bytes32 policyId = MockNewtonPolicyClient(policyClient).setPolicy(
            INewtonPolicy.PolicyConfig({
                policyParams: bytes(policyParams),
                expireAfter: uint32(expireAfter)
            })
        );

        DeploymentData memory _deploymentData = DeploymentData({
            policyAddress: _policyAddress,
            policyId: policyId,
            policyClient: policyClient,
            policyClientImpl: policyClientImpl,
            policyClientOwner: _deployer
        });

        // solhint-disable-next-line no-console
        console2.log(_prettyPrintDeploymentJson(_deploymentData));

        vm.stopBroadcast();
    }

    function _prettyPrintDeploymentJson(
        DeploymentData memory deploymentData
    ) private pure returns (string memory) {
        string memory json = "{\n";
        json = string.concat(
            json, "  \"policyAddress\": \"", vm.toString(deploymentData.policyAddress), "\",\n"
        );
        json = string.concat(
            json,
            "  \"policyId\": \"",
            Strings.toHexString(uint256(deploymentData.policyId)),
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
        json = string.concat(
            json,
            "  \"policyClientOwner\": \"",
            vm.toString(deploymentData.policyClientOwner),
            "\",\n"
        );
        json = string.concat(json, "}");

        return json;
    }
}
