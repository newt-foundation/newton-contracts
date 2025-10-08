// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IAVSDirectory} from "@eigenlayer/contracts/interfaces/IAVSDirectory.sol";
import {ISocketRegistry, SocketRegistry} from "@eigenlayer-middleware/src/SocketRegistry.sol";
import {ISlashingRegistryCoordinator} from
    "@eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {SlashingRegistryCoordinator} from
    "@eigenlayer-middleware/src/SlashingRegistryCoordinator.sol";
import {IPermissionController} from "@eigenlayer/contracts/interfaces/IPermissionController.sol";
import {IDelegationManager} from "@eigenlayer/contracts/interfaces/IDelegationManager.sol";
import {UpgradeableProxyLib} from "./UpgradeableProxyLib.sol";
import {DeploymentLib} from "./DeploymentLib.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {BLSApkRegistry} from "@eigenlayer-middleware/src/BLSApkRegistry.sol";
import {IndexRegistry} from "@eigenlayer-middleware/src/IndexRegistry.sol";
import {InstantSlasher} from "@eigenlayer-middleware/src/slashers/InstantSlasher.sol";
import {StakeRegistry} from "@eigenlayer-middleware/src/StakeRegistry.sol";
import {IAllocationManager} from "@eigenlayer/contracts/interfaces/IAllocationManager.sol";
import {
    IBLSApkRegistry,
    IIndexRegistry,
    IStakeRegistry
} from "@eigenlayer-middleware/src/SlashingRegistryCoordinator.sol";
import {
    PauserRegistry, IPauserRegistry
} from "@eigenlayer/contracts/permissions/PauserRegistry.sol";
import {OperatorStateRetriever} from "@eigenlayer-middleware/src/OperatorStateRetriever.sol";

library NewtonProverDeploymentLib {
    using stdJson for *;
    using Strings for *;
    using UpgradeableProxyLib for address;

    error BlsApkRegistryNotDeployed();
    error StakeRegistryNotDeployed();
    error DelegationManagerNotDeployed();
    error ContractNotDeployed(string contractName, address contractAddress);
    error ValidationFailed(string reason);

    string internal constant MIDDLEWARE_VERSION = "v1.5.0-testnet-final";
    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @notice Helper function to validate individual contracts
    function _validateContract(string memory contractName, address contractAddress) private view {
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

        // solhint-disable-next-line no-console
        console2.log(string.concat("[OK] ", contractName, " validated:"), contractAddress);
    }

    function verifyDeployment(
        DeploymentLib.DeploymentData memory result
    ) internal view {
        // Core service contracts validation
        _validateContract("NewtonProverServiceManager", result.newtonProverServiceManager);
        _validateContract("NewtonProverTaskManager", result.newtonProverTaskManager);
        _validateContract("OperatorRegistry", result.operatorRegistry);
        _validateContract("ChallengeVerifier", result.challengeVerifier);
        _validateContract("AttestationValidator", result.attestationValidator);

        // Registry contracts validation
        _validateContract("BLSApkRegistry", result.blsApkRegistry);
        _validateContract("IndexRegistry", result.indexRegistry);
        _validateContract("StakeRegistry", result.stakeRegistry);
        _validateContract("SocketRegistry", result.socketRegistry);
        _validateContract("OperatorStateRetriever", result.operatorStateRetriever);

        // Additional infrastructure
        _validateContract("PauserRegistry", result.pauserRegistry);
        _validateContract("Slasher", result.slasher);

        // Verify Eigenlayer Middleware contracts
        IBLSApkRegistry blsapkregistry =
            ISlashingRegistryCoordinator(result.operatorRegistry).blsApkRegistry();
        require(address(blsapkregistry) != address(0), BlsApkRegistryNotDeployed());
        IStakeRegistry stakeregistry =
            ISlashingRegistryCoordinator(result.operatorRegistry).stakeRegistry();
        require(address(stakeregistry) != address(0), StakeRegistryNotDeployed());
        IDelegationManager delegationmanager = IStakeRegistry(address(stakeregistry)).delegation();
        require(address(delegationmanager) != address(0), DelegationManagerNotDeployed());

        // solhint-disable-next-line no-console
        console2.log("[SUCCESS] All contract deployments verified");
    }
}
