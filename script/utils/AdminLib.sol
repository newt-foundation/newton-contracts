// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {OperatorRegistry} from "../../src/middlewares/OperatorRegistry.sol";
import {NewtonPolicyFactory} from "../../src/core/NewtonPolicyFactory.sol";
import {NewtonPolicyDataFactory} from "../../src/core/NewtonPolicyDataFactory.sol";
import {NewtonPolicyData} from "../../src/core/NewtonPolicyData.sol";
import {INewtonPolicyData} from "../../src/interfaces/INewtonPolicyData.sol";
import {ArrayLib} from "./ArrayLib.sol";

library AdminLib {
    using stdJson for *;
    using Strings for *;
    using ArrayLib for address[];

    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    error AddressesFileDoesNotExist();
    error AddressCannotBeZero();

    struct AdminAddresses {
        address[] taskGenerator;
        address[] operator;
        address[] policyVerifier;
        address[] policyDataVerifier;
        address[] policy;
        address[] policyData;
    }

    function readAddresses(
        string memory path,
        bool add
    ) internal returns (AdminAddresses memory) {
        require(VM.exists(path), AddressesFileDoesNotExist());
        string memory json = VM.readFile(path);
        AdminAddresses memory addresses;
        if (add) {
            addresses.taskGenerator =
                json.readAddressArrayOr(".add.taskGenerator", new address[](0));
            addresses.operator = json.readAddressArrayOr(".add.operator", new address[](0));
            addresses.policyVerifier =
                json.readAddressArrayOr(".add.policyVerifier", new address[](0));
            addresses.policyDataVerifier =
                json.readAddressArrayOr(".add.policyDataVerifier", new address[](0));
            addresses.policy = json.readAddressArrayOr(".add.policy", new address[](0));
            addresses.policyData = json.readAddressArrayOr(".add.policyData", new address[](0));
        } else {
            addresses.taskGenerator =
                json.readAddressArrayOr(".remove.taskGenerator", new address[](0));
            addresses.operator = json.readAddressArrayOr(".remove.operator", new address[](0));
            addresses.policyVerifier =
                json.readAddressArrayOr(".remove.policyVerifier", new address[](0));
            addresses.policyDataVerifier =
                json.readAddressArrayOr(".remove.policyDataVerifier", new address[](0));
            addresses.policy = json.readAddressArrayOr(".remove.policy", new address[](0));
            addresses.policyData = json.readAddressArrayOr(".remove.policyData", new address[](0));
        }
        return addresses;
    }

    function commandInCommands(
        string memory command
    ) internal pure returns (bool) {
        string[7] memory commands = [
            "task_generator",
            "operator",
            "policy_verifier",
            "policy_data_verifier",
            "policy",
            "policy_data",
            "fund_operators"
        ];

        for (uint256 i = 0; i < commands.length; i++) {
            if (keccak256(bytes(commands[i])) == keccak256(bytes(command))) {
                return true;
            }
        }
        return false;
    }

    function updateTaskGenerator(
        address[] memory addresses,
        bool add,
        address operatorRegistry,
        address policyDataFactory,
        address policyDataOwner
    ) internal {
        // Validate all addresses first
        for (uint256 i = 0; i < addresses.length; i++) {
            require(addresses[i] != address(0), AddressCannotBeZero());
        }

        // Update operator registry for each address
        for (uint256 i = 0; i < addresses.length; i++) {
            if (add) {
                if (!OperatorRegistry(operatorRegistry).isTaskGenerator(addresses[i])) {
                    OperatorRegistry(operatorRegistry).addTaskGenerator(addresses[i]);
                    // solhint-disable-next-line no-console
                    console2.log("Task generator added", addresses[i]);
                } else {
                    // solhint-disable-next-line no-console
                    console2.log("Task generator already exists", addresses[i]);
                }
            } else {
                if (OperatorRegistry(operatorRegistry).isTaskGenerator(addresses[i])) {
                    OperatorRegistry(operatorRegistry).removeTaskGenerator(addresses[i]);
                    // solhint-disable-next-line no-console
                    console2.log("Task generator removed", addresses[i]);
                } else {
                    // solhint-disable-next-line no-console
                    console2.log("Task generator does not exist", addresses[i]);
                }
            }
        }

        address[] memory policyDataOwners =
            NewtonPolicyDataFactory(policyDataFactory).getAllPolicyDataOwners();

        if (policyDataOwner != address(0)) {
            policyDataOwners = new address[](1);
            policyDataOwners[0] = policyDataOwner;
        }

        for (uint256 i = 0; i < policyDataOwners.length; i++) {
            // solhint-disable-next-line no-console
            console2.log("Adding to attesters for policy data owner", policyDataOwners[i]);
            // Update policy data attesters
            address[] memory policyData = NewtonPolicyDataFactory(policyDataFactory)
                .getAllPolicyDataByOwner(policyDataOwners[i]);
            for (uint256 j = 0; j < policyData.length; j++) {
                INewtonPolicyData.AttestationInfo memory attestationInfo =
                    NewtonPolicyData(policyData[j]).getAttestationInfo();

                address[] memory updatedAttesters;
                if (add) {
                    updatedAttesters = attestationInfo.attesters.addToArray(addresses);
                } else {
                    updatedAttesters = attestationInfo.attesters.removeFromArray(addresses);
                }

                // solhint-disable-next-line no-console
                console2.log("Updating attesters for policy data", policyData[j]);
                NewtonPolicyData(policyData[j])
                    .setAttestationInfo(
                        INewtonPolicyData.AttestationInfo({
                            attesters: updatedAttesters,
                            attestationType: attestationInfo.attestationType,
                            verifier: attestationInfo.verifier,
                            verificationKey: attestationInfo.verificationKey
                        })
                    );

                if (add) {
                    // solhint-disable-next-line no-console
                    console2.log("Task generators added to policy data attesters", addresses.length);
                } else {
                    // solhint-disable-next-line no-console
                    console2.log(
                        "Task generators removed from policy data attesters", addresses.length
                    );
                }
            }
        }
    }

    function updateOperatorWhitelist(
        address[] memory addresses,
        bool add,
        address operatorRegistry
    ) internal {
        for (uint256 i = 0; i < addresses.length; i++) {
            require(addresses[i] != address(0), AddressCannotBeZero());
            if (add) {
                if (!OperatorRegistry(operatorRegistry).isOperatorWhitelisted(addresses[i])) {
                    OperatorRegistry(operatorRegistry).addToWhitelist(addresses[i]);
                    // solhint-disable-next-line no-console
                    console2.log("Operator added to whitelist", addresses[i]);
                } else {
                    // solhint-disable-next-line no-console
                    console2.log("Operator already in whitelist", addresses[i]);
                }
            } else {
                if (OperatorRegistry(operatorRegistry).isOperatorWhitelisted(addresses[i])) {
                    OperatorRegistry(operatorRegistry).removeFromWhitelist(addresses[i]);
                    // solhint-disable-next-line no-console
                    console2.log("Operator removed from whitelist", addresses[i]);
                } else {
                    // solhint-disable-next-line no-console
                    console2.log("Operator not in whitelist", addresses[i]);
                }
            }
        }
    }

    function updatePolicyVerification(
        address[] memory addresses,
        bool add,
        address policyFactory
    ) internal {
        for (uint256 i = 0; i < addresses.length; i++) {
            require(addresses[i] != address(0), AddressCannotBeZero());
            if (
                NewtonPolicyFactory(policyFactory).getPolicyVerificationInfo(addresses[i]).verified
                    != add
            ) {
                NewtonPolicyFactory(policyFactory).setPolicyVerification(addresses[i], add);
                // solhint-disable-next-line no-console
                console2.log("Policy verification updated", addresses[i], add);
            } else {
                // solhint-disable-next-line no-console
                console2.log("Policy verification already up to date", addresses[i], add);
            }
        }
    }

    function updatePolicyDataVerification(
        address[] memory addresses,
        bool add,
        address policyDataFactory
    ) internal {
        for (uint256 i = 0; i < addresses.length; i++) {
            require(addresses[i] != address(0), AddressCannotBeZero());
            if (
                NewtonPolicyDataFactory(policyDataFactory)
                    .getPolicyDataVerificationInfo(addresses[i])
                    .verified != add
            ) {
                NewtonPolicyDataFactory(policyDataFactory).setPolicyDataVerified(addresses[i], add);
                // solhint-disable-next-line no-console
                console2.log("Policy data verification updated", addresses[i], add);
            } else {
                // solhint-disable-next-line no-console
                console2.log("Policy data verification already up to date", addresses[i], add);
            }
        }
    }

    function updatePolicyVerifier(
        address[] memory addresses,
        bool add,
        address policyFactory
    ) internal {
        for (uint256 i = 0; i < addresses.length; i++) {
            require(addresses[i] != address(0), AddressCannotBeZero());
            if (add) {
                if (!NewtonPolicyFactory(policyFactory).verifiers(addresses[i])) {
                    NewtonPolicyFactory(policyFactory).addVerifier(addresses[i]);
                    // solhint-disable-next-line no-console
                    console2.log("Policy verifier added", addresses[i]);
                } else {
                    // solhint-disable-next-line no-console
                    console2.log("Policy verifier already exists", addresses[i]);
                }
            } else {
                if (NewtonPolicyFactory(policyFactory).verifiers(addresses[i])) {
                    NewtonPolicyFactory(policyFactory).removeVerifier(addresses[i]);
                    // solhint-disable-next-line no-console
                    console2.log("Policy verifier removed", addresses[i]);
                } else {
                    // solhint-disable-next-line no-console
                    console2.log("Policy verifier does not exist", addresses[i]);
                }
            }
        }
    }

    function updatePolicyDataVerifier(
        address[] memory addresses,
        bool add,
        address policyDataFactory
    ) internal {
        for (uint256 i = 0; i < addresses.length; i++) {
            require(addresses[i] != address(0), AddressCannotBeZero());
            if (add) {
                if (!NewtonPolicyDataFactory(policyDataFactory).verifiers(addresses[i])) {
                    NewtonPolicyDataFactory(policyDataFactory).addVerifier(addresses[i]);
                    // solhint-disable-next-line no-console
                    console2.log("Policy data verifier added", addresses[i]);
                } else {
                    // solhint-disable-next-line no-console
                    console2.log("Policy data verifier already exists", addresses[i]);
                }
            } else {
                if (NewtonPolicyDataFactory(policyDataFactory).verifiers(addresses[i])) {
                    NewtonPolicyDataFactory(policyDataFactory).removeVerifier(addresses[i]);
                    // solhint-disable-next-line no-console
                    console2.log("Policy data verifier removed", addresses[i]);
                } else {
                    // solhint-disable-next-line no-console
                    console2.log("Policy data verifier does not exist", addresses[i]);
                }
            }
        }
    }
}
