// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;
/* eslint-disable no-console */
// solhint-disable no-console

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
        uint256 chainId
    ) internal returns (AdminAddresses memory) {
        require(VM.exists(path), AddressesFileDoesNotExist());
        string memory json = VM.readFile(path);
        string memory keyPrefix = string.concat(".", Strings.toString(chainId));

        AdminAddresses memory addresses;
        addresses.taskGenerator =
            json.readAddressArrayOr(string.concat(keyPrefix, ".taskGenerator"), new address[](0));
        addresses.operator =
            json.readAddressArrayOr(string.concat(keyPrefix, ".operator"), new address[](0));
        addresses.policyVerifier =
            json.readAddressArrayOr(string.concat(keyPrefix, ".policyVerifier"), new address[](0));
        addresses.policyDataVerifier = json.readAddressArrayOr(
            string.concat(keyPrefix, ".policyDataVerifier"), new address[](0)
        );
        addresses.policy =
            json.readAddressArrayOr(string.concat(keyPrefix, ".policy"), new address[](0));
        addresses.policyData =
            json.readAddressArrayOr(string.concat(keyPrefix, ".policyData"), new address[](0));

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

    // Helper to find diff between two arrays: target - current = toAdd, current - target = toRemove
    function diffAddresses(
        address[] memory target,
        address[] memory current
    ) internal pure returns (address[] memory toAdd, address[] memory toRemove) {
        // Calculate toAdd
        address[] memory tempAdd = new address[](target.length);
        uint256 addCount = 0;
        for (uint256 i = 0; i < target.length; i++) {
            bool found = false;
            for (uint256 j = 0; j < current.length; j++) {
                if (target[i] == current[j]) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                tempAdd[addCount] = target[i];
                addCount++;
            }
        }

        // Resize toAdd
        toAdd = new address[](addCount);
        for (uint256 i = 0; i < addCount; i++) {
            toAdd[i] = tempAdd[i];
        }

        // Calculate toRemove
        address[] memory tempRemove = new address[](current.length);
        uint256 removeCount = 0;
        for (uint256 i = 0; i < current.length; i++) {
            bool found = false;
            for (uint256 j = 0; j < target.length; j++) {
                if (current[i] == target[j]) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                tempRemove[removeCount] = current[i];
                removeCount++;
            }
        }

        // Resize toRemove
        toRemove = new address[](removeCount);
        for (uint256 i = 0; i < removeCount; i++) {
            toRemove[i] = tempRemove[i];
        }
    }

    function syncTaskGenerator(
        address[] memory targetAddresses,
        address operatorRegistry,
        address policyDataFactory
    ) internal {
        address[] memory currentAddresses =
            OperatorRegistry(operatorRegistry).getAllTaskGenerators();
        (address[] memory toAdd, address[] memory toRemove) =
            diffAddresses(targetAddresses, currentAddresses);

        if (toAdd.length > 0) {
            OperatorRegistry(operatorRegistry).addMultipleToTaskGenerators(toAdd);
            console2.log("Added task generators:", toAdd.length);
        }

        for (uint256 i = 0; i < toRemove.length; i++) {
            OperatorRegistry(operatorRegistry).removeTaskGenerator(toRemove[i]);
            console2.log("Removed task generator:", toRemove[i]);
        }

        // Sync PolicyData attesters (task generators sign attestations in non-consensus mode)
        _syncAttesters(toAdd, toRemove, policyDataFactory, "task generator");
    }

    function syncOperatorWhitelist(
        address[] memory targetAddresses,
        address operatorRegistry,
        address policyDataFactory
    ) internal {
        // 1. Sync OperatorRegistry whitelist
        address[] memory currentAddresses =
            OperatorRegistry(operatorRegistry).getAllWhitelistedOperators();
        (address[] memory toAdd, address[] memory toRemove) =
            diffAddresses(targetAddresses, currentAddresses);

        if (toAdd.length > 0) {
            OperatorRegistry(operatorRegistry).addMultipleToWhitelist(toAdd);
            console2.log("Added operators to whitelist:", toAdd.length);
        }

        for (uint256 i = 0; i < toRemove.length; i++) {
            OperatorRegistry(operatorRegistry).removeFromWhitelist(toRemove[i]);
            console2.log("Removed operator from whitelist:", toRemove[i]);
        }

        // 2. Sync PolicyData attesters (operators generate policy data during task evaluation)
        _syncAttesters(toAdd, toRemove, policyDataFactory, "operator");
    }

    /// @notice Internal helper to sync attesters for PolicyData contracts
    /// @dev Used by both syncOperatorWhitelist and syncTaskGenerator
    function _syncAttesters(
        address[] memory toAdd,
        address[] memory toRemove,
        address policyDataFactory,
        string memory attesterType
    ) private {
        if (toAdd.length == 0 && toRemove.length == 0) {
            return;
        }

        address[] memory policyDataOwners =
            NewtonPolicyDataFactory(policyDataFactory).getAllPolicyDataOwners();
        for (uint256 i = 0; i < policyDataOwners.length; i++) {
            address[] memory policyData = NewtonPolicyDataFactory(policyDataFactory)
                .getAllPolicyDataByOwner(policyDataOwners[i]);

            for (uint256 j = 0; j < policyData.length; j++) {
                INewtonPolicyData.AttestationInfo memory attestationInfo =
                    NewtonPolicyData(policyData[j]).getAttestationInfo();

                address[] memory currentAttesters = attestationInfo.attesters;
                address[] memory updatedAttesters = currentAttesters;

                if (toAdd.length > 0) {
                    updatedAttesters = updatedAttesters.addToArray(toAdd);
                }
                if (toRemove.length > 0) {
                    updatedAttesters = updatedAttesters.removeFromArray(toRemove);
                }

                if (
                    keccak256(abi.encode(currentAttesters))
                        != keccak256(abi.encode(updatedAttesters))
                ) {
                    NewtonPolicyData(policyData[j])
                        .setAttestationInfo(
                            INewtonPolicyData.AttestationInfo({
                                attesters: updatedAttesters,
                                attestationType: attestationInfo.attestationType,
                                verifier: attestationInfo.verifier,
                                verificationKey: attestationInfo.verificationKey
                            })
                        );
                    console2.log(
                        "Updated attesters for policy data (", attesterType, "):", policyData[j]
                    );
                }
            }
        }
    }

    function syncPolicyVerifier(
        address[] memory targetAddresses,
        address policyFactory
    ) internal {
        address[] memory currentAddresses = NewtonPolicyFactory(policyFactory).getAllVerifiers();
        (address[] memory toAdd, address[] memory toRemove) =
            diffAddresses(targetAddresses, currentAddresses);

        for (uint256 i = 0; i < toAdd.length; i++) {
            NewtonPolicyFactory(policyFactory).addVerifier(toAdd[i]);
            console2.log("Added policy verifier:", toAdd[i]);
        }

        for (uint256 i = 0; i < toRemove.length; i++) {
            // Check if it's owner before removing (safety check, though contract handles logic)
            NewtonPolicyFactory(policyFactory).removeVerifier(toRemove[i]);
            console2.log("Removed policy verifier:", toRemove[i]);
        }
    }

    function syncPolicyDataVerifier(
        address[] memory targetAddresses,
        address policyDataFactory
    ) internal {
        address[] memory currentAddresses =
            NewtonPolicyDataFactory(policyDataFactory).getAllVerifiers();
        (address[] memory toAdd, address[] memory toRemove) =
            diffAddresses(targetAddresses, currentAddresses);

        for (uint256 i = 0; i < toAdd.length; i++) {
            NewtonPolicyDataFactory(policyDataFactory).addVerifier(toAdd[i]);
            console2.log("Added policy data verifier:", toAdd[i]);
        }

        for (uint256 i = 0; i < toRemove.length; i++) {
            NewtonPolicyDataFactory(policyDataFactory).removeVerifier(toRemove[i]);
            console2.log("Removed policy data verifier:", toRemove[i]);
        }
    }

    function syncPolicyVerification(
        address[] memory targetAddresses, // List of policies that SHOULD be verified
        address policyFactory
    ) internal {
        // 1. Set verified = true for all target addresses
        for (uint256 i = 0; i < targetAddresses.length; i++) {
            if (!NewtonPolicyFactory(policyFactory)
                .getPolicyVerificationInfo(targetAddresses[i])
                .verified) {
                NewtonPolicyFactory(policyFactory).setPolicyVerification(targetAddresses[i], true);
                console2.log("Set policy verified:", targetAddresses[i]);
            }
        }

        // 2. Set verified = false for all other policies that are currently verified
        address[] memory owners = NewtonPolicyFactory(policyFactory).getAllPolicyOwners();
        for (uint256 i = 0; i < owners.length; i++) {
            address[] memory policies =
                NewtonPolicyFactory(policyFactory).getAllPoliciesByOwner(owners[i]);
            for (uint256 j = 0; j < policies.length; j++) {
                address policy = policies[j];
                bool shouldBeVerified = false;
                for (uint256 k = 0; k < targetAddresses.length; k++) {
                    if (targetAddresses[k] == policy) {
                        shouldBeVerified = true;
                        break;
                    }
                }

                if (
                    !shouldBeVerified
                        && NewtonPolicyFactory(policyFactory)
                        .getPolicyVerificationInfo(policy)
                        .verified
                ) {
                    NewtonPolicyFactory(policyFactory).setPolicyVerification(policy, false);
                    console2.log("Set policy unverified:", policy);
                }
            }
        }
    }

    function syncPolicyDataVerification(
        address[] memory targetAddresses, // List of policy data that SHOULD be verified
        address policyDataFactory
    ) internal {
        // 1. Set verified = true for all target addresses
        for (uint256 i = 0; i < targetAddresses.length; i++) {
            if (!NewtonPolicyDataFactory(policyDataFactory)
                .getPolicyDataVerificationInfo(targetAddresses[i])
                .verified) {
                NewtonPolicyDataFactory(policyDataFactory)
                    .setPolicyDataVerified(targetAddresses[i], true);
                console2.log("Set policy data verified:", targetAddresses[i]);
            }
        }

        // 2. Set verified = false for all others
        address[] memory owners =
            NewtonPolicyDataFactory(policyDataFactory).getAllPolicyDataOwners();
        for (uint256 i = 0; i < owners.length; i++) {
            address[] memory policyDataList =
                NewtonPolicyDataFactory(policyDataFactory).getAllPolicyDataByOwner(owners[i]);
            for (uint256 j = 0; j < policyDataList.length; j++) {
                address pd = policyDataList[j];
                bool shouldBeVerified = false;
                for (uint256 k = 0; k < targetAddresses.length; k++) {
                    if (targetAddresses[k] == pd) {
                        shouldBeVerified = true;
                        break;
                    }
                }

                if (
                    !shouldBeVerified
                        && NewtonPolicyDataFactory(policyDataFactory)
                        .getPolicyDataVerificationInfo(pd)
                        .verified
                ) {
                    NewtonPolicyDataFactory(policyDataFactory).setPolicyDataVerified(pd, false);
                    console2.log("Set policy data unverified:", pd);
                }
            }
        }
    }
}
