// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
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

    function readAddresses(string memory path, bool add) internal returns (AdminAddresses memory) {
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
}
