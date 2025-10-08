// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {stdJson} from "forge-std/StdJson.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

library ArrayLib {
    using stdJson for *;
    using Strings for *;

    function removeFromArray(
        address[] memory addresses,
        address[] memory addressesToRemove
    ) internal pure returns (address[] memory) {
        // First remove all specified addresses
        address[] memory filteredAddresses = new address[](addresses.length);
        uint256 filteredIndex = 0;

        for (uint256 k = 0; k < addresses.length; k++) {
            bool shouldRemove = false;
            for (uint256 i = 0; i < addressesToRemove.length; i++) {
                if (addresses[k] == addressesToRemove[i]) {
                    shouldRemove = true;
                    break;
                }
            }
            if (!shouldRemove) {
                filteredAddresses[filteredIndex] = addresses[k];
                filteredIndex++;
            }
        }

        // Create array with correct size for filtered addresses
        address[] memory tempFiltered = new address[](filteredIndex);
        for (uint256 k = 0; k < filteredIndex; k++) {
            tempFiltered[k] = filteredAddresses[k];
        }

        // Then remove duplicates from the filtered array
        return removeDuplicates(tempFiltered);
    }

    function addToArray(
        address[] memory addresses,
        address[] memory addressesToAdd
    ) internal pure returns (address[] memory) {
        // First, remove duplicates from existing array
        address[] memory deduplicatedAddresses = removeDuplicates(addresses);

        // Combine existing addresses with new addresses
        address[] memory combined =
            new address[](deduplicatedAddresses.length + addressesToAdd.length);

        // Copy existing addresses
        for (uint256 k = 0; k < deduplicatedAddresses.length; k++) {
            combined[k] = deduplicatedAddresses[k];
        }

        // Add new addresses
        for (uint256 i = 0; i < addressesToAdd.length; i++) {
            combined[deduplicatedAddresses.length + i] = addressesToAdd[i];
        }

        // Remove duplicates from the combined array
        return removeDuplicates(combined);
    }

    function removeDuplicates(
        address[] memory addresses
    ) internal pure returns (address[] memory) {
        if (addresses.length == 0) {
            return addresses;
        }

        address[] memory temp = new address[](addresses.length);
        uint256 uniqueCount = 0;

        for (uint256 i = 0; i < addresses.length; i++) {
            bool isDuplicate = false;
            for (uint256 j = 0; j < uniqueCount; j++) {
                if (addresses[i] == temp[j]) {
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) {
                temp[uniqueCount] = addresses[i];
                uniqueCount++;
            }
        }

        // Create final array with correct size
        address[] memory result = new address[](uniqueCount);
        for (uint256 k = 0; k < uniqueCount; k++) {
            result[k] = temp[k];
        }

        return result;
    }
}
