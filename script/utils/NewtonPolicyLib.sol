// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

library NewtonPolicyLib {
    using stdJson for *;
    using Strings for *;

    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    error NewtonPolicyLib__PolicyParamNotFound();
    error NewtonPolicyLib__PolicyUrisNotFound();

    struct PolicyUris {
        string policyDataLocation;
        string policyDataArgs;
        address attester;
        string policyUri;
        string schemaUri;
        string entrypoint;
        string policyDataMetadataUri;
        string policyMetadataUri;
    }

    function readPolicyUris(
        string memory path
    ) internal returns (PolicyUris memory) {
        return _readPolicyUris(path);
    }

    function readPolicyParam(
        string memory path
    ) internal returns (string memory) {
        return _readPolicyParam(path);
    }

    function _readPolicyUris(
        string memory path
    ) internal returns (PolicyUris memory) {
        require(VM.exists(path), NewtonPolicyLib__PolicyUrisNotFound());
        string memory json = VM.readFile(path);

        PolicyUris memory data;
        data.policyDataLocation = json.readString(".policyDataLocation");
        data.policyDataArgs = json.readString(".policyDataArgs");
        data.attester = json.readAddress(".attester");
        data.policyUri = json.readString(".policyUri");
        data.schemaUri = json.readString(".schemaUri");
        data.entrypoint = json.readString(".entrypoint");
        data.policyDataMetadataUri = json.readString(".policyDataMetadataUri");
        data.policyMetadataUri = json.readString(".policyMetadataUri");
        return data;
    }

    function _readPolicyParam(
        string memory path
    ) internal returns (string memory) {
        require(VM.exists(path), NewtonPolicyLib__PolicyParamNotFound());
        string memory json = VM.readFile(path);
        return json;
    }
}
