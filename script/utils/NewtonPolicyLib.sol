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
    error NewtonPolicyLib__policyCidsNotFound();

    struct policyCids {
        string wasmCid;
        string wasmArgs;
        address attester;
        string policyCid;
        string schemaCid;
        string entrypoint;
        string policyDataMetadataCid;
        string policyMetadataCid;
    }

    function readpolicyCids(
        string memory path
    ) internal returns (policyCids memory) {
        return _readpolicyCids(path);
    }

    function readPolicyParam(
        string memory path
    ) internal returns (string memory) {
        return _readPolicyParam(path);
    }

    function _readpolicyCids(
        string memory path
    ) internal returns (policyCids memory) {
        require(VM.exists(path), NewtonPolicyLib__policyCidsNotFound());
        string memory json = VM.readFile(path);

        policyCids memory data;
        data.wasmCid = json.readString(".wasmCid");
        data.wasmArgs = json.readString(".wasmArgs");
        data.attester = json.readAddress(".attester");
        data.policyCid = json.readString(".policyCid");
        data.schemaCid = json.readString(".schemaCid");
        data.entrypoint = json.readString(".entrypoint");
        data.policyDataMetadataCid = json.readString(".policyDataMetadataCid");
        data.policyMetadataCid = json.readString(".policyMetadataCid");
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
