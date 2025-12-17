// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

library NewtonPolicyLib {
    using stdJson for *;
    using Strings for *;

    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    error NewtonPolicyLib__PolicyParamNotFound();
    error NewtonPolicyLib__PolicyCidsNotFound();

    struct PolicyCids {
        string wasmCid;
        address attester;
        string policyCid;
        string schemaCid;
        string entrypoint;
        string policyDataMetadataCid;
        string policyMetadataCid;
        string secretsSchemaCid;
    }

    function readPolicyCids(
        string memory path
    ) internal returns (PolicyCids memory) {
        return _readPolicyCids(path);
    }

    function readPolicyParam(
        string memory path
    ) internal returns (string memory) {
        return _readPolicyParam(path);
    }

    function _readPolicyCids(
        string memory path
    ) internal returns (PolicyCids memory) {
        require(VM.exists(path), NewtonPolicyLib__PolicyCidsNotFound());
        string memory json = VM.readFile(path);

        PolicyCids memory data;
        data.wasmCid = json.readString(".wasmCid");
        data.attester = json.readAddress(".attester");
        data.policyCid = json.readString(".policyCid");
        data.schemaCid = json.readString(".schemaCid");
        data.entrypoint = json.readString(".entrypoint");
        data.policyDataMetadataCid = json.readString(".policyDataMetadataCid");
        data.policyMetadataCid = json.readString(".policyMetadataCid");
        data.secretsSchemaCid = json.readString(".secretsSchemaCid");
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
