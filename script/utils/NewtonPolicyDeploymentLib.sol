// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Vm} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {NewtonPolicyDataFactory} from "../../src/core/NewtonPolicyDataFactory.sol";
import {NewtonPolicyFactory} from "../../src/core/NewtonPolicyFactory.sol";
import {INewtonPolicyData} from "../../src/interfaces/INewtonPolicyData.sol";
import {NewtonPolicyLib} from "./NewtonPolicyLib.sol";
import {NewtonProverDeploymentLib} from "./NewtonProverDeploymentLib.sol";

library NewtonPolicyDeploymentLib {
    using stdJson for *;
    using Strings for *;

    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    error NewtonPolicyLib__PolicyParamNotFound();
    error NewtonPolicyLib__policyCidsNotFound();

    struct DeploymentData {
        address policy;
        address policyImplementation;
    }

    function deployPolicy(
        address owner,
        NewtonProverDeploymentLib.DeploymentData memory deploymentData,
        string memory policyCidsPath
    ) internal returns (DeploymentData memory) {
        require(VM.exists(policyCidsPath), NewtonPolicyLib__policyCidsNotFound());

        address policyFactory = deploymentData.policyFactory;
        address policyDataFactory = deploymentData.policyDataFactory;

        NewtonPolicyLib.policyCids memory policyCids =
            NewtonPolicyLib.readpolicyCids(policyCidsPath);

        uint256 expireAfter = 4 minutes;

        address[] memory attesters = new address[](1);

        // solhint-disable-next-line no-console
        attesters[0] = policyCids.attester;

        address policyData = NewtonPolicyDataFactory(policyDataFactory).deployPolicyData(
            policyCids.wasmCid,
            policyCids.wasmArgs,
            uint32(expireAfter),
            policyCids.policyDataMetadataCid,
            owner
        );

        INewtonPolicyData(policyData).setAttestationInfo(
            INewtonPolicyData.AttestationInfo({
                attesters: attesters,
                attestationType: INewtonPolicyData.AttestationType.ECDSA,
                verifier: address(0),
                verificationKey: bytes32(0)
            })
        );

        address[] memory policyDataArray = new address[](1);
        policyDataArray[0] = policyData;

        address policy = NewtonPolicyFactory(policyFactory).deployPolicy(
            policyCids.entrypoint,
            policyCids.policyCid,
            policyCids.schemaCid,
            policyDataArray,
            policyCids.policyMetadataCid,
            owner
        );
        address policyImplementation = NewtonPolicyFactory(policyFactory).implementation();

        return DeploymentData({policy: policy, policyImplementation: policyImplementation});
    }
}
