// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";

/// @notice Interface for a NewtonPolicyData
interface INewtonPolicyData is IERC165 {
    enum AttestationType {
        ECDSA,
        BN254,
        BLS12_381,
        GROTH16
    }

    struct PolicyDataInfo {
        address policyDataAddress;
        address owner;
        string metadataCid;
        string wasmCid;
        string secretsSchemaCid;
        uint32 expireAfter;
    }

    struct AttestationInfo {
        /// Only used for ECDSA or BLS signature attestation type
        address[] attesters;
        /// The attestation type for the policy data
        AttestationType attestationType;
        /// The verifier contract address. Only used for ZK-SNARK groth16 attestation type
        address verifier;
        /// Only used for ZK-SNARK groth16 attestation type
        bytes32 verificationKey;
    }

    /**
     * @notice Retrieves the metadata CID for the policy.
     * @return The metadata CID for the policy.
     */
    function getMetadataCid() external view returns (string memory);

    /**
     * @notice Sets the metadata CID for the policy data.
     * @param metadataCid The metadata CID to set for the policy data.
     */
    function setMetadataCid(
        string calldata metadataCid
    ) external;

    /**
     * @notice Retrieves the attestation info for the policy.
     * @return The attestation info for the policy.
     */
    function getAttestationInfo() external view returns (AttestationInfo memory);

    /**
     * @notice Sets the attestation info for the policy data.
     * @param attestationInfo The attestation info to set for the policy data.
     */
    function setAttestationInfo(
        AttestationInfo calldata attestationInfo
    ) external;

    /**
     * @notice Retrieves the policy data location (IPFS CID for WASM plugin).
     * @return The policy data location for the policy data contract.
     */
    function getWasmCid() external view returns (string memory);

    /**
     * @notice Retrieves the expire after block number for the policy data.
     * @return The block number after which the policy data should expire.
     */
    function getExpireAfter() external view returns (uint32);

    /**
     * @notice Attest the policy data for the given task.
     * @param policyData The policy data to attest.
     * @return True if the policy data is valid, false otherwise.
     */
    function attest(
        NewtonMessage.PolicyData calldata policyData
    ) external view returns (bool);

    /**
     * @notice Retrieves the policy data verified status.
     * @return The policy data verified status.
     */
    function isPolicyDataVerified() external view returns (bool);

    /**
     * @notice Get the factory contract that deployed this policy data
     * @return The address of the factory contract
     */
    function factory() external view returns (address);
}
