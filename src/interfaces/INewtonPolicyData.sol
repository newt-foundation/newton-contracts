// SPDX-License-Identifier: MIT

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
        string metadataUri;
        string policyDataLocation;
        string policyDataArgs;
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
     * @notice Retrieves the metadata URI for the policy.
     * @return The metadata URI for the policy.
     */
    function getMetadataUri() external view returns (string memory);

    /**
     * @notice Sets the metadata URI for the policy data.
     * @param metadataUri The metadata URI to set for the policy data.
     */
    function setMetadataUri(
        string calldata metadataUri
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
     * @notice Retrieves the policy data location (IPFS URL for WASM plugin).
     * @return The policy data location for the policy data contract.
     */
    function getPolicyDataLocation() external view returns (string memory);

    /**
     * @notice Retrieves the policy data arguments location (IPFS URL for WASM plugin args).
     * @return The policy data arguments location for the policy data contract.
     */
    function getPolicyDataArgs() external view returns (string memory);

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
}
