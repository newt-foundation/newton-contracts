// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

/// @notice Interface for a NewtonPolicy
/// @dev For Rego policy grammar, refer to https://github.com/microsoft/regorus/blob/main/docs/grammar.md
interface INewtonPolicy is IERC165 {
    struct PolicyConfig {
        bytes policyParams;
        uint32 expireAfter;
    }

    struct SetPolicyInfo {
        bytes32 policyId;
        address policyAddress;
        address owner;
        string policyCid;
        string schemaCid;
        string entrypoint;
        PolicyConfig policyConfig;
        address[] policyData;
    }

    struct PolicyInfo {
        address policyAddress;
        address owner;
        string metadataCid;
        string policyCid;
        string schemaCid;
        string entrypoint;
        address[] policyData;
    }

    /* Events */
    event PolicySet(address indexed client, bytes32 indexed policyId, SetPolicyInfo policy);
    event policyMetadataCidUpdated(string metadataCid);

    /**
     * @notice Retrieves the metadata CID for the policy.
     * @return The metadata CID for the policy.
     */
    function getMetadataCid() external view returns (string memory);

    /**
     * @notice Sets the metadata CID for the policy.
     * @param metadataCid The metadata CID to set for the policy.
     */
    function setMetadataCid(
        string calldata metadataCid
    ) external;

    /**
     * @notice Retrieves the policyID for the calling address.
     * @return The policyID associated with the calling address.
     */
    function getPolicyId(
        address client
    ) external view returns (bytes32);

    /**
     * @notice Retrieves the policy evaluation entrypoint from the Rego policy
     * @return The policy evaluation entrypoint from the Rego policy
     * @dev Expected format is {package}.{output} for the Rego program
     */
    function getEntrypoint() external view returns (string memory);

    /**
     * @notice Retrieves the policy params schema from the Rego policy
     * @return The policy params schema from the Rego policy
     * @dev https://docs.rs/regorus/latest/regorus/struct.Schema.html
     */
    function getSchemaCid() external view returns (string memory);

    /**
     * @notice Retrieves the policy location for the policy.
     * @return The policy location for the policy.
     */
    function getPolicyCid() external view returns (string memory);

    /**
     * @notice Retrieves the policy configuration for the given policyID.
     * @param policyId The policyID to retrieve the policy configuration for.
     * @return The policy configuration for the given policyID.
     */
    function getPolicyConfig(
        bytes32 policyId
    ) external view returns (PolicyConfig memory);

    /**
     * @notice Retrieves the policy data contract addresses.
     * @return The policy data contract addresses.
     */
    function getPolicyData() external view returns (address[] memory);

    /**
     * @notice Retrieves the policy verified status.
     * @return The policy verified status.
     */
    function isPolicyVerified() external view returns (bool);

    /**
     * @notice Get the factory contract that deployed this policy
     * @return The address of the factory contract
     */
    function factory() external view returns (address);
}
