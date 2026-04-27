// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

/// @notice Interface for a NewtonPolicyData
interface INewtonPolicyData is IERC165 {
    struct PolicyDataInfo {
        address policyDataAddress;
        address owner;
        string metadataCid;
        string wasmCid;
        string secretsSchemaCid;
        uint32 expireAfter;
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
