// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {INewtonPolicy} from "./INewtonPolicy.sol";

/// @notice Interface for a NewtonPolicyClient-type contract that enables clients to define execution rules or parameters for tasks they submit
interface INewtonPolicyClient is IERC165 {
    /// @notice error for when validate() is called with an incorrect policyID
    error InvalidPolicyID();

    /// @notice One policy in a client's composed set, paired with the config the
    ///         client evaluates it under.
    struct PolicySpec {
        address policy;
        INewtonPolicy.PolicyConfig config;
    }

    /// @notice Emitted whenever a client's policy set is written via `setPolicies`.
    /// @param previousPolicyId The set's id before this write (bytes32(0) at birth).
    /// @param newPolicyId The set's id after this write.
    /// @param revision The set's monotonic revision after this write.
    /// @param policies The new ordered policy set.
    event PoliciesUpdated(
        bytes32 indexed previousPolicyId,
        bytes32 indexed newPolicyId,
        uint64 revision,
        PolicySpec[] policies
    );

    /// @notice Emitted once when a client binds itself to a task manager and an owner.
    /// @param taskManager The task manager the client submits tasks through.
    /// @param owner The account authorized to configure the client.
    event PolicyClientInitialized(address indexed taskManager, address indexed owner);

    /// @notice Emitted whenever a client's owner is replaced.
    /// @param previousOwner The owner before this write (address(0) at birth).
    /// @param newOwner The owner after this write.
    event PolicyClientOwnerUpdated(address indexed previousOwner, address indexed newOwner);

    /// @notice error for when setPolicies is called with an empty policy set
    error EmptyPolicySet();

    /// @notice error for when setPolicies is called with more than MAX_POLICIES entries
    error TooManyPolicies(uint256 given, uint256 max);

    /// @notice error for when a policy address is not a real policy deployed by the
    ///         configured factory
    error PolicyNotRegistered(address policy);

    /// @notice error for when a policy's config has a zero expireAfter
    error ZeroExpireAfter(uint256 index);

    /// @notice error for when a policy carries more than one oracle, which cannot be
    ///         composed under the one-rego-to-one-oracle invariant
    error MultiOracleNotComposable(address policy);

    /// @notice error for when a policy's single oracle child has an empty wasmCid,
    ///         which would make every response to that policy unconditionally revert
    error OracleWithoutWasm(address policy);

    /// @notice error for when the task manager has no policy factory configured
    error PolicyFactoryNotSet();

    /// @notice error for when a policy's params exceed MAX_POLICY_FIELD_BYTES
    error PolicyParamsTooLarge(uint256 index, uint256 size);

    /**
     * @notice Only callable by the owner. Sets the client's ordered policy set.
     * @param policies The new ordered policy set.
     * @return policyId The id of the new policy set.
     */
    function setPolicies(
        PolicySpec[] calldata policies
    ) external returns (bytes32 policyId);

    /**
     * @notice Retrieves the calling address's composed policy set.
     * @return The ordered policy set.
     */
    function getPolicies() external view returns (PolicySpec[] memory);

    /**
     * @notice Retrieves the policyID for the calling address.
     * @return The policyID associated with the calling address.
     */
    function getPolicyId() external view returns (bytes32);

    /**
     * @notice Retrieves the policy set revision for the calling address.
     * @return The monotonic revision of the calling address's policy set.
     */
    function policyRevision() external view returns (uint64);

    /**
     * @notice Retrieves the policyID, revision, and policy set in one call, so a
     *         caller reading all three cannot observe them straddling a
     *         `setPolicies` write.
     * @return policyId The policyID associated with the calling address.
     * @return revision The monotonic revision of the calling address's policy set.
     * @return policies The ordered policy set.
     */
    function getPolicySetSnapshot()
        external
        view
        returns (bytes32 policyId, uint64 revision, PolicySpec[] memory policies);

    /**
     * @notice Function for getting the Newton PolicyTaskManager
     * @return address of the policy task manager
     */
    function getNewtonPolicyTaskManager() external view returns (address);

    /**
     * @notice Retrieves the owner address of the policy client.
     * @return The owner address of the policy client.
     */
    function getOwner() external view returns (address);
}
