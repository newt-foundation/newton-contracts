// SPDX-License-Identifier: MIT

pragma solidity ^0.8.12;

/// @notice Struct that bundles together a task's parameters for validation
struct Task {
    // the unique identifier for the task
    string taskId;
    // the address of the sender of the task
    address msgSender;
    // the address of the target contract for the task
    address target;
    // the value to send with the task
    uint256 value;
    // the encoded signature and arguments for the task
    bytes encodedSigAndArgs;
    // the policy ID associated with the task
    string policyID;
    // the timestamp by which the task must be executed
    uint256 expireByTime;
}

/// @notice Struct that bundles together a signature, a salt for uniqueness, and an expiration time for the signature. Used primarily for stack management.
struct SignatureWithSaltAndExpiry {
    // the signature itself, formatted as a single bytes object
    bytes signature;
    // the salt used to generate the signature
    bytes32 salt;
    // the expiration timestamp (UTC) of the signature
    uint256 expiry;
}

/**
 * @title Minimal interface for a ServiceManager-type contract that forms the single point for an AVS to push updates to EigenLayer
 * @author Newton Labs, Inc
 */
interface INewtonManager {
    /**
     * @notice Sets the metadata URI for the AVS
     * @param _metadataURI is the metadata URI for the AVS
     */
    function setMetadataURI(
        string memory _metadataURI
    ) external;

    /**
     * @notice Sets a policy ID for the sender, defining execution rules or parameters for tasks
     * @param policyID string pointing to the policy details
     * @dev Only callable by client contracts or EOAs to associate a policy with their address
     * @dev Emits a SetPolicy event upon successful association
     */
    function setPolicy(
        string memory policyID
    ) external;

    /**
     * @notice Deploys a policy with ID with execution rules or parameters for tasks
     * @param _policyID string pointing to the policy details
     * @param _policy string containing the policy details
     * @dev Only callable by service manager deployer
     * @dev Emits a DeployedPolicy event upon successful deployment
     */
    function deployPolicy(string memory _policyID, string memory _policy) external;

    /**
     * @notice Gets array of deployed policies
     */
    function getDeployedPolicies() external view returns (string[] memory);

    /**
     * @notice Verifies if a task is authorized by the required number of operators
     * @param _task Parameters of the task including sender, target, function signature, arguments, and expiry block
     * @param input the input data for the task
     * @param proof the proof for the task
     * @return isVerified Boolean indicating if the task has been verified by the required number of operators
     */
    function verify(
        Task memory _task,
        bytes memory input,
        bytes memory proof
    ) external returns (bool isVerified);
}
