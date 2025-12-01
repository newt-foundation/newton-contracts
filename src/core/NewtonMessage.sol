// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

/// @notice Contract for a NewtonMessage
contract NewtonMessage {
    // STRUCTS
    /// @notice Intent struct for a transaction authorization
    struct Intent {
        // equivalent to tx.origin/from
        address from;
        // equivalent to to
        address to;
        // equivalent to msg.value
        uint256 value;
        // ABI-encoded calldata. function selector and arguments
        bytes data;
        // chain id of the chain that the transaction is on
        uint256 chainId;
        // encoded ABI of the function that is being called
        // e.g. abi.encodePacked("function transfer(address,uint256)")
        bytes functionSignature;
    }

    /// @notice Attestation struct for a transaction authorization
    struct Attestation {
        // task id
        bytes32 taskId;
        // policy id
        bytes32 policyId;
        // policy client
        address policyClient;
        // expiration block number for the attestation
        uint32 expiration;
        // intent
        Intent intent;
        // signature of the intent by the intent creator
        bytes intentSignature;
    }

    /// @notice PolicyData struct for a policy data and its attestation proof
    struct PolicyData {
        // encoded policy data
        bytes data;
        // attestation proof for the policy data.
        bytes attestation;
        // policy data address
        address policyDataAddress;
        // expiration block number for the policy data
        uint32 expireBlock;
    }

    /// @notice PolicyTaskData struct for a policy data
    struct PolicyTaskData {
        // policy id
        bytes32 policyId;
        // policy address
        address policyAddress;
        // policy program binary
        bytes policy;
        // an array of policy data with attestation
        // NOTE: order matters, the first policy data is the first policy data in the policy data set of the policy.
        PolicyData[] policyData;
    }

    /// @notice VerificationInfo struct for a policy data verification
    struct VerificationInfo {
        // verifier
        address verifier;
        // verified
        bool verified;
        // timestamp
        uint256 timestamp;
    }

    /// @notice error type for unauthorized access
    error Unauthorized(string reason);
}
