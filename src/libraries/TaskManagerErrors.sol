// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/**
 * @title TaskManagerErrors
 * @notice Library containing all error definitions for TaskManager
 * @dev Extracting errors to a library reduces contract bytecode size
 */
library TaskManagerErrors {
    error OnlyAggregator();
    error OnlyTaskGenerator();
    error AttestationHashMismatch();
    error AttestationExpired();
    error AttestationAlreadySpent();
    error InvalidAggregatorAddress();
    error NotDirectlyVerified();
    error InvalidTaskResponseHandler();
}
