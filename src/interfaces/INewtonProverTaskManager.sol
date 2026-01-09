// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@eigenlayer-middleware/src/libraries/BN254.sol";
import {IBLSSignatureChecker} from "@eigenlayer-middleware/src/interfaces/IBLSSignatureChecker.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";
import {INewtonPolicy} from "./INewtonPolicy.sol";

interface INewtonProverTaskManager {
    // EVENTS
    event NewTaskCreated(bytes32 indexed taskId, Task task);

    event TaskResponded(TaskResponse taskResponse, ResponseCertificate responseCertificate);

    event TaskChallengedSuccessfully(bytes32 indexed taskId, address indexed challenger);

    event TaskChallengedUnsuccessfully(bytes32 indexed taskId, address indexed challenger);

    event AttestationSpent(bytes32 indexed taskId, NewtonMessage.Attestation attestation);

    event AggregatorUpdated(address indexed previousAggregator, address indexed newAggregator);

    // STRUCTS
    // task submitter decides on the criteria for a task to be completed
    // note that this does not mean the task was "correctly" answered (i.e. the number was proved correctly)
    //      this is for the challenge logic to verify
    // task is completed (and contract will accept its TaskResponse) when each quorumNumbers specified here
    // are signed by at least quorumThresholdPercentage of the operators
    // note that we set the quorumThresholdPercentage to be the same for all quorumNumbers, but this could be changed
    struct Task {
        // the unique identifier for the task
        bytes32 taskId;
        // policy id
        bytes32 policyId;
        // policy client address
        address policyClient;
        // the nonce of the task
        uint32 nonce;
        // the block number when the task was created
        uint32 taskCreatedBlock;
        // the quorum threshold percentage of the task
        uint32 quorumThresholdPercentage;
        // the intent of the task
        NewtonMessage.Intent intent;
        // the signature of the intent by the intent creator
        bytes intentSignature;
        // the policy task data of the task
        NewtonMessage.PolicyTaskData policyTaskData;
        // policy configuration for the policy program
        INewtonPolicy.PolicyConfig policyConfig;
        // the quorum numbers of the task
        bytes quorumNumbers;
    }

    /// Parameters for creating a new task (passed as a single struct to avoid stack-too-deep)
    struct TaskParams {
        // task id
        bytes32 taskId;
        // task request WASM args
        bytes wasmArgs;
        // policy client address
        address policyClient;
        // intent
        NewtonMessage.Intent intent;
        // signature of the intent by the intent creator
        bytes intentSignature;
        // policy task data
        NewtonMessage.PolicyTaskData policyTaskData;
        // quorum numbers
        bytes quorumNumbers;
        // quorum threshold percentage
        uint32 quorumThresholdPercentage;
    }

    // Task response is hashed and signed by operators.
    // these signatures are aggregated and sent to the contract as response.
    struct TaskResponse {
        // Can be obtained by the operator from the event NewTaskCreated.
        bytes32 taskId;
        // policy client address
        address policyClient;
        // policy id of the task
        bytes32 policyId;
        // the policy address of the task
        address policyAddress;
        // the intent of the task
        NewtonMessage.Intent intent;
        // the signature of the intent by the intent creator
        bytes intentSignature;
        // Policy evaluation result.
        bytes evaluationResult;
    }

    // Certificate is filled by the protocol contract for each taskResponse signed by operators.
    // This Certificate is used by policy clients to attest the validity of policy evaluation result
    // during intent execution.
    // This certificate is also used by the challenger, who monitors and if invalid, raises challenge
    // with zero-knowledge proof of the policy evaluation result discrepancy.
    // NOTE: this can be used as an attestation for not just single chain but multi-chain attestation.
    struct ResponseCertificate {
        // the block number when the response certificate is created
        uint32 referenceBlock;
        // the block number when the task response expires
        uint32 responseExpireBlock;
        // the hash of the non-signers
        bytes32 hashOfNonSigners;
        // encoded signature data (NonSignerStakesAndSignature for source chains, BN254Certificate for destination)
        bytes signatureData;
    }

    // Challenge data is submitted by the challenger.
    // Contains the proof data and verification key for onchain verification of the policy evaluation result.
    // TODO: add support for risc0 zk proofs, and other proof types.
    struct ChallengeData {
        // Can be obtained by the operator from the event NewTaskCreated.
        bytes32 taskId;
        // sp1 zk proof to attest the policy evaluation result of the challenger
        bytes proof;
        // The committed proof output to verify against the task response data.
        bytes data;
    }

    // FUNCTIONS
    // NOTE: this function creates new task.
    function createNewTask(
        TaskParams calldata params
    ) external;

    // NOTE: this function responds to existing tasks.
    function respondToTask(
        Task calldata task,
        TaskResponse calldata taskResponse,
        bytes calldata signatureData
    ) external;

    // NOTE: this function raises challenge to existing tasks.
    function raiseAndResolveChallenge(
        Task calldata task,
        TaskResponse calldata taskResponse,
        ResponseCertificate calldata responseCertificate,
        ChallengeData calldata challenge,
        BN254.G1Point[] calldata pubkeysOfNonSigningOperators
    ) external;

    // NOTE: this function authorizes existing task responses.
    function validateAttestation(
        NewtonMessage.Attestation calldata attestation
    ) external returns (bool);

    // NOTE: this function validates attestation directly by verifying BLS signatures
    // without waiting for respondToTask to be called.
    function validateAttestationDirect(
        Task calldata task,
        TaskResponse calldata taskResponse,
        IBLSSignatureChecker.NonSignerStakesAndSignature calldata nonSignerStakesAndSignature
    ) external returns (bool);

    // NOTE: this function challenges directly verified attestations when respondToTask
    // was never called after the taskResponseWindow has passed.
    function challengeDirectlyVerifiedAttestation(
        Task calldata task,
        TaskResponse calldata taskResponse,
        IBLSSignatureChecker.NonSignerStakesAndSignature calldata nonSignerStakesAndSignature
    ) external;

    // NOTE: getter functions for public mappings
    function taskHash(
        bytes32 taskId
    ) external view returns (bytes32);
    function taskResponseHash(
        bytes32 taskId
    ) external view returns (bytes32);
}
