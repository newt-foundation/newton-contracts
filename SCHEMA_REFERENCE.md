# Newton Prover AVS Contract Schema Reference

This document provides a comprehensive reference for all structs, enums, constants, and interfaces defined in the Newton Prover AVS contracts located in the `contracts/src` directory.

## Table of Contents

1. [Core Message Types](#core-message-types)
2. [Policy System](#policy-system)
3. [Policy Data System](#policy-data-system)
4. [Task Management](#task-management)
5. [Interfaces](#interfaces)
6. [Constants](#constants)
7. [Enums](#enums)
8. [Error Types](#error-types)

---

## Core Message Types

### Intent Struct

**Location:** `core/NewtonMessage.sol`

Represents a transaction authorization intent.

```solidity
struct Intent {
    address from;              // equivalent to tx.origin/from
    address to;                // equivalent to to
    uint256 value;             // equivalent to msg.value
    bytes data;                // ABI-encoded calldata (function selector and arguments)
    uint256 chainId;           // chain id of the chain that the transaction is on
    bytes functionSignature;   // encoded ABI of the function being called
}
```

**Fields:**

- `from`: The originator of the transaction (equivalent to `tx.origin`)
- `to`: The target address for the transaction
- `value`: The ETH value to be sent (equivalent to `msg.value`)
- `data`: ABI-encoded calldata containing function selector and arguments
- `chainId`: The blockchain network identifier where the transaction occurs
- `functionSignature`: Encoded ABI signature of the function (e.g., `abi.encodePacked("function transfer(address,uint256)")`)

### Attestation Struct

**Location:** `core/NewtonMessage.sol`

Represents a transaction authorization attestation.

```solidity
struct Attestation {
    bytes32 taskId;            // task id
    bytes32 policyId;          // policy id
    address policyClient;      // policy client
    Intent intent;             // intent
    uint32 expiration;         // expiration block number for the attestation
}
```

**Fields:**

- `taskId`: Unique identifier for the associated task
- `policyId`: Identifier for the policy governing this attestation
- `policyClient`: Address of the policy client contract
- `intent`: The transaction intent being attested
- `expiration`: Block number after which the attestation expires

### PolicyData Struct

**Location:** `core/NewtonMessage.sol`

Represents policy data with its attestation proof.

```solidity
struct PolicyData {
    bytes data;                // encoded policy data
    bytes attestation;         // attestation proof for the policy data
    address policyDataAddress; // policy data address
    uint32 expireBlock;        // expiration block number for the policy data
}
```

**Fields:**

- `data`: The encoded policy data content
- `attestation`: Cryptographic proof attesting to the validity of the policy data
- `policyDataAddress`: Address of the policy data contract
- `expireBlock`: Block number after which the policy data expires

### PolicyTaskData Struct

**Location:** `core/NewtonMessage.sol`

Represents comprehensive policy data for task execution.

```solidity
struct PolicyTaskData {
    bytes32 policyId;          // policy id
    address policyAddress;     // policy address
    bytes policy;              // policy program binary
    PolicyData[] policyData;   // array of policy data with attestation
}
```

**Fields:**

- `policyId`: Unique identifier for the policy
- `policyAddress`: Address of the policy contract
- `policy`: Binary representation of the policy program
- `policyData`: Array of policy data entries (order matters - first entry is the first policy data in the policy data set)

### VerificationInfo Struct

**Location:** `core/NewtonMessage.sol`

Represents verification information for policy data.

```solidity
struct VerificationInfo {
    address verifier;          // verifier
    bool verified;             // verified
    uint256 timestamp;         // timestamp
}
```

**Fields:**

- `verifier`: Address of the entity that performed the verification
- `verified`: Boolean indicating whether the item is verified
- `timestamp`: Unix timestamp of when the verification occurred

---

## Policy System

### PolicyConfig Struct

**Location:** `interfaces/INewtonPolicy.sol`

Configuration parameters for a policy.

```solidity
struct PolicyConfig {
    bytes policyParams;        // policy parameters
    uint32 expireAfter;        // expiration time in blocks
}
```

**Fields:**

- `policyParams`: Encoded parameters for the policy
- `expireAfter`: Number of blocks after which the policy configuration expires

### SetPolicyInfo Struct

**Location:** `interfaces/INewtonPolicy.sol`

Information provided when a policy is set.

```solidity
struct SetPolicyInfo {
    bytes32 policyId;          // policy id
    address policyAddress;     // policy address
    address owner;             // owner
    string policyUri;          // policy URI
    string schemaUri;          // schema URI
    string entrypoint;         // entrypoint
    PolicyConfig policyConfig; // policy configuration
    address[] policyData;      // policy data addresses
}
```

**Fields:**

- `policyId`: Unique identifier for the policy
- `policyAddress`: Address of the policy contract
- `owner`: Address of the policy owner
- `policyUri`: URI pointing to the policy location
- `schemaUri`: URI pointing to the policy schema
- `entrypoint`: Policy evaluation entrypoint (format: `{package}.{output}`)
- `policyConfig`: Configuration parameters for the policy
- `policyData`: Array of policy data contract addresses

### PolicyInfo Struct

**Location:** `interfaces/INewtonPolicy.sol`

General information about a policy.

```solidity
struct PolicyInfo {
    address policyAddress;     // policy address
    address owner;             // owner
    string metadataUri;        // metadata URI
    string policyUri;          // policy URI
    string schemaUri;          // schema URI
    string entrypoint;         // entrypoint
    address[] policyData;      // policy data addresses
}
```

**Fields:**

- `policyAddress`: Address of the policy contract
- `owner`: Address of the policy owner
- `metadataUri`: URI pointing to policy metadata
- `policyUri`: URI pointing to the policy location
- `schemaUri`: URI pointing to the policy schema
- `entrypoint`: Policy evaluation entrypoint
- `policyData`: Array of policy data contract addresses

---

## Policy Data System

### PolicyDataInfo Struct

**Location:** `interfaces/INewtonPolicyData.sol`

Information about policy data.

```solidity
struct PolicyDataInfo {
    address policyDataAddress; // policy data address
    address owner;             // owner
    string metadataUri;        // metadata URI
    string policyDataLocation; // policy data location
    string policyDataArgs;     // policy data arguments
    uint32 expireAfter;        // expiration time in blocks
}
```

**Fields:**

- `policyDataAddress`: Address of the policy data contract
- `owner`: Address of the policy data owner
- `metadataUri`: URI pointing to policy data metadata
- `policyDataLocation`: IPFS URL for WASM plugin location
- `policyDataArgs`: IPFS URL for WASM plugin arguments
- `expireAfter`: Number of blocks after which the policy data expires

### AttestationInfo Struct

**Location:** `interfaces/INewtonPolicyData.sol`

Information about how policy data should be attested.

```solidity
struct AttestationInfo {
    address[] attesters;           // Only used for ECDSA or BLS signature attestation
    AttestationType attestationType; // The attestation type for the policy data
    address verifier;              // Verifier contract address (ZK-SNARK groth16 only)
    bytes32 verificationKey;       // Verification key (ZK-SNARK groth16 only)
}
```

**Fields:**

- `attesters`: Array of addresses authorized to attest (used for ECDSA/BLS signature types)
- `attestationType`: Type of attestation required (see AttestationType enum)
- `verifier`: Address of verifier contract (used only for GROTH16 attestation)
- `verificationKey`: Cryptographic verification key (used only for GROTH16 attestation)

---

## Task Management

### Task Struct

**Location:** `interfaces/INewtonProverTaskManager.sol`

Represents a task in the Newton Prover system.

```solidity
struct Task {
    bytes32 taskId;                    // unique identifier for the task
    address policyClient;              // policy client address
    bytes32 policyId;                  // policy id
    uint32 nonce;                      // nonce of the task
    Intent intent;                     // intent of the task
    PolicyTaskData policyTaskData;     // policy task data of the task
    PolicyConfig policyConfig;         // policy configuration for the policy program
    uint32 taskCreatedBlock;           // block number when the task was created
    bytes quorumNumbers;               // quorum numbers of the task
    uint32 quorumThresholdPercentage;  // quorum threshold percentage of the task
}
```

**Fields:**

- `taskId`: Unique identifier for the task
- `policyClient`: Address of the policy client that created the task
- `policyId`: Identifier of the policy governing this task
- `nonce`: Sequential number for task ordering
- `intent`: The transaction intent to be evaluated
- `policyTaskData`: Complete policy data for task execution
- `policyConfig`: Configuration parameters for the policy
- `taskCreatedBlock`: Block number when the task was created
- `quorumNumbers`: Encoded quorum identifiers for operator selection
- `quorumThresholdPercentage`: Minimum percentage of operators required to sign

### TaskResponse Struct

**Location:** `interfaces/INewtonProverTaskManager.sol`

Response to a task, signed by operators.

```solidity
struct TaskResponse {
    bytes32 taskId;             // task identifier
    address policyClient;       // policy client address
    bytes32 policyId;           // policy id of the task
    address policyAddress;      // policy address of the task
    Intent intent;              // intent of the task
    bytes evaluationResult;     // policy evaluation result
}
```

**Fields:**

- `taskId`: Identifier of the task being responded to
- `policyClient`: Address of the policy client
- `policyId`: Identifier of the policy that was evaluated
- `policyAddress`: Address of the policy contract
- `intent`: The transaction intent that was evaluated
- `evaluationResult`: Result of the policy evaluation (encoded boolean or string)

### ResponseCertificate Struct

**Location:** `interfaces/INewtonProverTaskManager.sol`

TaskResponse Certificate for policy clients to attest the validity of policy evaluation result during intent execution.

```solidity
struct ResponseCertificate {
    // the block number when the response certificate is created
    uint32 referenceBlock;
    // the hash of the non-signers
    bytes32 hashOfNonSigners;
    // the non-signers and their stakes
    IBLSSignatureChecker.NonSignerStakesAndSignature nonSignerStakesAndSignature;
    // the block number when the task response expires
    uint32 responseExpireBlock;
}
```

**Fields:**

- `referenceBlock`: Block number when the response was submitted
- `hashOfNonSigners`: Hash of operators who did not sign the response
- `nonSignerStakesAndSignature`: Non-signers and their stakes
- `responseExpireBlock`: Block number after which the response expires

### ChallengeData Struct

**Location:** `interfaces/INewtonProverTaskManager.sol`

Data submitted by challengers to dispute task responses.

```solidity
struct ChallengeData {
    bytes32 taskId;            // task identifier
    bytes proof;               // sp1 zk proof to attest the policy evaluation result
    bytes data;                // committed proof output to verify against task response
}
```

**Fields:**

- `taskId`: Identifier of the task being challenged
- `proof`: Zero-knowledge proof attesting to the challenger's evaluation result
- `data`: The committed proof output used for verification against the task response

---

## Policy Client System

### NewtonPolicyClientStorage Struct

**Location:** `mixins/NewtonPolicyClient.sol`

Storage structure for policy client contracts using ERC-7201 storage pattern.

```solidity
struct NewtonPolicyClientStorage {
    INewtonProverTaskManager policyTaskManager; // task manager contract
    address policy;                             // policy contract address
    bytes32 policyId;                          // policy identifier
    address policyClientOwner;                 // owner of the policy client
}
```

**Fields:**

- `policyTaskManager`: Interface to the Newton Prover Task Manager contract
- `policy`: Address of the associated policy contract
- `policyId`: Unique identifier for the policy
- `policyClientOwner`: Address authorized to manage the policy client

---

## Interfaces

### INewtonPolicy Interface

**Location:** `interfaces/INewtonPolicy.sol`

Main interface for Newton Policy contracts.

**Key Functions:**

- `getMetadataUri()`: Retrieves policy metadata URI
- `setMetadataUri(string)`: Sets policy metadata URI
- `getPolicyId(address)`: Gets policy ID for a client address
- `getEntrypoint()`: Gets policy evaluation entrypoint
- `getSchemaUri()`: Gets policy schema URI
- `getPolicyUri()`: Gets policy location URI
- `getPolicyConfig(bytes32)`: Gets policy configuration by ID
- `getPolicyData()`: Gets array of policy data contract addresses
- `isPolicyVerified()`: Checks if policy is verified

### INewtonPolicyClient Interface

**Location:** `interfaces/INewtonPolicyClient.sol`

Interface for contracts that can submit tasks with policy constraints.

**Key Functions:**

- `getPolicyId()`: Gets the policy ID for the client
- `getPolicyAddress()`: Gets the policy contract address
- `getNewtonPolicyTaskManager()`: Gets the task manager address

### INewtonPolicyData Interface

**Location:** `interfaces/INewtonPolicyData.sol`

Interface for policy data contracts.

**Key Functions:**

- `getMetadataUri()`: Gets policy data metadata URI
- `setMetadataUri(string)`: Sets policy data metadata URI
- `getAttestationInfo()`: Gets attestation configuration
- `setAttestationInfo(AttestationInfo)`: Sets attestation configuration
- `getPolicyDataLocation()`: Gets IPFS URL for WASM plugin
- `getPolicyDataArgs()`: Gets IPFS URL for WASM plugin arguments
- `getExpireAfter()`: Gets expiration block count
- `attest(PolicyData)`: Validates policy data attestation
- `isPolicyDataVerified()`: Checks if policy data is verified

### INewtonProverTaskManager Interface

**Location:** `interfaces/INewtonProverTaskManager.sol`

Main interface for task management in the Newton Prover system.

**Key Functions:**

- `createNewTask(...)`: Creates a new task for policy evaluation
- `latestNonce()`: Gets the latest task nonce
- `respondToTask(...)`: Submits a response to an existing task
- `raiseAndResolveChallenge(...)`: Challenges a task response
- `getTaskResponseWindowBlock()`: Gets the response window in blocks
- `validateAttestation(Attestation)`: Validates an attestation for use

---

## Constants

### Task Management Constants

**Location:** `NewtonProverTaskManager.sol`

```solidity
uint32 public immutable TASK_RESPONSE_WINDOW_BLOCK;  // Set during construction
uint32 public constant TASK_CHALLENGE_WINDOW_BLOCK = 100;
uint256 internal constant _THRESHOLD_DENOMINATOR = 100;
uint256 public constant WADS_TO_SLASH = 100000000000000000; // 10%
```

**Descriptions:**

- `TASK_RESPONSE_WINDOW_BLOCK`: Number of blocks within which aggregators must respond to tasks
- `TASK_CHALLENGE_WINDOW_BLOCK`: Number of blocks within which challenges can be raised (100 blocks)
- `_THRESHOLD_DENOMINATOR`: Denominator for threshold calculations (100)
- `WADS_TO_SLASH`: Amount to slash when operators are penalized (10% in WAD format)

### Storage Slot Constants

**Location:** `mixins/NewtonPolicyClient.sol`

```solidity
bytes32 private constant _NEWTON_POLICY_CLIENT_STORAGE_SLOT =
    0xaa6954ac1e404d8f79e6eba698b90c3c7071936d683ce65dd13ddf463ffbcb00;
```

**Description:**

- `_NEWTON_POLICY_CLIENT_STORAGE_SLOT`: ERC-7201 storage slot for NewtonPolicyClient data

---

## Enums

### AttestationType Enum

**Location:** `interfaces/INewtonPolicyData.sol`

Defines the types of attestation supported for policy data.

```solidity
enum AttestationType {
    ECDSA,      // ECDSA signature attestation
    BN254,      // BN254 curve signature attestation
    BLS12_381,  // BLS signature on BLS12-381 curve
    GROTH16     // GROTH16 zero-knowledge proof attestation
}
```

**Values:**

- `ECDSA`: Standard ECDSA signature attestation using secp256k1
- `BN254`: Signature attestation using the BN254 elliptic curve
- `BLS12_381`: BLS signature attestation using the BLS12-381 curve
- `GROTH16`: Zero-knowledge proof attestation using GROTH16 proving system

---

## Error Types

### Core Errors

**Location:** `core/NewtonMessage.sol`

```solidity
error Unauthorized(string reason);
```

### Policy Errors

**Location:** `core/NewtonPolicy.sol`

```solidity
error OnlyPolicyClient();
error InterfaceNotSupported();
```

### Policy Data Errors

**Location:** `core/NewtonPolicyData.sol`

```solidity
error OnlyNewtonPolicy();
error InterfaceNotSupported();
error InvalidSignature();
error SignatureVerificationFailed();
error InvalidPolicyData();
error InvalidAttestationInfo();
```

### Factory Errors

**Location:** `core/NewtonPolicyFactory.sol` & `core/NewtonPolicyDataFactory.sol`

```solidity
error OnlyNewtonPolicy();        // or OnlyNewtonPolicyData()
error InterfaceNotSupported();
error OnlyVerifiers();
```

### Task Manager Errors

**Location:** `NewtonProverTaskManager.sol`

```solidity
error OnlyAggregator();
error OnlyTaskGenerator();
error PolicyIdMismatch();
error PolicyAddressMismatch();
error PolicyDataLengthMismatch();
error PolicyDataAddressMismatch();
error PolicyDataAttestationFailed();
error PolicyDataExpired();
error TaskMismatch();
error InvalidPolicyId();
error InvalidPolicyClient();
error InvalidPolicyAddress();
error TaskAlreadyResponded();
error TaskResponseTooLate();
error InsufficientQuorumStake();
error ChallengeNotEnabled();
error ChallengeTaskIdMismatch();
error TaskResponseInvalid();
error ChallengePeriodExpired();
error InvalidNonSigners();
error AttestationHashMismatch();
error AttestationExpired();
error AttestationAlreadySpent();
error OnlyPolicyClient();
error InterfaceNotSupported();
error PolicyNotVerified();
error PolicyDataNotVerified();
```

### Policy Client Errors

**Location:** `mixins/NewtonPolicyClient.sol`

```solidity
error OnlyPolicyClientOwner();
```

### Interface Errors

**Location:** `interfaces/INewtonPolicyClient.sol`

```solidity
error InvalidPolicyID();
```

---

## Events

### Policy Events

#### PolicySet Event

**Location:** `interfaces/INewtonPolicy.sol`

```solidity
event PolicySet(address indexed client, bytes32 indexed policyId, SetPolicyInfo policy);
```

**Description:** Emitted when a policy client sets a new policy configuration.

**Parameters:**

- `client`: Address of the policy client that set the policy
- `policyId`: Unique identifier for the newly set policy
- `policy`: Complete policy information including configuration and metadata

#### PolicyMetadataUriUpdated Event

**Location:** `interfaces/INewtonPolicy.sol`

```solidity
event PolicyMetadataUriUpdated(string metadataUri);
```

**Description:** Emitted when a policy's metadata URI is updated.

**Parameters:**

- `metadataUri`: New metadata URI for the policy

### Policy Data Events

#### PolicyDataMetadataUriUpdated Event

**Location:** `core/NewtonPolicyData.sol`

```solidity
event PolicyDataMetadataUriUpdated(string metadataUri);
```

**Description:** Emitted when policy data metadata URI is updated.

**Parameters:**

- `metadataUri`: New metadata URI for the policy data

#### AttestationInfoUpdated Event

**Location:** `core/NewtonPolicyData.sol`

```solidity
event AttestationInfoUpdated(INewtonPolicyData.AttestationInfo attestationInfo);
```

**Description:** Emitted when attestation configuration is updated for policy data.

**Parameters:**

- `attestationInfo`: New attestation configuration including type, attesters, and verification details

### Factory Events

#### PolicyDeployed Event

**Location:** `core/NewtonPolicyFactory.sol`

```solidity
event PolicyDeployed(address policy, INewtonPolicy.PolicyInfo policyInfo);
```

**Description:** Emitted when a new policy contract is deployed through the factory.

**Parameters:**

- `policy`: Address of the newly deployed policy contract
- `policyInfo`: Complete information about the deployed policy

#### PolicyVerificationUpdated Event

**Location:** `core/NewtonPolicyFactory.sol`

```solidity
event PolicyVerificationUpdated(address policy, NewtonMessage.VerificationInfo verificationInfo);
```

**Description:** Emitted when a policy's verification status is updated.

**Parameters:**

- `policy`: Address of the policy contract
- `verificationInfo`: Updated verification information including verifier, status, and timestamp

#### PolicyDataDeployed Event

**Location:** `core/NewtonPolicyDataFactory.sol`

```solidity
event PolicyDataDeployed(address policyData, INewtonPolicyData.PolicyDataInfo policyDataInfo);
```

**Description:** Emitted when a new policy data contract is deployed through the factory.

**Parameters:**

- `policyData`: Address of the newly deployed policy data contract
- `policyDataInfo`: Complete information about the deployed policy data

#### PolicyDataVerificationUpdated Event

**Location:** `core/NewtonPolicyDataFactory.sol`

```solidity
event PolicyDataVerificationUpdated(address policyData, NewtonMessage.VerificationInfo verificationInfo);
```

**Description:** Emitted when a policy data contract's verification status is updated.

**Parameters:**

- `policyData`: Address of the policy data contract
- `verificationInfo`: Updated verification information including verifier, status, and timestamp

#### VerifierAdded Event

**Location:** `core/NewtonPolicyFactory.sol` & `core/NewtonPolicyDataFactory.sol`

```solidity
event VerifierAdded(address verifier);
```

**Description:** Emitted when a new verifier is authorized to verify policies or policy data.

**Parameters:**

- `verifier`: Address of the newly authorized verifier

#### VerifierRemoved Event

**Location:** `core/NewtonPolicyFactory.sol` & `core/NewtonPolicyDataFactory.sol`

```solidity
event VerifierRemoved(address verifier);
```

**Description:** Emitted when a verifier's authorization is revoked.

**Parameters:**

- `verifier`: Address of the verifier whose authorization was revoked

### Task Management Events

#### NewTaskCreated Event

**Location:** `interfaces/INewtonProverTaskManager.sol`

```solidity
event NewTaskCreated(bytes32 indexed taskId, Task task);
```

**Description:** Emitted when a new task is created for policy evaluation.

**Parameters:**

- `taskId`: Unique identifier for the newly created task
- `task`: Complete task information including intent, policy data, and quorum requirements

#### TaskResponded Event

**Location:** `interfaces/INewtonProverTaskManager.sol`

```solidity
event TaskResponded(TaskResponse taskResponse, ResponseCertificate responseCertificate);
```

**Description:** Emitted when operators submit a response to a task.

**Parameters:**

- `taskResponse`: The task response containing evaluation results
- `responseCertificate`: Additional metadata including response timing and non-signer information

#### TaskChallengedSuccessfully Event

**Location:** `interfaces/INewtonProverTaskManager.sol`

```solidity
event TaskChallengedSuccessfully(bytes32 indexed taskId, address indexed challenger);
```

**Description:** Emitted when a challenge to a task response is successful, resulting in operator slashing.

**Parameters:**

- `taskId`: Identifier of the task that was successfully challenged
- `challenger`: Address of the challenger who proved the task response was incorrect

#### TaskChallengedUnsuccessfully Event

**Location:** `interfaces/INewtonProverTaskManager.sol`

```solidity
event TaskChallengedUnsuccessfully(bytes32 indexed taskId, address indexed challenger);
```

**Description:** Emitted when a challenge to a task response fails, meaning the original response was correct.

**Parameters:**

- `taskId`: Identifier of the task that was unsuccessfully challenged
- `challenger`: Address of the challenger whose challenge failed

#### AttestationSpent Event

**Location:** `interfaces/INewtonProverTaskManager.sol`

```solidity
event AttestationSpent(bytes32 indexed taskId, NewtonMessage.Attestation attestation);
```

**Description:** Emitted when an attestation is consumed/spent by a policy client to validate a transaction.

**Parameters:**

- `taskId`: Identifier of the task associated with the attestation
- `attestation`: The attestation that was spent, including policy details and intent information

---

## Usage Patterns

### Policy Deployment Flow

1. Deploy policy using `NewtonPolicyFactory.deployPolicy()`
2. Set policy verification using `NewtonPolicyFactory.setPolicyVerification()`
3. Deploy policy data using `NewtonPolicyDataFactory.deployPolicyData()`
4. Configure attestation info using `INewtonPolicyData.setAttestationInfo()`

### Task Execution Flow

1. Policy client calls `INewtonProverTaskManager.createNewTask()`
2. Operators evaluate the task and submit `respondToTask()`
3. If successful, an attestation is created
4. Policy client validates attestation using `validateAttestation()`

### Challenge Flow

1. Challenger calls `raiseAndResolveChallenge()` with proof
2. System verifies the challenge proof
3. If challenge succeeds, signing operators are slashed
4. If challenge fails, challenger bears the cost

This schema reference provides a complete overview of all data structures, interfaces, and patterns used in the Newton Prover AVS contract system.
