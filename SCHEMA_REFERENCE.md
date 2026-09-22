# Newton Prover AVS Contract Schema Reference

This document provides a comprehensive reference for all structs, enums, constants, and interfaces defined in the Newton Prover AVS contracts located in the `contracts/src` directory.

## Table of Contents

1. [Core Message Types](#core-message-types)
2. [Policy System](#policy-system)
3. [Task Management](#task-management)
4. [Interfaces](#interfaces)
5. [Constants](#constants)
6. [Enums](#enums)
7. [Error Types](#error-types)

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
    bytes32 taskId;
    bytes32 policyId;
    address policyClient;
    uint32 expiration;
    Intent intent;
    bytes intentSignature;
}
```

**Fields:**

- `taskId`: Unique identifier for the associated task
- `policyId`: Identifier for the policy set governing this attestation
- `policyClient`: Address of the policy client contract
- `expiration`: Block number after which the attestation expires
- `intent`: The transaction intent being attested
- `intentSignature`: User's signature on the intent


---

## Policy System

### PolicyInfo Struct

**Location:** `interfaces/INewtonPolicy.sol`

A policy's artifact fields, written once by `initialize` and emitted by `PolicyDeployed`.

```solidity
struct PolicyInfo {
    address policyAddress;
    address owner;
    string metadataCid;
    string policyCid;
    string schemaCid;
    string entrypoint;
    address[] policyData;
    bytes32 policyCodeHash;
}
```

**Fields:**

- `policyAddress`: address of the deployed policy proxy
- `owner`: policy owner, authorized for `setMetadataCid` only
- `metadataCid`: IPFS CID of the human-facing metadata document
- `policyCid`: IPFS CID of the Rego module source
- `schemaCid`: IPFS CID of the JSON schema for this policy's params
- `entrypoint`: Rego evaluation entrypoint, formatted `{package}.{rule}`
- `policyData`: `NewtonPolicyData` children; empty for a pure-Rego policy. WASM and secrets metadata live on the child, reachable via `getWasmCid()` and `getSecretsSchemaCid()`
- `policyCodeHash`: keccak256 of the raw Rego module bytes

### PolicyConfig Struct

**Location:** `interfaces/INewtonPolicy.sol`

One client's configuration for one use of a policy.

```solidity
struct PolicyConfig {
    bytes policyParams;
    uint32 expireAfter;
}
```

**Fields:**

- `policyParams`: Encoded parameters for this policy use
- `expireAfter`: Blocks a response stays valid, counted from the block the response is recorded

### PolicySpec Struct

**Location:** `interfaces/INewtonPolicyClient.sol`

One policy and the client's configuration for this use of it.

```solidity
struct PolicySpec {
    address policy;
    INewtonPolicy.PolicyConfig config;
}
```

**Fields:**

- `policy`: Policy contract address
- `config`: Client's configuration for this use (policyParams and expireAfter)

---

## Task Management

### Task Struct

**Location:** `interfaces/INewtonProverTaskManager.sol`

Represents a task in the Newton Prover system.

```solidity
struct Task {
    bytes32 taskId;
    address policyClient;
    bytes32 policyId;
    uint64 policyRevision;
    uint32 taskCreatedBlock;
    uint32 quorumThresholdPercentage;
    NewtonMessage.Intent intent;
    bytes intentSignature;
    INewtonPolicyClient.PolicySpec[] policies;
    bytes[] wasmArgs;
    bytes quorumNumbers;
    uint256 initializationTimestamp;
}
```

**Fields:**

- `taskId`: Unique identifier for the task
- `policyClient`: Address of the policy client that created the task
- `policyId`: Identifier for the policy set governing this task
- `policyRevision`: The client's policy revision this task is bound to
- `taskCreatedBlock`: Block number when the task was created
- `quorumThresholdPercentage`: Minimum percentage of operators required to sign
- `intent`: The transaction intent to be evaluated
- `intentSignature`: User's signature on the intent
- `policies`: The client's exact ordered policy set, frozen into the task at creation
- `wasmArgs`: One WASM input per policy, in `policies` order; empty bytes for pure-Rego policies
- `quorumNumbers`: Encoded quorum identifiers for operator selection
- `initializationTimestamp`: Unix timestamp when the task was initialized

### TaskResponse Struct

**Location:** `interfaces/INewtonProverTaskManager.sol`

Response to a task, signed by operators.

```solidity
struct TaskResponse {
    bytes32 taskId;
    address policyClient;
    bytes32 policyId;
    NewtonMessage.Intent intent;
    bytes intentSignature;
    bytes[] rego;
    bytes[] oracleOutputs;
    bool allowed;
    uint256 initializationTimestamp;
}
```

**Fields:**

- `taskId`: Identifier of the task being responded to
- `policyClient`: Address of the policy client
- `policyId`: Identifier of the policy set that was evaluated
- `intent`: The transaction intent that was evaluated
- `intentSignature`: User's signature on the intent
- `rego`: The exact Rego module bytes evaluated per policy, in the task's `policies` order
- `oracleOutputs`: Each policy's WASM oracle output, in the task's `policies` order; empty bytes for pure-Rego policies
- `allowed`: The policy set's verdict; true only when every policy allowed
- `initializationTimestamp`: Unix timestamp when the task was initialized

### ResponseCertificate Struct

**Location:** `interfaces/INewtonProverTaskManager.sol`

Certificate for policy clients to attest the validity of policy evaluation result during intent execution.

```solidity
struct ResponseCertificate {
    uint32 referenceBlock;
    uint32 responseExpireBlock;
    bytes32 hashOfNonSigners;
    bytes signatureData;
}
```

**Fields:**

- `referenceBlock`: Block number when the response certificate is created
- `responseExpireBlock`: Block number when the task response expires
- `hashOfNonSigners`: Hash of operators who did not sign the response
- `signatureData`: Encoded signature data (NonSignerStakesAndSignature for source chains, BN254Certificate for destination chains)

### ChallengeData Struct

**Location:** `interfaces/INewtonProverTaskManager.sol`

Data submitted by challengers to dispute task responses.

```solidity
struct ChallengeData {
    bytes32 taskId;
    bytes proof;
    bytes data;
}
```

**Fields:**

- `taskId`: Identifier of the task being challenged
- `proof`: SP1 zero-knowledge proof attesting to the challenger's evaluation result
- `data`: The committed proof output used for verification against the task response

---

## Policy Client System

### NewtonPolicyClientStorage Struct

**Location:** `mixins/NewtonPolicyClient.sol`

Storage structure for policy client contracts using ERC-7201 storage pattern.

```solidity
struct NewtonPolicyClientStorage {
    INewtonProverTaskManager policyTaskManager;
    address _reservedSlot0;
    bytes32 _reservedSlot1;
    address policyClientOwner;
    PolicySpec[] policies;
    bytes32 policyId;
    uint64 policyRevision;
}
```

**Fields:**

- `policyTaskManager`: Interface to the Newton Prover Task Manager contract
- `_reservedSlot0`: Reserved storage slot (formerly policy)
- `_reservedSlot1`: Reserved storage slot (formerly policyId)
- `policyClientOwner`: Address authorized to manage the policy client
- `policies`: The client's ordered policy set
- `policyId`: Unique identifier for the current policy set
- `policyRevision`: Policy revision counter, increments on every successful write

---

## Interfaces

### INewtonPolicy Interface

**Location:** `interfaces/INewtonPolicy.sol`

Main interface for Newton Policy contracts.

**Key Functions:**

- `getPolicyCid()`: IPFS CID of the Rego module source
- `getPolicyCodeHash()`: keccak256 of the raw Rego module bytes
- `getSchemaCid()`: IPFS CID of the JSON schema for this policy's params
- `getEntrypoint()`: Rego evaluation entrypoint, formatted `{package}.{rule}`
- `getPolicyData()`: The `NewtonPolicyData` oracle children; empty for a pure-Rego policy. The WASM CID and secrets schema are read from the child
- `getMetadataCid()` / `setMetadataCid()`: IPFS CID of the human-facing metadata document, the one artifact field the policy owner may change
- `getPolicyConfig(policyId)`: One client's `PolicyConfig` for this policy
- `getPolicyId(client)`: The policyId registered for a client
- `factory()`: The factory that deployed this policy
- `version()`: The semantic version of the policy implementation

### INewtonPolicyClient Interface

**Location:** `interfaces/INewtonPolicyClient.sol`

Interface for contracts that can submit tasks with policy constraints.

**Key Functions:**

- `setPolicies(PolicySpec[])`: Replaces the complete policy set atomically
- `getPolicies()`: Returns the client's current ordered policy set
- `getPolicySetSnapshot()`: Returns (policyId, revision, policies) atomically - the complete frozen snapshot
- `policyId()`: Returns the identifier for the client's current policy set
- `policyRevision()`: Returns the client's policy revision counter
- `getNewtonPolicyTaskManager()`: Returns the task manager address
- `getOwner()`: Retrieves the owner address of the policy client

### INewtonProverTaskManager Interface

**Location:** `interfaces/INewtonProverTaskManager.sol`

Main interface for task management in the Newton Prover system.

**Key Functions:**

- `createNewTask(Task)`: Creates a new task for policy evaluation
- `respondToTask(Task, TaskResponse, bytes, bytes)`: Submits a response to an existing task
- `raiseAndResolveChallenge(Task, TaskResponse, ResponseCertificate, ChallengeData, BN254.G1Point[])`: Challenges a task response
- `slashForCrossChainChallenge(uint256, Task, TaskResponse, ChallengeData, bytes, BN254.G1Point[])`: Relays a cross-chain challenge to trigger slashing on source
- `validateAttestation(Attestation)`: Validates an attestation for use
- `validateAttestationDirect(Task, TaskResponse, bytes)`: Validates attestation directly by verifying signatures
- `challengeDirectlyVerifiedAttestation(Task, TaskResponse, bytes)`: Challenges directly verified attestations
- `challengeDirectlyVerifiedMismatch(Task, TaskResponse)`: Invalidates a direct-path attestation whose stored hashes diverge
- `taskHash(bytes32)`: Returns the task-identity hash recorded when the task was created
- `taskResponseHash(bytes32)`: Returns keccak256 of task response with response certificate
- `normalizedTaskResponseHash(bytes32)`: Returns keccak256 of task response only, without response certificate
- `allTaskAttestations(bytes32)`: Returns keccak256 of attestation data for the given task

### IRegoVerifier Interface

**Location:** `interfaces/IRegoVerifier.sol`

Interface for verifying Rego policy evaluation proofs.

**RegoContext Struct:**

```solidity
struct RegoContext {
    INewtonProverTaskManager.Task task;
    INewtonProverTaskManager.TaskResponse taskResponse;
    string[] entrypoints;
    bytes[] evaluations;
    bytes32[] policyCodeHashes;
}
```

**Key Functions:**

- `verifyRegoProof(bytes calldata _publicValues, bytes calldata _proofBytes)`: Verifies a zero-knowledge proof of Rego evaluation, returns RegoContext

---

## Constants

### Policy System Constants

**Location:** `libraries/PolicyConstants.sol`

```solidity
bytes32 constant POLICY_SET_DOMAIN = keccak256("newton.policy.set");
uint256 constant MAX_POLICIES = 8;
```

**Descriptions:**

- `POLICY_SET_DOMAIN`: Domain separator for a policy-set ID: one client's exact ordered policy list at one revision
- `MAX_POLICIES`: Upper bound on policies in one client's set. The single authoritative bound; contracts reject oversize sets and off-chain services mirror this value

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

---

## Error Types

### Core Errors

**Location:** `core/NewtonMessage.sol`

```solidity
error Unauthorized(string reason);
```

### Policy Errors

**Location:** `interfaces/INewtonPolicy.sol`

```solidity
error InvalidPolicyCodeHash();
error EmptyPolicyCid();
error EmptySchemaCid();
error EmptyEntrypoint();
error SecretsSchemaWithoutWasm();
```

### Policy Client Errors

**Location:** `interfaces/INewtonPolicyClient.sol`

```solidity
error EmptyPolicySet();
error TooManyPolicies(uint256 count, uint256 maximum);
error PolicyNotRegistered(address policy);
error ZeroExpireAfter(uint256 index);
error PolicyFactoryNotSet();
```

### Mixin Errors

**Location:** `mixins/NewtonPolicyClient.sol`

```solidity
error OnlyPolicyClientOwner();
```

---

## Events

### Policy Client Events

#### PoliciesUpdated Event

**Location:** `interfaces/INewtonPolicyClient.sol`

```solidity
event PoliciesUpdated(
    bytes32 indexed previousPolicyId,
    bytes32 indexed policyId,
    uint64 revision,
    PolicySpec[] policies
);
```

**Description:** Emitted on every successful write, including reapplying an identical list: the revision advances, so each write mints a distinct policyId.

**Parameters:**

- `previousPolicyId`: The policy ID before this update
- `policyId`: The new policy ID for this exact ordered list at this revision
- `revision`: The client's policy revision counter
- `policies`: The ordered policy specifications

### Factory Events

#### PolicyDeployed Event

**Location:** `core/NewtonPolicyFactory.sol`

```solidity
event PolicyDeployed(
    address policy, INewtonPolicy.PolicyInfo policyInfo, string implementationVersion
);
```

**Description:** Emitted when a new policy contract is deployed through the factory.

**Parameters:**

- `policy`: Address of the newly deployed policy contract
- `policyInfo`: The policy's artifact fields, including its owner and `policyData` children
- `implementationVersion`: Version of the policy implementation behind the proxy

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

1. Deploy any WASM oracle with `NewtonPolicyDataFactory.deployPolicyData`, then deploy the policy with `NewtonPolicyFactory.deployPolicy(entrypoint, policyCid, schemaCid, policyData[], metadataCid, owner, policyCodeHash)`
2. Policy client calls `setPolicies(PolicySpec[])` to configure its ordered policy set

### Task Execution Flow

1. Policy client calls `INewtonProverTaskManager.createNewTask(Task)` with a frozen policy snapshot and one `wasmArgs` entry per policy
2. Operators evaluate the policy set and submit `respondToTask(Task, TaskResponse, bytes, bytes)`
3. If allowed, an attestation is created
4. Policy client validates attestation using `validateAttestation(Attestation)` or `validateAttestationDirect(Task, TaskResponse, bytes)`

### Challenge Flow

1. Challenger calls `raiseAndResolveChallenge(Task, TaskResponse, ResponseCertificate, ChallengeData, BN254.G1Point[])` with SP1 zero-knowledge proof
2. System verifies the challenge proof on-chain
3. If challenge succeeds, signing operators are slashed
4. If challenge fails, challenger bears the cost

This schema reference provides a complete overview of all data structures, interfaces, and patterns used in the Newton Prover AVS contract system.
