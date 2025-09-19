# Newton Policy Protocol AVS

A decentralized policy-based authorization system built on EigenLayer that enables intent-based transaction validation using Rego policies and zero-knowledge proofs.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Contract Documentation](#contract-documentation)
4. [Policy System](#policy-system)
5. [Deployment Guide](#deployment-guide)
6. [Usage Examples](#usage-examples)
7. [Development Setup](#development-setup)
8. [Security Considerations](#security-considerations)
9. [Related Projects](#related-projects)

## Overview

The Newton Policy Protocol AVS is a decentralized system that enables policy-based authorization for blockchain transactions. It allows users to submit transaction intents that are evaluated against predefined policies using the Rego language (Open Policy Agent), with cryptographic proofs ensuring the correctness of policy evaluations.

### Key Features

- **Intent-Based Authorization**: Users submit transaction intents that are evaluated against policies
- **Rego Policy Engine**: Flexible policy definition using Open Policy Agent's Rego language
- **Zero-Knowledge Proofs**: Supports SP1 and RISC0 proof systems for verification
- **Decentralized Validation**: Multiple operators validate policy evaluations
- **Challenge Mechanism**: Economic incentives ensure correctness through slashing
- **EigenLayer Integration**: Leverages restaked ETH for security
- **Upgradeable Contracts**: Uses OpenZeppelin's transparent proxy pattern for upgradeability
- **Multi-Chain Support**: Designed to work across different blockchain networks

### How It Works

1. **Policy Creation**: Clients deploy policy contracts with Rego rules and configuration
2. **Policy Data Setup**: Deploy policy data contracts with attestation mechanisms
3. **Intent Submission**: Users submit transaction intents for policy evaluation
4. **Operator Validation**: Multiple operators independently evaluate intents against policies
5. **Response Aggregation**: BLS signatures from operators are aggregated and submitted
6. **Challenge Resolution**: Challengers can dispute incorrect evaluations with ZK proofs
7. **Authorization**: Validated intents are authorized for execution

## Architecture

The Newton Policy Protocol consists of several interconnected components working together to provide secure, decentralized policy-based authorization.

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Policy Factory │────│  Policy Data    │────│  Policy Client  │
│                 │    │  Factory        │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Policy         │    │  Policy Data    │    │  Example Policy │
│  Contracts      │    │  Contracts      │    │  Client         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────┐
                    │  Newton Prover  │
                    │  Task Manager   │
                    │  (EigenLayer)   │
                    └─────────────────┘
```

### Layer Architecture

1. **Factory Layer**: Deploys and manages policy and policy data contracts
2. **Policy Layer**: Stores Rego policies, schemas, and configurations
3. **Data Layer**: Handles policy data validation and attestation
4. **Client Layer**: Interfaces for applications to interact with the policy system
5. **Validation Layer**: EigenLayer-based task management and validation

## Contract Documentation

### Core Contracts (`src/core/`)

#### NewtonPolicyFactory.sol

**Purpose**: Factory contract for deploying new policy instances using CREATE2 for deterministic addresses.

**Key Features**:

- Deploys policy contracts using transparent upgradeable proxies
- Manages policy verification status
- Supports verifier role management
- Deterministic address computation

**Key Functions**:

```solidity
function deployPolicy(
    string memory _entrypoint,
    string memory _policyUri,
    string memory _schemaUri,
    address[] memory _policyData,
    string memory _metadataUri,
    address _owner
) external returns (address policyAddr)

function computePolicyAddress(...) public view returns (address predicted)
function setPolicyVerification(address policyAddr, bool verified) external
```

#### NewtonPolicy.sol

**Purpose**: Core policy contract that stores Rego policies and client configurations.

**Key Features**:

- Stores policy URIs, schemas, and entrypoints
- Manages per-client policy configurations
- Supports policy verification status
- ERC165 interface compliance

**Key Functions**:

```solidity
function setPolicy(PolicyConfig calldata policyConfig) public returns (bytes32)
function getPolicyConfig(bytes32 policyId) public view returns (PolicyConfig memory)
function isPolicyVerified() public view returns (bool)
```

**Policy Configuration Structure**:

```solidity
struct PolicyConfig {
    bytes policyParams;    // Encoded policy parameters
    uint32 expireAfter;   // Expiration time in blocks
}
```

#### NewtonPolicyData.sol

**Purpose**: Manages policy data with cryptographic attestation mechanisms.

**Key Features**:

- Multiple attestation types (ECDSA, BLS12-381, BN254, GROTH16)
- Policy data validation and expiration
- Flexible attestation configuration
- IPFS integration for data storage

**Attestation Types**:

```solidity
enum AttestationType {
    ECDSA,      // ECDSA signature attestation
    BN254,      // BN254 curve signatures
    BLS12_381,  // BLS signatures on BLS12-381
    GROTH16     // Zero-knowledge proofs using Groth16
}
```

#### NewtonPolicyDataFactory.sol

**Purpose**: Factory for deploying policy data contracts with proper attestation setup.

#### NewtonMessage.sol

**Purpose**: Defines core message types and data structures used throughout the system.

**Key Structures**:

```solidity
struct Intent {
    address from;
    address to;
    uint256 value;
    bytes data;
    uint256 chainId;
    bytes functionSignature;
}

struct Attestation {
    bytes32 taskId;
    bytes32 policyId;
    address policyClient;
    Intent intent;
    uint32 expiration;
}
```

### Interface Contracts (`src/interfaces/`)

#### INewtonPolicy.sol

Defines the standard interface for policy contracts including policy configuration, metadata management, and verification status.

#### INewtonPolicyClient.sol

Interface for client contracts that interact with the policy system, enabling policy-based transaction authorization.

#### INewtonPolicyData.sol

Interface for policy data contracts with attestation capabilities and data validation.

#### INewtonProverTaskManager.sol

Interface for the EigenLayer-based task management system that handles policy evaluation tasks.

### Library Contracts (`src/libraries/`)

#### PolicyValidationLib.sol

**Purpose**: Comprehensive validation library for policies and policy data.

**Key Functions**:

```solidity
function checkVerifiedPolicy(address policyClient, PolicyTaskData calldata policyTaskData)
function validatePolicyData(address policyAddress, PolicyTaskData calldata policyTaskData, uint32 currentBlock)
```

**Validation Features**:

- Policy ID and address verification
- Policy data attestation validation
- Expiration checking
- Mainnet verification requirements

#### ChainLib.sol

Utility library for chain-specific operations and network detection.

#### TaskEvaluationLib.sol

Library for task evaluation and processing logic.

### Mixin Contracts (`src/mixins/`)

#### NewtonPolicyClient.sol

**Purpose**: Abstract base contract providing policy client functionality.

**Key Features**:

- ERC-7201 storage pattern for upgradeable contracts
- Policy configuration management
- Attestation validation
- Owner access control

**Storage Structure**:

```solidity
struct NewtonPolicyClientStorage {
    INewtonProverTaskManager policyTaskManager;
    address policy;
    bytes32 policyId;
    address policyClientOwner;
}
```

### Example Implementation (`src/examples/`)

#### ExamplePolicyClient.sol

**Purpose**: Reference implementation showing how to build a policy-enabled application.

**Features**:

- Token deposit/withdrawal functionality
- Intent execution with policy validation
- Integration with Newton Policy system
- Proper error handling and event emission

## Policy System

### Rego Policy Language

The Newton Protocol uses the Rego language (Open Policy Agent) for flexible and powerful policy definition. Policies are stored on-chain and evaluated by operators to determine whether user intents should be authorized.

#### Policy Structure

```rego
package example

# Main authorization rule
allow if {
    # Check if sender is authorized
    input.sender in data.authorized_senders

    # Verify transaction value limits
    input.value <= data.max_transaction_value

    # Validate target contract
    input.target in data.allowed_contracts

    # Additional custom logic
    custom_validation
}

# Denial rules (explicit deny)
deny if {
    input.target in data.blacklisted_contracts
}

# Helper rules
custom_validation if {
    # Complex business logic
    input.timestamp >= data.start_time
    input.timestamp <= data.end_time
}
```

#### Policy Components

1. **Policy URI**: IPFS location of the Rego policy file
2. **Schema URI**: JSON schema defining the policy input structure
3. **Entrypoint**: The Rego rule to evaluate (e.g., `example.allow`)
4. **Policy Parameters**: Client-specific configuration data
5. **Policy Data**: External data sources with attestation

#### Policy Lifecycle

1. **Policy Creation**: Deploy policy contract with Rego rules and schema
2. **Policy Registration**: Client calls `setPolicy()` with configuration
3. **Policy ID Generation**: Unique ID created from policy data hash
4. **Task Association**: Tasks reference policy ID for evaluation
5. **Evaluation**: Operators evaluate user intents against policies
6. **Authorization**: Validated intents are authorized for execution

### Policy Data and Attestation

Policy data provides external information that policies can use during evaluation. This data must be attested to ensure integrity.

#### Attestation Methods

1. **ECDSA Signatures**: Traditional cryptographic signatures
2. **BLS Signatures**: Aggregate signatures for efficiency
3. **Zero-Knowledge Proofs**: GROTH16 proofs for privacy-preserving attestation

#### Data Lifecycle

1. **Data Creation**: Generate policy data off-chain
2. **Attestation**: Sign or prove data integrity
3. **Upload**: Store data and attestation on IPFS
4. **Registration**: Deploy policy data contract
5. **Validation**: Operators verify attestations during evaluation

## Deployment Guide

### Prerequisites

- [Foundry](https://github.com/foundry-rs/foundry) - Solidity development framework
- [Docker](https://www.docker.com/) - For local testing environment
- [jq](https://jqlang.org/download/) - JSON processing tool
- Node.js and npm - For additional tooling

### Environment Setup

1. **Clone the repository**:

```bash
git clone <repository-url>
cd newton-contracts
```

2. **Install dependencies**:

```bash
git submodule update --init --recursive
```

3. **Set up environment variables**:

```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Build contracts**:

```bash
forge build
```

### Local Development

1. **Start local Anvil node**:

```bash
make start_docker
# or
anvil
```

2. **Run tests**:

```bash
forge test
# or
make tests
```

### Deployment Scripts

The project includes comprehensive deployment scripts in the `script/` directory:

#### PolicyDeployer.s.sol

Deploys policy contracts with the following parameters:

- Policy entrypoint
- Policy URI (IPFS)
- Schema URI (IPFS)
- Policy data contract addresses
- Metadata URI
- Owner address

**Usage**:

```bash
forge script script/PolicyDeployer.s.sol:PolicyDeployer \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast -vvvv
```

#### PolicyClientDeployer.s.sol

Deploys policy client contracts with:

- Newton Prover Task Manager integration
- Policy address configuration
- Initial policy parameters

**Usage**:

```bash
forge script script/PolicyClientDeployer.s.sol:PolicyClientDeployer \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast -vvvv
```

### Network Configuration

The project supports multiple networks configured in `foundry.toml`:

- **Mainnet**: Production Ethereum network
- **Sepolia**: Ethereum testnet
- **Holesky**: Ethereum testnet
- **Local**: Anvil local development

### Makefile Commands

```bash
# Upload policy files to IPFS
make upload-policy-to-ipfs json=path/to/config.json chain_id=1

# Deploy policy contracts
make deploy-policy json=path/to/config.json chain_id=1

# Deploy policy client
make deploy-policy-client policy_params_file=path/to/params.json policy_address=0x...
```

## Usage Examples

### Basic Policy Client Implementation

```solidity
pragma solidity ^0.8.27;

import {NewtonPolicyClient} from "../mixins/NewtonPolicyClient.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";
import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";

contract MyPolicyClient is NewtonPolicyClient {
    function initialize(
        address policyTaskManager,
        address policy,
        address owner
    ) public initializer {
        _initNewtonPolicyClient(policyTaskManager, policy, owner);
    }

    function executeWithPolicy(
        NewtonMessage.Attestation calldata attestation
    ) external returns (bytes memory) {
        require(_validateAttestation(attestation), "Invalid attestation");

        NewtonMessage.Intent memory intent = attestation.intent;
        (bool success, bytes memory result) = intent.to.call{value: intent.value}(intent.data);
        require(success, "Intent execution failed");

        return result;
    }
}
```

### Policy Configuration

```solidity
// Set up policy with parameters
INewtonPolicy.PolicyConfig memory config = INewtonPolicy.PolicyConfig({
    policyParams: abi.encode(
        maxTransactionValue,
        allowedContracts,
        authorizedSenders
    ),
    expireAfter: 3600 // 1 hour in blocks
});

bytes32 policyId = policyClient.setPolicy(config);
```

### Intent Creation and Execution

```javascript
// Create an intent (off-chain)
const intent = {
  from: userAddress,
  to: targetContract,
  value: ethers.utils.parseEther("1.0"),
  data: encodedFunctionCall,
  chainId: 1,
  functionSignature: encodedABI,
};

// Submit to operators for evaluation
// Operators return attestation if policy allows

// Execute with attestation
await policyClient.executeIntent(attestation);
```

## Development Setup

### Project Structure

```
newton-contracts/
├── src/
│   ├── core/              # Core protocol contracts
│   ├── interfaces/        # Contract interfaces
│   ├── libraries/         # Utility libraries
│   ├── mixins/           # Reusable contract components
│   └── examples/         # Example implementations
├── script/
│   ├── utils/            # Deployment utilities
│   └── *.s.sol          # Deployment scripts
├── test/                 # Test contracts
├── data/                 # Configuration files
└── anvil/               # Local deployment scripts
```

### Configuration Files

#### foundry.toml

Main Foundry configuration with:

- Solidity compiler settings (0.8.27)
- Optimizer configuration
- Network RPC endpoints
- Testing parameters

#### Makefile

Automation for:

- Docker container management
- IPFS uploads
- Contract deployment
- Testing workflows

### Testing

```bash
# Run all tests
forge test

# Run with verbosity
forge test -vvv

# Run specific test
forge test --match-test testPolicyDeployment

# Run with gas reporting
forge test --gas-report
```

### Code Quality

The project uses several tools for code quality:

- **Solhint**: Solidity linting
- **Forge fmt**: Code formatting
- **Slither**: Security analysis (configured in `slither.config.json`)

```bash
# Format code
forge fmt

# Run linter
solhint src/**/*.sol

# Security analysis
slither .
```

## Security Considerations

### Access Control

1. **Owner Controls**: Critical functions protected by ownership checks
2. **Verifier System**: Multi-party verification for policy validation
3. **Interface Validation**: ERC165 checks for contract compatibility

### Policy Security

1. **Policy Verification**: Mainnet policies must be verified
2. **Data Attestation**: All policy data must be cryptographically attested
3. **Expiration Handling**: Time-based expiration for policies and data

### Upgrade Safety

1. **Transparent Proxies**: OpenZeppelin's battle-tested proxy pattern
2. **Storage Layouts**: ERC-7201 storage slots prevent collisions
3. **Initialization Guards**: Prevent multiple initialization

### Validation Mechanisms

1. **Policy ID Matching**: Ensures correct policy evaluation
2. **Chain ID Validation**: Prevents cross-chain replay attacks
3. **Signature Verification**: Multiple signature schemes supported
4. **Expiration Checks**: Prevents use of stale data

### Best Practices

1. **Minimal Trust**: Verify all external data and signatures
2. **Fail-Safe Defaults**: Deny by default, allow explicitly
3. **Comprehensive Logging**: Detailed events for monitoring
4. **Error Handling**: Clear error messages and proper reverts

## Related Projects

### EigenLayer Ecosystem

- [eigensdk-rs](https://github.com/Layr-Labs/eigensdk-rs) - Official EigenLayer Rust SDK
- [rust-bls-bn254](https://github.com/Layr-Labs/bn254-bls-keystore-rs) - EIP 2335 Compatible Keystore using BN254
- [eigenlayer-contracts](https://github.com/Layr-Labs/eigenlayer-contracts) - EigenLayer core smart contracts
- [eigenlayer-middleware](https://github.com/Layr-Labs/eigenlayer-middleware) - Middleware contracts for AVS development

### Policy and Authorization

- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) - Policy engine used for Rego language
- [Rego Language](https://www.openpolicyagent.org/docs/latest/policy-language/) - Policy language for authorization decisions
- [Regorus](https://github.com/microsoft/regorus) - Rust implementation of Rego

### Zero-Knowledge Proofs

- [SP1](https://github.com/succinctlabs/sp1) - Succinct's zkVM for general-purpose computation
- [RISC0](https://github.com/risc0/risc0) - RISC Zero's zkVM for verifiable computation

### Development Tools

- [Foundry](https://github.com/foundry-rs/foundry) - Fast, portable and modular toolkit for Ethereum development
- [OpenZeppelin](https://github.com/OpenZeppelin/openzeppelin-contracts) - Secure smart contract library
- [IPFS](https://ipfs.io/) - Distributed storage for policy files and data

---

For detailed schema reference and data structures, see [SCHEMA_REFERENCE.md](SCHEMA_REFERENCE.md).

For contribution guidelines and development workflows, see the project's contribution documentation.
