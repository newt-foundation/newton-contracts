# Newton Policy Protocol AVS

A decentralized policy-based authorization system built on EigenLayer that enables intent-based transaction validation using Rego policies and zero-knowledge proofs.

## Overview

The Newton Policy Protocol AVS is a decentralized system that enables policy-based authorization for blockchain transactions. It allows users to submit transaction intents that are evaluated against predefined policies using the Rego language (Open Policy Agent), with cryptographic proofs ensuring the correctness of policy evaluations.

### Key Features

- **Intent-Based Authorization**: Users submit transaction intents that are evaluated against policies
- **Rego Policy Engine**: Flexible policy definition using Open Policy Agent's Rego language
- **Zero-Knowledge Proofs**: Supports SP1 and RISC0 proof systems for verification
- **Decentralized Validation**: Multiple operators validate policy evaluations
- **Challenge Mechanism**: Economic incentives ensure correctness through slashing
- **EigenLayer Integration**: Leverages restaked ETH for security

### How It Works

1. **Policy Creation**: Clients deploy policy contracts with Rego rules and configuration
2. **Intent Submission**: Users submit transaction intents for policy evaluation
3. **Operator Validation**: Multiple operators independently evaluate intents against policies
4. **Response Aggregation**: BLS signatures from operators are aggregated and submitted
5. **Challenge Resolution**: Challengers can dispute incorrect evaluations with ZK proofs
6. **Authorization**: Validated intents are authorized for execution

## Dependencies

- [Foundry](https://github.com/foundry-rs/foundry) - to compile and deploy the contracts
- [Docker](https://www.docker.com/) - for tests
- [jq](https://jqlang.org/download/) - for rewards examples

## Running the Policy Evaluation System

### Deploy the contracts

First, start anvil in a separate terminal

```sh
anvil
```

Second, update git submodules and copy `.env` file

```sh
git submodule update --init --recursive
cp .env.example .env
```

## Architecture

The Newton Protocol Core Contracts consists of:

- [**Policy Factory**](contracts/src/core/NewtonPolicyFactory.sol): Deploys new policy instances for clients
- [**Policy Contracts**](contracts/src/core/NewtonPolicy.sol): Store Rego policies and client-specific configurations
- [**Policy Data Contracts**](contracts/src/core/NewtonPolicyData.sol): Handle policy data validation and attestation

### Policy System

The Newton Policy Protocol uses the Rego language (Open Policy Agent) for flexible and powerful policy definition. Policies are stored on-chain and evaluated by operators to determine whether user intents should be authorized.

### Policy Components

- **Policy Factory**: Deploys new policy instances for clients
- **Policy Contracts**: Store Rego policies, schemas, and client-specific configurations
- **Policy Data Contracts**: Handle policy data validation and attestation
- **Policy Evaluation Engine**: Operators run Rego evaluation against user intents

### Example Policy

```rego
package example

# Example policy for transaction authorization
allow if {
    # Check if sender is authorized
    input.sender in data.authorized_senders

    # Verify transaction value limits
    input.value <= data.max_transaction_value

    # Validate target contract
    input.target in data.allowed_contracts
}

# Additional rules for complex logic
deny if {
    input.target in data.blacklisted_contracts
}
```

### Policy Lifecycle

1. **Policy Creation**: Client deploys policy contract with Rego rules
2. **Policy Registration**: Client calls `setPolicy()` with configuration parameters
3. **Policy ID Generation**: Unique ID created from policy data hash
4. **Task Association**: Tasks reference policy ID for evaluation
5. **Evaluation**: Operators evaluate user intents against policies
6. **Authorization**: Validated intents are authorized for execution

## Related Projects

### EigenLayer Ecosystem

- [eigensdk-rs](https://github.com/Layr-Labs/eigensdk-rs) - Official EigenLayer Rust SDK
- [rust-bls-bn254](https://github.com/Layr-Labs/bn254-bls-keystore-rs) - EIP 2335 Compatible Keystore using BN254
- [eigenlayer-contracts](https://github.com/Layr-Labs/eigenlayer-contracts) - EigenLayer core smart contracts

### Policy and Authorization

- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) - Policy engine used for Rego language
- [Rego Language](https://www.openpolicyagent.org/docs/latest/policy-language/) - Policy language for authorization decisions
- [SP1](https://github.com/succinctlabs/sp1) - Zero-knowledge proof system for policy verification
- [RISC0](https://github.com/risc0/risc0) - Zero-knowledge proof system for policy verification

### Zero-Knowledge Proofs

- [SP1](https://github.com/succinctlabs/sp1) - Succinct's zkVM for general-purpose computation
- [RISC0](https://github.com/risc0/risc0) - RISC Zero's zkVM for verifiable computation
