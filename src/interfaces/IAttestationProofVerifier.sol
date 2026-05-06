// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

/// @title IAttestationProofVerifier
///
/// @notice Verifies SP1 ZK proofs that prove a Nitro attestation is invalid.
///         Called by ChallengeVerifier during Type 2 (TEE attestation) challenges.
///
/// @dev The SP1 circuit commits AttestationContext as public values. The on-chain
///      verifier decodes them and returns the struct for the caller to bind against
///      on-chain state (PCR0 registry, task attestation hash, etc.).
interface IAttestationProofVerifier {
    /// @notice Public values committed by the SP1 attestation verification circuit.
    struct AttestationContext {
        /// Task ID the attestation is bound to
        bytes32 taskId;
        /// keccak256(abi.encode(taskResponse)) — binds attestation to specific response
        bytes32 responseDigest;
        /// keccak256(attestation_bytes) — binds proof to the specific on-chain attestation
        bytes32 attestationHash;
        /// keccak256(pcr0_bytes) — matches EnclaveVersionRegistry entries
        bytes32 pcr0Hash;
        /// keccak256(root_cert_der) — matches EnclaveVersionRegistry.rootCertHash
        bytes32 rootCertHash;
        /// keccak256(policy_bytes) — matches NewtonPolicy.policyCodeHash for binding
        bytes32 policyCodeHash;
        /// false when the circuit proves the attestation is invalid
        bool isValid;
        /// 0=valid, 1=invalid_cert_chain, 2=pcr0_not_whitelisted, 3=task_binding_mismatch, 4=expired
        uint8 failureReason;
        /// true when the Rego source references privacy namespaces
        bool isPrivacyPolicy;
    }

    /// @notice Verify an SP1 attestation proof and decode the public values.
    /// @param _publicValues ABI-encoded AttestationContext from the SP1 journal
    /// @param _proofBytes SP1 Groth16 proof bytes
    /// @return Decoded AttestationContext
    function verifyAttestationProof(
        bytes calldata _publicValues,
        bytes calldata _proofBytes
    ) external view returns (AttestationContext memory);
}
