// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IAttestationProofVerifier} from "../interfaces/IAttestationProofVerifier.sol";
import {ISP1Verifier} from "../../lib/sp1-contracts/contracts/src/ISP1Verifier.sol";

import {Initializable} from "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";

/// @title AttestationProofVerifier
///
/// @notice Verifies SP1 ZK proofs for Nitro attestation invalidity (fraud proofs).
///         Called by ChallengeVerifier during Type 2 TEE attestation challenges.
///
/// @dev Mirrors the RegoVerifier pattern: delegates proof verification to ISP1Verifier,
///      then decodes and returns the public values (AttestationContext) for the caller
///      to bind against on-chain state.
contract AttestationProofVerifier is Initializable, OwnableUpgradeable, IAttestationProofVerifier {
    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------

    /// @notice SP1 verifier contract address (handles Groth16/Plonk proof math)
    address public verifier;

    /// @notice SP1 program verification key for the attestation circuit
    bytes32 public attestationProgramVKey;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event VerifierSet(address indexed verifier);
    event AttestationProgramVKeySet(bytes32 indexed vkey);

    // -------------------------------------------------------------------------
    // Gap
    // -------------------------------------------------------------------------

    uint256[48] private __gap;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // -------------------------------------------------------------------------
    // Initializer
    // -------------------------------------------------------------------------

    function initialize(
        address _verifier,
        bytes32 _attestationProgramVKey,
        address _owner
    ) external initializer {
        require(_verifier != address(0), "invalid verifier");
        require(_attestationProgramVKey != bytes32(0), "invalid vkey");
        __Ownable_init();
        _transferOwnership(_owner);
        verifier = _verifier;
        attestationProgramVKey = _attestationProgramVKey;
    }

    // -------------------------------------------------------------------------
    // Admin
    // -------------------------------------------------------------------------

    function setAttestationProgramVKey(
        bytes32 _attestationProgramVKey
    ) external onlyOwner {
        attestationProgramVKey = _attestationProgramVKey;
        emit AttestationProgramVKeySet(_attestationProgramVKey);
    }

    function setVerifier(
        address _verifier
    ) external onlyOwner {
        verifier = _verifier;
        emit VerifierSet(_verifier);
    }

    // -------------------------------------------------------------------------
    // Verification
    // -------------------------------------------------------------------------

    /// @inheritdoc IAttestationProofVerifier
    function verifyAttestationProof(
        bytes calldata _publicValues,
        bytes calldata _proofBytes
    ) external view override returns (AttestationContext memory) {
        ISP1Verifier(verifier).verifyProof(attestationProgramVKey, _publicValues, _proofBytes);

        return abi.decode(_publicValues, (AttestationContext));
    }
}
