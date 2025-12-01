// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {IRegoVerifier} from "../interfaces/IRegoVerifier.sol";

/// @title RegoVerifier
/// @author denniswon
/// @notice This contract implements verifying the proof of evaluating a rego policy.
contract RegoVerifier is OwnableUpgradeable, IRegoVerifier {
    address public verifier;
    bytes32 public regoProgramVKey;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the RegoVerifier contract
    /// @param _verifier The verifier address
    /// @param _regoProgramVKey The rego program verification key
    /// @param _owner The owner of the contract
    function initialize(
        address _verifier,
        bytes32 _regoProgramVKey,
        address _owner
    ) public initializer {
        __Ownable_init();
        _transferOwnership(_owner);
        verifier = _verifier;
        regoProgramVKey = _regoProgramVKey;
    }

    /// @notice Update the verifier address
    /// @param _verifier The new verifier address
    function setVerifier(
        address _verifier
    ) external onlyOwner {
        verifier = _verifier;
    }

    /// @notice Update the rego program verification key
    /// @param _regoProgramVKey The new verification key
    function setRegoProgramVKey(
        bytes32 _regoProgramVKey
    ) external onlyOwner {
        regoProgramVKey = _regoProgramVKey;
    }

    /// @notice The entrypoint for verifying the proof of a rego policy evaluation.
    /// @param _publicValues The encoded public values.
    /// @param _proofBytes The encoded proof.
    function verifyRegoProof(
        bytes calldata _publicValues,
        bytes calldata _proofBytes
    ) public view returns (RegoContext memory) {
        ISP1Verifier(verifier).verifyProof(regoProgramVKey, _publicValues, _proofBytes);
        return abi.decode(_publicValues, (RegoContext));
    }
}
