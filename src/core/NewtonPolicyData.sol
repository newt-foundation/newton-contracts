// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin-upgrades/contracts/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts/interfaces/IERC165.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./NewtonPolicyDataFactory.sol";
import "../interfaces/INewtonPolicyData.sol";
import "../interfaces/INewtonPolicy.sol";
import "./NewtonMessage.sol";

contract NewtonPolicyData is
    Initializable,
    OwnableUpgradeable,
    ERC165Upgradeable,
    INewtonPolicyData
{
    using ECDSA for bytes32;

    /* STORAGE */
    address public factory;
    string private _wasmCid;
    string private _secretsSchemaCid;
    uint32 private _expireAfter;
    string private _metadataCid;
    INewtonPolicyData.AttestationInfo private _attestationInfo;

    /* ERRORS */
    error OnlyNewtonPolicy();
    error InterfaceNotSupported();
    error InvalidSignature();
    error SignatureVerificationFailed();
    error InvalidPolicyData(bytes data);
    error InvalidAttestationInfo();

    /* EVENTS */
    event PolicyDataMetadataCidUpdated(string metadataCid);
    event SecretsSchemaCidUpdated(string secretsSchemaCid);
    event AttestationInfoUpdated(INewtonPolicyData.AttestationInfo attestationInfo);

    /* Modifiers */
    modifier onlyNewtonPolicy() {
        require(msg.sender.code.length > 0, OnlyNewtonPolicy());

        bytes4 interfaceId = type(INewtonPolicy).interfaceId;

        (bool success, bytes memory result) = msg.sender
            .staticcall(abi.encodeWithSelector(IERC165.supportsInterface.selector, interfaceId));

        require(
            success && result.length == 32 && abi.decode(result, (bool)), InterfaceNotSupported()
        );

        _;
    }

    function initialize(
        address _factory,
        string calldata wasmCid,
        string calldata secretsSchemaCid,
        uint32 expireAfter,
        string calldata metadataCid,
        address _owner
    ) public initializer {
        __Ownable_init();
        _transferOwnership(_owner);
        __ERC165_init();
        factory = _factory;
        _wasmCid = wasmCid;
        _secretsSchemaCid = secretsSchemaCid;
        _expireAfter = expireAfter;
        _metadataCid = metadataCid;
    }

    function getMetadataCid() public view returns (string memory) {
        return _metadataCid;
    }

    function setMetadataCid(
        string calldata metadataCid
    ) public onlyOwner {
        _metadataCid = metadataCid;
        emit PolicyDataMetadataCidUpdated(metadataCid);
    }

    function getWasmCid() public view returns (string memory) {
        return _wasmCid;
    }

    function getSecretsSchemaCid() public view returns (string memory) {
        return _secretsSchemaCid;
    }

    function setSecretsSchemaCid(
        string calldata secretsSchemaCid
    ) public onlyOwner {
        _secretsSchemaCid = secretsSchemaCid;
        emit SecretsSchemaCidUpdated(secretsSchemaCid);
    }

    function getAttestationInfo() public view returns (INewtonPolicyData.AttestationInfo memory) {
        return _attestationInfo;
    }

    function setAttestationInfo(
        INewtonPolicyData.AttestationInfo calldata attestationInfo
    ) public onlyOwner {
        if (
            attestationInfo.attestationType == AttestationType.ECDSA
                || attestationInfo.attestationType == AttestationType.BLS12_381
                || attestationInfo.attestationType == AttestationType.BN254
        ) {
            require(attestationInfo.attesters.length > 0, InvalidAttestationInfo());
        } else if (attestationInfo.attestationType == AttestationType.GROTH16) {
            require(
                attestationInfo.verifier != address(0)
                    && attestationInfo.verificationKey != bytes32(0),
                InvalidAttestationInfo()
            );
        }
        _attestationInfo = attestationInfo;
        emit AttestationInfoUpdated(attestationInfo);
    }

    function getExpireAfter() public view returns (uint32) {
        return _expireAfter;
    }

    // TODO: implement the attest function
    function attest(
        NewtonMessage.PolicyData calldata policyData
    ) external view returns (bool) {
        require(policyData.data.length > 0, InvalidPolicyData(policyData.data));

        if (_attestationInfo.attestationType == INewtonPolicyData.AttestationType.ECDSA) {
            return _verifyECDSASignature(policyData);
        }
        // TODO: implement other validation type verications
        return false;
    }

    /// @notice Verifies ECDSA signature for policy data attestation
    /// @param policyData The policy data containing the attestation signature
    /// @return True if signature is valid, false otherwise
    function _verifyECDSASignature(
        NewtonMessage.PolicyData calldata policyData
    ) internal view returns (bool) {
        // Check if attestation has the correct length (65 bytes for ECDSA signature)
        if (policyData.attestation.length != 65) {
            return false;
        }

        (address signer, ECDSA.RecoverError error) = ECDSA.tryRecover(
            keccak256(
                abi.encodePacked(
                    policyData.wasmArgs,
                    policyData.data,
                    policyData.policyDataAddress,
                    policyData.expireBlock,
                    _wasmCid,
                    _secretsSchemaCid
                )
            ),
            policyData.attestation
        );

        if (error != ECDSA.RecoverError.NoError) {
            return false;
        }

        // Check if the signer is in the attesters list
        for (uint256 i; i < _attestationInfo.attesters.length; ++i) {
            if (signer == _attestationInfo.attesters[i]) {
                return true;
            }
        }
        return false;
    }

    function isPolicyDataVerified() external view returns (bool) {
        return
            NewtonPolicyDataFactory(factory).getPolicyDataVerificationInfo(address(this)).verified;
    }

    /// @notice Function to check if a contract implements an interface
    /// @param interfaceId The interface identifier to check
    /// @return True if the contract implements the interface, false otherwise
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165Upgradeable, IERC165) returns (bool) {
        return
            interfaceId == type(INewtonPolicyData).interfaceId
                || super.supportsInterface(interfaceId);
    }
}
