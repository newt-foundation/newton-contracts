// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IEnclaveVersionRegistry} from "../interfaces/IEnclaveVersionRegistry.sol";
import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";
import {INewtonAddressesProvider} from "../interfaces/INewtonAddressesProvider.sol";
import {AddressesProviderConsumer} from "../mixins/AddressesProviderConsumer.sol";

import {Initializable} from "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";

/// @title EnclaveVersionRegistry
///
/// @notice On-chain registry for whitelisted Nitro Enclave image measurements.
///         Stores keccak256(PCR0) hashes that identify approved enclave binaries.
///         Operators must run an enclave whose PCR0 matches a whitelisted version.
///
/// @dev PCR0 is the SHA-384 hash of the Enclave Image File (EIF), measured by the
///      Nitro hypervisor at launch. We store keccak256(pcr0_bytes) on-chain for gas
///      efficiency — the SP1 attestation circuit (NEWT-994, future work) will hash
///      the raw 48-byte PCR0 from the attestation doc and compare against the
///      on-chain value.
///
///      Rolling upgrades: multiple versions can be active simultaneously. Operators
///      upgrade at their own pace within the window between activation and deprecation.
///      Reproducible builds: same Dockerfile + Rust toolchain + source commit = same PCR0.
///
///      Access control: only task generators (gateway operators) can activate/deprecate
///      versions. This matches the EpochRegistry pattern where the gateway is the
///      trusted orchestrator for protocol state transitions.
contract EnclaveVersionRegistry is
    Initializable,
    OwnableUpgradeable,
    AddressesProviderConsumer,
    IEnclaveVersionRegistry
{
    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------

    /// @notice Version entries indexed by pcr0Hash.
    mapping(bytes32 => EnclaveVersion) internal _versions;

    /// @notice Count of currently active (non-deprecated) versions.
    uint256 internal _activeCount;

    /// @notice keccak256 of the AWS Nitro root CA DER certificate.
    ///         Used by the SP1 attestation circuit to bind the root trust anchor.
    ///         Set by admin via setRootCertHash(). Zero means not configured.
    bytes32 public rootCertHash;

    /// @notice Operator enclave ephemeral X25519 public keys.
    ///         Registered by the gateway after off-chain attestation verification.
    ///         Changes on enclave reboot (ephemeral per boot).
    mapping(address => bytes32) internal _enclaveKeys;

    // -------------------------------------------------------------------------
    // Gap
    // -------------------------------------------------------------------------

    uint256[46] private __gap;

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    modifier onlyTaskGenerator() {
        require(
            operatorRegistry.isTaskGenerator(msg.sender), IEnclaveVersionRegistry.NotTaskGenerator()
        );
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor (implementation only)
    // -------------------------------------------------------------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        INewtonAddressesProvider _provider
    ) AddressesProviderConsumer(_provider) {
        require(address(operatorRegistry) != address(0));
        _disableInitializers();
    }

    // -------------------------------------------------------------------------
    // Initializer
    // -------------------------------------------------------------------------

    function initialize(
        address _owner
    ) external initializer {
        __Ownable_init();
        _transferOwnership(_owner);
    }

    // -------------------------------------------------------------------------
    // Task generator functions
    // -------------------------------------------------------------------------

    /// @inheritdoc IEnclaveVersionRegistry
    function activateVersion(
        bytes32 pcr0Hash,
        string calldata label
    ) external onlyTaskGenerator {
        require(pcr0Hash != bytes32(0), InvalidPcr0Hash());
        require(_versions[pcr0Hash].activatedAt == 0, VersionAlreadyRegistered(pcr0Hash));

        _versions[pcr0Hash] =
            EnclaveVersion({activatedAt: uint64(block.number), deprecatedAt: 0, label: label});

        unchecked {
            ++_activeCount;
        }

        emit EnclaveVersionActivated(pcr0Hash, label);
    }

    /// @inheritdoc IEnclaveVersionRegistry
    function deprecateVersion(
        bytes32 pcr0Hash
    ) external onlyTaskGenerator {
        EnclaveVersion storage v = _versions[pcr0Hash];
        require(v.activatedAt != 0, VersionNotRegistered(pcr0Hash));
        require(v.deprecatedAt == 0, VersionAlreadyDeprecated(pcr0Hash));

        v.deprecatedAt = uint64(block.number);

        unchecked {
            --_activeCount;
        }

        emit EnclaveVersionDeprecated(pcr0Hash);
    }

    // -------------------------------------------------------------------------
    // View functions
    // -------------------------------------------------------------------------

    /// @inheritdoc IEnclaveVersionRegistry
    function isActiveVersion(
        bytes32 pcr0Hash
    ) external view returns (bool) {
        EnclaveVersion storage v = _versions[pcr0Hash];
        return v.activatedAt != 0 && v.deprecatedAt == 0;
    }

    /// @inheritdoc IEnclaveVersionRegistry
    function getVersion(
        bytes32 pcr0Hash
    ) external view returns (EnclaveVersion memory) {
        return _versions[pcr0Hash];
    }

    /// @inheritdoc IEnclaveVersionRegistry
    function activeVersionCount() external view returns (uint256) {
        return _activeCount;
    }

    // -------------------------------------------------------------------------
    // Enclave key registration
    // -------------------------------------------------------------------------

    /// @inheritdoc IEnclaveVersionRegistry
    function registerEnclaveKey(
        address operator,
        bytes32 pubkey
    ) external onlyTaskGenerator {
        require(operator != address(0), InvalidOperator());
        require(pubkey != bytes32(0), InvalidPubkey());

        _enclaveKeys[operator] = pubkey;
        emit EnclaveKeyRegistered(operator, pubkey);
    }

    /// @inheritdoc IEnclaveVersionRegistry
    function getEnclaveKey(
        address operator
    ) external view returns (bytes32) {
        return _enclaveKeys[operator];
    }

    // -------------------------------------------------------------------------
    // Admin functions
    // -------------------------------------------------------------------------

    /// @notice Set the trusted AWS Nitro root CA certificate hash.
    ///         The SP1 attestation circuit uses this to bind the root trust anchor.
    /// @param _rootCertHash keccak256 of the root CA DER bytes
    function setRootCertHash(
        bytes32 _rootCertHash
    ) external onlyOwner {
        rootCertHash = _rootCertHash;
        emit RootCertHashUpdated(_rootCertHash);
    }

    event RootCertHashUpdated(bytes32 indexed rootCertHash);
}
