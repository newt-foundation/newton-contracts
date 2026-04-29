// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {INewtonAddressesProvider} from "../interfaces/INewtonAddressesProvider.sol";
import {SemVerMixin} from "../mixins/SemVerMixin.sol";

import {Initializable} from "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";

/// @title NewtonAddressesProvider
///
/// @notice On-chain directory for all Newton Protocol contract addresses on a given chain.
///         One instance per chain — operators, challengers, and contracts discover each
///         other through this provider rather than off-chain deployment JSONs.
///
/// @dev Typed getters map to well-known bytes32 IDs internally, so getTaskManager() and
///      getAddress(keccak256("TASK_MANAGER")) always return the same value.
///      All setters validate that the target address has deployed code (extcodesize > 0)
///      to catch stale or wrong-chain addresses at registration time.
///
///      Follows the Aave V3 PoolAddressesProvider pattern adapted for Newton's contract
///      graph. Deployed behind an upgradeable proxy for future extensibility.
contract NewtonAddressesProvider is
    Initializable,
    OwnableUpgradeable,
    SemVerMixin,
    INewtonAddressesProvider
{
    // -------------------------------------------------------------------------
    // Well-known IDs
    // -------------------------------------------------------------------------

    bytes32 public constant TASK_MANAGER = keccak256("TASK_MANAGER");
    bytes32 public constant CHALLENGE_VERIFIER = keccak256("CHALLENGE_VERIFIER");
    bytes32 public constant ATTESTATION_VALIDATOR = keccak256("ATTESTATION_VALIDATOR");
    bytes32 public constant OPERATOR_REGISTRY = keccak256("OPERATOR_REGISTRY");
    bytes32 public constant POLICY_CLIENT_REGISTRY = keccak256("POLICY_CLIENT_REGISTRY");
    bytes32 public constant BATCH_TASK_MANAGER = keccak256("BATCH_TASK_MANAGER");
    bytes32 public constant SERVICE_MANAGER = keccak256("SERVICE_MANAGER");
    bytes32 public constant POLICY_FACTORY = keccak256("POLICY_FACTORY");
    bytes32 public constant POLICY_DATA_FACTORY = keccak256("POLICY_DATA_FACTORY");
    bytes32 public constant STATE_COMMIT_REGISTRY = keccak256("STATE_COMMIT_REGISTRY");
    bytes32 public constant IDENTITY_REGISTRY = keccak256("IDENTITY_REGISTRY");
    bytes32 public constant CONFIDENTIAL_DATA_REGISTRY = keccak256("CONFIDENTIAL_DATA_REGISTRY");
    bytes32 public constant EPOCH_REGISTRY = keccak256("EPOCH_REGISTRY");
    bytes32 public constant ENCLAVE_VERSION_REGISTRY = keccak256("ENCLAVE_VERSION_REGISTRY");
    bytes32 public constant REGO_VERIFIER = keccak256("REGO_VERIFIER");
    bytes32 public constant VIEW_BN254_CERTIFICATE_VERIFIER =
        keccak256("VIEW_BN254_CERTIFICATE_VERIFIER");
    bytes32 public constant SOCKET_REGISTRY = keccak256("SOCKET_REGISTRY");

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------

    /// @notice Maps contract identifier → deployed address
    mapping(bytes32 => address) internal _addresses;

    // -------------------------------------------------------------------------
    // Gap
    // -------------------------------------------------------------------------

    uint256[49] private __gap;

    // -------------------------------------------------------------------------
    // Constructor (implementation only)
    // -------------------------------------------------------------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        string memory _version
    ) SemVerMixin(_version) {
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
    // Internal
    // -------------------------------------------------------------------------

    function _setAddress(
        bytes32 id,
        address addr
    ) internal {
        if (addr == address(0)) revert ZeroAddress(id);
        if (addr.code.length == 0) revert NoContractCode(id, addr);

        address old = _addresses[id];
        _addresses[id] = addr;
        emit AddressSet(id, old, addr);
    }

    // -------------------------------------------------------------------------
    // Core protocol — typed getters
    // -------------------------------------------------------------------------

    /// @inheritdoc INewtonAddressesProvider
    function getTaskManager() external view returns (address) {
        return _addresses[TASK_MANAGER];
    }

    /// @inheritdoc INewtonAddressesProvider
    function getChallengeVerifier() external view returns (address) {
        return _addresses[CHALLENGE_VERIFIER];
    }

    /// @inheritdoc INewtonAddressesProvider
    function getAttestationValidator() external view returns (address) {
        return _addresses[ATTESTATION_VALIDATOR];
    }

    /// @inheritdoc INewtonAddressesProvider
    function getOperatorRegistry() external view returns (address) {
        return _addresses[OPERATOR_REGISTRY];
    }

    /// @inheritdoc INewtonAddressesProvider
    function getPolicyClientRegistry() external view returns (address) {
        return _addresses[POLICY_CLIENT_REGISTRY];
    }

    /// @inheritdoc INewtonAddressesProvider
    function getBatchTaskManager() external view returns (address) {
        return _addresses[BATCH_TASK_MANAGER];
    }

    /// @inheritdoc INewtonAddressesProvider
    function getServiceManager() external view returns (address) {
        return _addresses[SERVICE_MANAGER];
    }

    /// @inheritdoc INewtonAddressesProvider
    function getPolicyFactory() external view returns (address) {
        return _addresses[POLICY_FACTORY];
    }

    /// @inheritdoc INewtonAddressesProvider
    function getPolicyDataFactory() external view returns (address) {
        return _addresses[POLICY_DATA_FACTORY];
    }

    // -------------------------------------------------------------------------
    // Private data storage — typed getters
    // -------------------------------------------------------------------------

    /// @inheritdoc INewtonAddressesProvider
    function getStateCommitRegistry() external view returns (address) {
        return _addresses[STATE_COMMIT_REGISTRY];
    }

    // -------------------------------------------------------------------------
    // Privacy layer — typed getters
    // -------------------------------------------------------------------------

    /// @inheritdoc INewtonAddressesProvider
    function getIdentityRegistry() external view returns (address) {
        return _addresses[IDENTITY_REGISTRY];
    }

    /// @inheritdoc INewtonAddressesProvider
    function getConfidentialDataRegistry() external view returns (address) {
        return _addresses[CONFIDENTIAL_DATA_REGISTRY];
    }

    /// @inheritdoc INewtonAddressesProvider
    function getEpochRegistry() external view returns (address) {
        return _addresses[EPOCH_REGISTRY];
    }

    // -------------------------------------------------------------------------
    // TEE layer — typed getters
    // -------------------------------------------------------------------------

    /// @inheritdoc INewtonAddressesProvider
    function getEnclaveVersionRegistry() external view returns (address) {
        return _addresses[ENCLAVE_VERSION_REGISTRY];
    }

    // -------------------------------------------------------------------------
    // Verification — typed getters
    // -------------------------------------------------------------------------

    /// @inheritdoc INewtonAddressesProvider
    function getRegoVerifier() external view returns (address) {
        return _addresses[REGO_VERIFIER];
    }

    /// @inheritdoc INewtonAddressesProvider
    function getViewBN254CertificateVerifier() external view returns (address) {
        return _addresses[VIEW_BN254_CERTIFICATE_VERIFIER];
    }

    // -------------------------------------------------------------------------
    // Cross-chain — typed getters
    // -------------------------------------------------------------------------

    /// @inheritdoc INewtonAddressesProvider
    function getSocketRegistry() external view returns (address) {
        return _addresses[SOCKET_REGISTRY];
    }

    // -------------------------------------------------------------------------
    // Generic — extensible directory
    // -------------------------------------------------------------------------

    /// @inheritdoc INewtonAddressesProvider
    function getAddress(
        bytes32 id
    ) external view returns (address) {
        return _addresses[id];
    }

    // -------------------------------------------------------------------------
    // Admin — owner-only setters
    // -------------------------------------------------------------------------

    /// @inheritdoc INewtonAddressesProvider
    function setTaskManager(
        address addr
    ) external onlyOwner {
        _setAddress(TASK_MANAGER, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setChallengeVerifier(
        address addr
    ) external onlyOwner {
        _setAddress(CHALLENGE_VERIFIER, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setAttestationValidator(
        address addr
    ) external onlyOwner {
        _setAddress(ATTESTATION_VALIDATOR, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setOperatorRegistry(
        address addr
    ) external onlyOwner {
        _setAddress(OPERATOR_REGISTRY, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setPolicyClientRegistry(
        address addr
    ) external onlyOwner {
        _setAddress(POLICY_CLIENT_REGISTRY, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setBatchTaskManager(
        address addr
    ) external onlyOwner {
        _setAddress(BATCH_TASK_MANAGER, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setServiceManager(
        address addr
    ) external onlyOwner {
        _setAddress(SERVICE_MANAGER, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setPolicyFactory(
        address addr
    ) external onlyOwner {
        _setAddress(POLICY_FACTORY, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setPolicyDataFactory(
        address addr
    ) external onlyOwner {
        _setAddress(POLICY_DATA_FACTORY, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setStateCommitRegistry(
        address addr
    ) external onlyOwner {
        _setAddress(STATE_COMMIT_REGISTRY, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setIdentityRegistry(
        address addr
    ) external onlyOwner {
        _setAddress(IDENTITY_REGISTRY, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setConfidentialDataRegistry(
        address addr
    ) external onlyOwner {
        _setAddress(CONFIDENTIAL_DATA_REGISTRY, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setEpochRegistry(
        address addr
    ) external onlyOwner {
        _setAddress(EPOCH_REGISTRY, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setEnclaveVersionRegistry(
        address addr
    ) external onlyOwner {
        _setAddress(ENCLAVE_VERSION_REGISTRY, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setSocketRegistry(
        address addr
    ) external onlyOwner {
        _setAddress(SOCKET_REGISTRY, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setRegoVerifier(
        address addr
    ) external onlyOwner {
        _setAddress(REGO_VERIFIER, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setViewBN254CertificateVerifier(
        address addr
    ) external onlyOwner {
        _setAddress(VIEW_BN254_CERTIFICATE_VERIFIER, addr);
    }

    /// @inheritdoc INewtonAddressesProvider
    function setAddress(
        bytes32 id,
        address addr
    ) external onlyOwner {
        _setAddress(id, addr);
    }
}
