// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IConfidentialDataRegistry} from "../interfaces/IConfidentialDataRegistry.sol";
import {INewtonPolicyClient} from "../interfaces/INewtonPolicyClient.sol";
import {IPolicyClientRegistry} from "../interfaces/IPolicyClientRegistry.sol";

import {Initializable} from "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @title ConfidentialDataRegistry
///
/// @notice Registry for provider-managed, versioned confidential data (blacklists, allowlists,
///         sanctions) with per-policy-client access grants.
///
/// @dev Providers self-register (no gatekeeping) and publish versioned data references pointing
///      to off-chain encrypted blobs. Each provider grants or revokes access per (domain,
///      policyClient) pair. Operators call getConfidentialData at task time to resolve the active
///      data reference for a given (policyClient, domain).
///
///      Two reverse indices are maintained for O(1) lookups:
///      - _clientProviders: (policyClient, domain) -> set of providers with active grants
///      - _grantedClients:  (provider, domain)     -> set of policy clients with active grants
///
///      The contract is deployed behind a TransparentUpgradeableProxy. The implementation
///      constructor calls _disableInitializers() and is stateless. All mutable state is set
///      via initialize().
contract ConfidentialDataRegistry is Initializable, IConfidentialDataRegistry {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------

    /// @notice Whether an address is a registered provider
    mapping(address => bool) public providers;

    /// @notice The latest DataEntry for each (provider, domain) pair
    mapping(address => mapping(bytes32 => DataEntry)) public providerData;

    /// @notice Whether a specific (provider, domain, policyClient) grant is active
    mapping(address => mapping(bytes32 => mapping(address => bool))) public clientGrants;

    /// @notice Reverse index: (policyClient, domain) -> set of providers that have granted access.
    ///         Used by getConfidentialData and getProviders for O(1) set membership and enumeration.
    mapping(address => mapping(bytes32 => EnumerableSet.AddressSet)) internal _clientProviders;

    /// @notice Reverse index: (provider, domain) -> set of policy clients with active grants.
    ///         Used by revokeGlobal to iterate and clear all grants without unbounded external loops.
    mapping(address => mapping(bytes32 => EnumerableSet.AddressSet)) internal _grantedClients;

    /// @notice Reverse index: policyClient -> set of domains with active grants.
    ///         Used by getGrantedDomains for enumerating all domains a policy client has access to.
    mapping(address => EnumerableSet.Bytes32Set) internal _clientDomains;

    /// @notice Pending grants proposed by providers awaiting policy client owner acceptance.
    mapping(address => mapping(bytes32 => mapping(address => bool))) public pendingGrants;

    // -------------------------------------------------------------------------
    // Immutables
    // -------------------------------------------------------------------------

    /// @notice PolicyClientRegistry used to validate client registration.
    ///         Immutable — set on the implementation contract at construction time.
    IPolicyClientRegistry public immutable override policyClientRegistry;

    // -------------------------------------------------------------------------
    // Constructor (implementation only — sets immutables and disables initializers)
    // -------------------------------------------------------------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        address _policyClientRegistry
    ) {
        require(_policyClientRegistry != address(0), InvalidClientRegistryAddress());
        policyClientRegistry = IPolicyClientRegistry(_policyClientRegistry);
        _disableInitializers();
    }

    // -------------------------------------------------------------------------
    // Initializer (proxy — called once after deployment)
    // -------------------------------------------------------------------------

    /// @notice Initialize the registry. No EIP-712 needed — v1 has no signature-based flows.
    function initialize() external initializer {}

    // -------------------------------------------------------------------------
    // Provider registration
    // -------------------------------------------------------------------------

    /// @inheritdoc IConfidentialDataRegistry
    function registerProvider() external override {
        require(!providers[msg.sender], AlreadyRegistered());
        providers[msg.sender] = true;
        emit ProviderRegistered(msg.sender);
    }

    /// @inheritdoc IConfidentialDataRegistry
    function deregisterProvider() external override {
        require(providers[msg.sender], NotRegistered());
        providers[msg.sender] = false;
        emit ProviderDeregistered(msg.sender);
        // Does NOT auto-revoke grants. Providers should call revokeGlobal per domain
        // before deregistering, or use revokeClient/revokeGlobal after deregistering
        // (those functions do not require active registration).
    }

    /// @inheritdoc IConfidentialDataRegistry
    function isRegisteredProvider(
        address provider
    ) external view override returns (bool) {
        return providers[provider];
    }

    // -------------------------------------------------------------------------
    // Data publishing
    // -------------------------------------------------------------------------

    /// @inheritdoc IConfidentialDataRegistry
    function publishData(
        bytes32 domain,
        string calldata dataRefId
    ) external override {
        require(providers[msg.sender], NotRegistered());
        require(domain != bytes32(0), InvalidDomain());
        require(bytes(dataRefId).length > 0, EmptyDataRefId());

        DataEntry storage entry = providerData[msg.sender][domain];
        entry.version += 1;
        entry.latestDataRefId = dataRefId;
        entry.updatedAt = uint64(block.timestamp);

        emit DataPublished(msg.sender, domain, dataRefId, entry.version);
    }

    // -------------------------------------------------------------------------
    // Grant management
    // -------------------------------------------------------------------------

    /// @inheritdoc IConfidentialDataRegistry
    function proposeGrant(
        bytes32 domain,
        address policyClient
    ) external override {
        require(providers[msg.sender], NotRegistered());
        require(domain != bytes32(0), InvalidDomain());
        require(
            policyClientRegistry.isRegisteredClient(policyClient),
            PolicyClientNotRegistered(policyClient)
        );
        require(!clientGrants[msg.sender][domain][policyClient], GrantAlreadyExists());
        require(!pendingGrants[msg.sender][domain][policyClient], GrantAlreadyExists());

        pendingGrants[msg.sender][domain][policyClient] = true;

        emit GrantProposed(msg.sender, domain, policyClient);
    }

    /// @inheritdoc IConfidentialDataRegistry
    function acceptGrant(
        address provider,
        bytes32 domain,
        address policyClient
    ) external override {
        require(
            INewtonPolicyClient(policyClient).getOwner() == msg.sender,
            NotPolicyClientOwner(policyClient, msg.sender)
        );
        require(pendingGrants[provider][domain][policyClient], GrantNotPending());

        pendingGrants[provider][domain][policyClient] = false;
        clientGrants[provider][domain][policyClient] = true;
        _clientProviders[policyClient][domain].add(provider);
        _grantedClients[provider][domain].add(policyClient);
        _clientDomains[policyClient].add(domain);

        emit ClientGranted(provider, domain, policyClient);
    }

    /// @inheritdoc IConfidentialDataRegistry
    function hasPendingGrant(
        address provider,
        bytes32 domain,
        address policyClient
    ) external view override returns (bool) {
        return pendingGrants[provider][domain][policyClient];
    }

    /// @inheritdoc IConfidentialDataRegistry
    function revokeClient(
        bytes32 domain,
        address policyClient
    ) external override {
        // No registration check: deregistered providers can still clean up their grants.
        require(clientGrants[msg.sender][domain][policyClient], GrantNotFound());

        clientGrants[msg.sender][domain][policyClient] = false;
        _clientProviders[policyClient][domain].remove(msg.sender);
        _grantedClients[msg.sender][domain].remove(policyClient);

        // Remove domain from client's domain set if no providers remain for this (client, domain) pair
        if (_clientProviders[policyClient][domain].length() == 0) {
            _clientDomains[policyClient].remove(domain);
        }

        emit ClientRevoked(msg.sender, domain, policyClient);
    }

    /// @inheritdoc IConfidentialDataRegistry
    function revokeGlobal(
        bytes32 domain
    ) external override {
        // No registration check: deregistered providers can still clean up their grants.

        EnumerableSet.AddressSet storage grantedSet = _grantedClients[msg.sender][domain];

        // Iterate from the end to avoid index shifting on remove.
        // at(0) is safe because length > 0 is the loop condition.
        uint256 length = grantedSet.length();
        while (length > 0) {
            address client = grantedSet.at(0);
            clientGrants[msg.sender][domain][client] = false;
            _clientProviders[client][domain].remove(msg.sender);
            grantedSet.remove(client);
            if (_clientProviders[client][domain].length() == 0) {
                _clientDomains[client].remove(domain);
            }
            length = grantedSet.length();
        }

        emit DataRevokedGlobally(msg.sender, domain);
    }

    // -------------------------------------------------------------------------
    // Query functions
    // -------------------------------------------------------------------------

    /// @inheritdoc IConfidentialDataRegistry
    function getConfidentialData(
        address policyClient,
        bytes32 domain
    ) external view override returns (address provider, string memory dataRefId, uint64 version) {
        EnumerableSet.AddressSet storage providerSet = _clientProviders[policyClient][domain];
        require(providerSet.length() > 0, NoGrantForClient(policyClient, domain));

        provider = providerSet.at(0);
        DataEntry storage entry = providerData[provider][domain];
        dataRefId = entry.latestDataRefId;
        version = entry.version;
    }

    /// @inheritdoc IConfidentialDataRegistry
    function getConfidentialDataFrom(
        address policyClient,
        bytes32 domain,
        address provider
    ) external view override returns (string memory dataRefId, uint64 version) {
        require(
            clientGrants[provider][domain][policyClient], NoGrantForClient(policyClient, domain)
        );
        DataEntry storage entry = providerData[provider][domain];
        return (entry.latestDataRefId, entry.version);
    }

    /// @inheritdoc IConfidentialDataRegistry
    function revokeGlobalBatch(
        bytes32 domain,
        uint256 limit
    ) external override {
        // No registration check: deregistered providers can still clean up their grants.
        EnumerableSet.AddressSet storage grantedSet = _grantedClients[msg.sender][domain];
        uint256 remaining = grantedSet.length();
        uint256 count = remaining < limit ? remaining : limit;

        for (uint256 i = 0; i < count;) {
            address client = grantedSet.at(0);
            clientGrants[msg.sender][domain][client] = false;
            _clientProviders[client][domain].remove(msg.sender);
            grantedSet.remove(client);
            if (_clientProviders[client][domain].length() == 0) {
                _clientDomains[client].remove(domain);
            }
            unchecked {
                ++i;
            }
        }

        if (grantedSet.length() == 0) {
            emit DataRevokedGlobally(msg.sender, domain);
        }
    }

    /// @inheritdoc IConfidentialDataRegistry
    function getProviders(
        address policyClient,
        bytes32 domain
    ) external view override returns (address[] memory) {
        return _clientProviders[policyClient][domain].values();
    }

    /// @inheritdoc IConfidentialDataRegistry
    function hasGrant(
        address provider,
        bytes32 domain,
        address policyClient
    ) external view override returns (bool) {
        return clientGrants[provider][domain][policyClient];
    }

    /// @inheritdoc IConfidentialDataRegistry
    function getDataEntry(
        address provider,
        bytes32 domain
    ) external view override returns (DataEntry memory) {
        return providerData[provider][domain];
    }

    /// @inheritdoc IConfidentialDataRegistry
    function getGrantedDomains(
        address policyClient
    ) external view override returns (bytes32[] memory) {
        return _clientDomains[policyClient].values();
    }
}
