// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IPolicyClientRegistry} from "../interfaces/IPolicyClientRegistry.sol";

/// @title IConfidentialDataRegistry
/// @notice Registry for provider-managed, versioned confidential data (blacklists, allowlists, sanctions)
///         with per-policy-client access grants.
///
/// @dev Providers self-register and publish versioned data references (content hashes pointing to
///      off-chain encrypted blobs). Each provider controls which policy clients can access their
///      data for a given domain. Operators use getConfidentialData to resolve the active data
///      reference for a given (policyClient, domain) pair.
interface IConfidentialDataRegistry {
    /// @notice A versioned data entry for a (provider, domain) pair
    struct DataEntry {
        /// content-addressed reference to the off-chain encrypted data blob
        string latestDataRefId;
        /// monotonically-increasing version counter, starting at 1 on first publish
        uint64 version;
        /// block.timestamp at the time of the last publish
        uint64 updatedAt;
    }

    // Events

    /// @notice Emitted when a provider self-registers
    event ProviderRegistered(address indexed provider);

    /// @notice Emitted when a provider deregisters
    event ProviderDeregistered(address indexed provider);

    /// @notice Emitted when a provider publishes a new data version for a domain
    event DataPublished(
        address indexed provider, bytes32 indexed domain, string dataRefId, uint64 version
    );

    /// @notice Emitted when a provider grants access for a domain to a policy client
    event ClientGranted(
        address indexed provider, bytes32 indexed domain, address indexed policyClient
    );

    /// @notice Emitted when a provider revokes access for a domain from a specific policy client
    event ClientRevoked(
        address indexed provider, bytes32 indexed domain, address indexed policyClient
    );

    /// @notice Emitted when a provider revokes access for a domain from all granted clients
    event DataRevokedGlobally(address indexed provider, bytes32 indexed domain);

    // Errors

    /// @notice The provider is already registered
    error AlreadyRegistered();

    /// @notice The caller is not a registered provider
    error NotRegistered();

    /// @notice The domain is the zero bytes32 value
    error InvalidDomain();

    /// @notice The dataRefId string is empty
    error EmptyDataRefId();

    /// @notice The grant already exists for this (provider, domain, policyClient) triple
    error GrantAlreadyExists();

    /// @notice The grant does not exist for this (provider, domain, policyClient) triple
    error GrantNotFound();

    /// @notice No providers have granted access to this (policyClient, domain) pair
    error NoGrantForClient(address policyClient, bytes32 domain);

    /// @notice The policy client is not registered (or not active) in the PolicyClientRegistry
    error PolicyClientNotRegistered(address client);

    /// @notice The constructor was called with a zero address for the policy client registry
    error InvalidClientRegistryAddress();

    /// @notice No pending grant exists for this (provider, domain, policyClient) triple
    error GrantNotPending();

    /// @notice Caller is not the owner of the policy client
    error NotPolicyClientOwner(address policyClient, address caller);

    /// @notice Emitted when a provider proposes a grant (pending acceptance by policy client owner)
    event GrantProposed(
        address indexed provider, bytes32 indexed domain, address indexed policyClient
    );

    // Functions

    /// @notice Self-register as a confidential data provider. No gatekeeping.
    function registerProvider() external;

    /// @notice Deregister as a confidential data provider.
    ///         Does not revoke existing grants or delete published data.
    function deregisterProvider() external;

    /// @notice Check whether an address is a registered provider
    /// @param provider The address to check
    /// @return True if registered
    function isRegisteredProvider(
        address provider
    ) external view returns (bool);

    /// @notice Publish a new data version for a domain. Increments the version counter.
    ///         Provider must be registered. Overwrites the previous latestDataRefId.
    /// @param domain The bytes32 domain identifier (e.g., keccak256("sanctions.ofac"))
    /// @param dataRefId Content-addressed reference to the off-chain encrypted data blob
    function publishData(
        bytes32 domain,
        string calldata dataRefId
    ) external;

    /// @notice Propose a grant for a policy client. Does NOT activate the grant — the
    ///         policy client owner must call acceptGrant to activate it. Prevents
    ///         malicious providers from unilaterally injecting data into policy evaluation.
    /// @param domain The domain to propose access for
    /// @param policyClient The policy client to propose access to
    function proposeGrant(
        bytes32 domain,
        address policyClient
    ) external;

    /// @notice Accept a pending grant proposed by a provider. Only callable by the policy
    ///         client's owner (via INewtonPolicyClient.getOwner()). Activates the grant.
    /// @param provider The provider that proposed the grant
    /// @param domain The domain to accept access for
    /// @param policyClient The policy client to accept access for
    function acceptGrant(
        address provider,
        bytes32 domain,
        address policyClient
    ) external;

    /// @notice Check whether a pending (unaccepted) grant exists
    /// @param provider The provider address
    /// @param domain The domain
    /// @param policyClient The policy client
    /// @return True if a pending grant exists
    function hasPendingGrant(
        address provider,
        bytes32 domain,
        address policyClient
    ) external view returns (bool);

    /// @notice Revoke a specific policy client's access to the caller's data for a domain
    /// @param domain The domain to revoke access for
    /// @param policyClient The policy client to revoke
    function revokeClient(
        bytes32 domain,
        address policyClient
    ) external;

    /// @notice Revoke all policy client grants for the caller's data for a domain
    /// @param domain The domain to revoke globally
    function revokeGlobal(
        bytes32 domain
    ) external;

    /// @notice Revoke up to `limit` grants for a domain (paginated for gas safety).
    ///         Call repeatedly until getGrantedClientCount returns 0.
    ///         Does not require active registration — deregistered providers can call this.
    /// @param domain The domain to revoke
    /// @param limit Maximum number of grants to revoke in this call
    function revokeGlobalBatch(
        bytes32 domain,
        uint256 limit
    ) external;

    /// @notice Resolve the active data reference for a (policyClient, domain) pair.
    ///         Returns data from the first granted provider found. Used by operators at task time.
    /// @param policyClient The policy client requesting data access
    /// @param domain The domain to look up
    /// @return provider The provider whose data is returned
    /// @return dataRefId The latest data reference from that provider
    /// @return version The version of the returned data entry
    function getConfidentialData(
        address policyClient,
        bytes32 domain
    ) external view returns (address provider, string memory dataRefId, uint64 version);

    /// @notice Get data from a specific provider for a (policyClient, domain) pair.
    ///         Use this when the caller knows which provider to query, avoiding non-deterministic
    ///         provider selection from getConfidentialData.
    /// @param policyClient The policy client requesting data access
    /// @param domain The domain to look up
    /// @param provider The specific provider to query
    /// @return dataRefId The latest data reference from that provider
    /// @return version The version of the returned data entry
    function getConfidentialDataFrom(
        address policyClient,
        bytes32 domain,
        address provider
    ) external view returns (string memory dataRefId, uint64 version);

    /// @notice Return all providers that have granted access to a (policyClient, domain) pair
    /// @param policyClient The policy client to query
    /// @param domain The domain to query
    /// @return providers Array of provider addresses with active grants
    function getProviders(
        address policyClient,
        bytes32 domain
    ) external view returns (address[] memory providers);

    /// @notice Check whether a grant exists for a (provider, domain, policyClient) triple
    /// @param provider The provider address
    /// @param domain The domain
    /// @param policyClient The policy client
    /// @return True if the grant is active
    function hasGrant(
        address provider,
        bytes32 domain,
        address policyClient
    ) external view returns (bool);

    /// @notice Direct lookup of a provider's DataEntry for a domain
    /// @param provider The provider address
    /// @param domain The domain
    /// @return The DataEntry struct (latestDataRefId, version, updatedAt)
    function getDataEntry(
        address provider,
        bytes32 domain
    ) external view returns (DataEntry memory);

    /// @notice The PolicyClientRegistry used to validate client registration on proposeGrant
    /// @return The registry address
    function policyClientRegistry() external view returns (IPolicyClientRegistry);

    /// @notice Return all domains that have at least one active grant for a policy client.
    ///         Operators use this at task time to enumerate which confidential data domains
    ///         are available for a given policy client, instead of relying on policyParams.
    /// @param policyClient The policy client to query
    /// @return Array of bytes32 domain identifiers with active grants
    function getGrantedDomains(
        address policyClient
    ) external view returns (bytes32[] memory);

    /// @notice Check whether any confidential data domain is granted to this policy client.
    ///         Used for on-chain privacy task detection — if true, the task involves
    ///         confidential data and requires TEE attestation for privacy protection.
    /// @param policyClient The policy client to query
    /// @return True if at least one domain has an active grant for this policy client
    function hasGrantedDomains(
        address policyClient
    ) external view returns (bool);
}
