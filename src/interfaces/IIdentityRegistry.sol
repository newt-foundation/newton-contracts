// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IPolicyClientRegistry} from "../interfaces/IPolicyClientRegistry.sol";
import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";

interface IIdentityRegistry {
    // storage accessors

    /// mapping that holds the encrypted identity.
    function identityData(
        address identityOwner,
        bytes32 identityDomain
    ) external view returns (string memory identityData);

    /// mapping that holds the linking of client to data
    function policyClientLinks(
        address policyClientAddress,
        address clientUser,
        bytes32 identityDomain
    ) external view returns (address linkedSigner);

    // typehashes for ERC-712 signature parsing
    function LINK_SIGNER_TYPEHASH() external view returns (bytes32);
    function LINK_USER_TYPEHASH() external view returns (bytes32);
    function REGISTER_IDENTITY_TYPEHASH() external view returns (bytes32);

    /// event for when an identity is registered for indexing the data
    event IdentityBound(address indexed identityOwner, bytes32 identityDomain, string identityData);

    /// event for when an identity is linked to a new policy client
    event IdentityLinked(
        address indexed identityOwner,
        address indexed policyClient,
        address indexed policyClientUser,
        bytes32 identityDomain
    );

    /// event for when an identity is unlinked from a policy client
    event IdentityUnlinked(
        address indexed identityOwner,
        address indexed policyClient,
        address indexed policyClientUser,
        bytes32 identityDomain
    );

    /// error when the contract is initialized with a zero valued operator registry address
    error InvalidOperatorRegistryAddress();

    /// error when the contract is initialized with a zero valued policy client registry address
    error InvalidClientRegistryAddress();

    /// error when identity data is submitted for the zero domain
    error InvalidIdentityDomain();

    /// error when someone tries to link an identity, but provides an empty array of domains to link
    error NoEmptyDomainsArray();

    /// error when someone tries to link more than MAX_LINKS domains at once
    error TooManyDomainsAtOnce();

    /// error when someone tries to link an identity, but does not provide a valid signature
    error InvalidSignature();

    /// error when the signature deadline has already passed (according to block.timestamp)
    error SignatureExpired();

    /// error when someone tries to unlink data that isn't linked to them
    error InvalidUnlinker();

    /// error when a link already exists for a different identity owner
    error LinkAlreadyExists(address policyClient, address clientUser, bytes32 identityDomain);

    /// error when a policy client is not registered (or not active) in the PolicyClientRegistry
    error PolicyClientNotRegistered(address client);

    /// error when the gateway signature on registerIdentityData is not from a valid task generator
    error InvalidIdentitySubmitter();

    /**
     * Register identity data reference for the caller (identity owner).
     * Requires a gateway signature proving the caller uploaded the data.
     *
     * @param _identityDomain this marks what type of data is associated
     * @param _dataRefId content-addressed reference to off-chain encrypted identity data
     * @param _gatewaySignature signature by a task generator over (owner, domain, dataRefId, deadline)
     * @param _deadline signature expiration timestamp
     */
    function registerIdentityData(
        bytes32 _identityDomain,
        string memory _dataRefId,
        bytes calldata _gatewaySignature,
        uint256 _deadline
    ) external;

    /**
     * function to link data if the msg.sender controls all elements of the system
     *
     * @param _policyClient the policy client where the data is to be associated
     * @param _identityDomains this specifies what type of data is associated
     */
    function linkIdentityAsSignerAndUser(
        address _policyClient,
        bytes32[] calldata _identityDomains
    ) external;

    /**
     * function to link existing data to a NewtonPolicyClient as the identityOwner for that data
     *
     * @param _policyClient the policy client where the data is to be associated
     * @param _identityDomains this specifies what type of data is associated
     * @param _clientUser the address that will use the data on this policy client
     * @param _signature signature by the identityOwner (msg.sender) to prove that this linking should be allowed
     * @param _nonce the nonce for the signature
     * @param _deadline the deadline for the signature
     */
    function linkIdentityAsSigner(
        address _policyClient,
        bytes32[] calldata _identityDomains,
        address _clientUser,
        bytes calldata _signature,
        uint256 _nonce,
        uint256 _deadline
    ) external;

    /**
     * function to link existing data to a NewtonPolicyClient as the user of that client
     *
     * @param _policyClient the policy client where the data is to be associated
     * @param _identityDomains this specifies what type of data is associated
     * @param _identityOwner the identityOwner being used to authorize access to the existing identity
     * @param _signature signature by the _identityOwner to prove that this linking should be allowed
     * @param _nonce the nonce for the signature
     * @param _deadline the deadline for the signature
     */
    function linkIdentityAsUser(
        address _identityOwner,
        address _policyClient,
        bytes32[] calldata _identityDomains,
        bytes calldata _signature,
        uint256 _nonce,
        uint256 _deadline
    ) external;

    /**
     * function to link existing data to a NewtonPolicyClient as a 3rd party using signatures from both addresses involved
     *
     * @param _identityOwner the identityOwner being used to authorize access to the existing identity
     * @param _clientUser the address that will use the data on this policy client
     * @param _policyClient the policy client where the data is to be associated
     * @param _identityDomains this specifies what type of data is associated
     * @param _identityOwnerSignature signature by the _identityOwner to prove that this linking should be allowed
     * @param _identityOwnerNonce the nonce for the identityOwner signature
     * @param _identityOwnerDeadline the deadline for the identityOwner signature
     * @param _clientUserSignature signature by the _clientUser to prove that this linking should be allowed
     * @param _clientUserNonce the nonce for the user signature
     * @param _clientUserDeadline the deadline for the user signature
     */
    function linkIdentity(
        address _identityOwner,
        address _clientUser,
        address _policyClient,
        bytes32[] calldata _identityDomains,
        bytes calldata _identityOwnerSignature,
        uint256 _identityOwnerNonce,
        uint256 _identityOwnerDeadline,
        bytes calldata _clientUserSignature,
        uint256 _clientUserNonce,
        uint256 _clientUserDeadline
    ) external;

    /**
     * function to unlink existing links, only useable if msg.sender is the identity that is linked
     *
     * @param _clientUser the address that has the linked data on this policy client
     * @param _policyClient the policy client where the data is associated
     * @param _identityDomains this specifies what type of data to unlink
     */
    function unlinkIdentityAsSigner(
        address _clientUser,
        address _policyClient,
        bytes32[] calldata _identityDomains
    ) external;

    /**
     * function to unlink existing links as the client user, allowing users to revoke their own linkages
     *
     * @param _policyClient the policy client where the data is associated
     * @param _identityDomains this specifies what type of data to unlink
     */
    function unlinkIdentityAsUser(
        address _policyClient,
        bytes32[] calldata _identityDomains
    ) external;

    /// @notice Get the OperatorRegistry address used to require task submitter privileges for writing identity data.
    ///   immutable, set on the implementation contract
    /// @return The OperatorRegistry address
    function operatorRegistry() external view returns (IOperatorRegistry);

    /// @notice Get the PolicyClientRegistry address used to enforce client registration during linking.
    ///   immutable, set on the implementation contract
    /// @return The PolicyClientRegistry address
    function policyClientRegistry() external view returns (IPolicyClientRegistry);

    /// @notice Return all identity domains linked for a (policyClient, clientUser) pair.
    ///         Operators use this at task time to enumerate which identity domains are available,
    ///         instead of relying on a single identity_domain in policyParams.
    /// @param policyClient The policy client address
    /// @param clientUser The client user address (intent signer)
    /// @return Array of bytes32 identity domain identifiers with active links
    function getLinkedDomains(
        address policyClient,
        address clientUser
    ) external view returns (bytes32[] memory);

    /// @notice Check whether any user has linked identity data to this policy client.
    ///         Used for on-chain privacy task detection — if true, the task involves
    ///         identity data and requires TEE attestation for privacy protection.
    /// @param policyClient The policy client address
    /// @return True if at least one identity link exists for this policy client
    function hasLinkedIdentity(
        address policyClient
    ) external view returns (bool);

    /// @notice Seed the link count for a policy client after contract upgrade.
    ///         The counter starts at 0 for all existing policy clients — pre-existing
    ///         links are not reflected until the next link/unlink operation. This function
    ///         allows a task generator to backfill the count from off-chain enumeration.
    ///         One-time migration use only.
    /// @param policyClient The policy client address
    /// @param count The number of active links to set
    function seedLinkCount(
        address policyClient,
        uint256 count
    ) external;
}
