// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

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

    /// error when identity data is submitted for the zero address
    error InvalidIdentityAddress();

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

    /**
     * submits a new identity to the registry
     * @notice this function is callable only by the trusted owner
     *
     * @param _identityOwner this is the user address who will control signing permissions for linking this data
     * @param _identityDomain this marks what type of data is associated
     * @param _identityData this is the actual encrypted data to be stored and to be looked up during task execution
     */
    function submitIdentity(
        address _identityOwner,
        bytes32 _identityDomain,
        string memory _identityData
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
}
