// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

interface IIdentityRegistry {
    // storage accessors

    /// mapping that holds the encrypted identity.
    function identityData(
        address policyClient,
        bytes32 indexIdentifier
    ) external returns (string memory identityData);

    /// mapping that holds the ownership of the data for linking
    function dataHashOwnership(
        bytes32 indexHash,
        address signer
    ) external returns (bool isSigner);

    // typehashes for ERC-712 signature parsing
    function SIGNER_ADD_TYPEHASH() external returns (bytes32);
    function LINK_SIGNER_TYPEHASH() external returns (bytes32);
    function LINK_OWNER_TYPEHASH() external returns (bytes32);

    /// event for when an identity is registered for indexing the data
    event IdentityBound(
        address indexed signer,
        address indexed policyClient,
        bytes32 indexIdentifier,
        string identityData
    );

    /// event for when a signer is added to an existing policy client's piece of data
    event SignerAdded(
        address indexed policyClient,
        address indexed approvingSigner,
        address indexed addedSigner,
        bytes32 indexIdentifier
    );

    /// event for when a an identity is linked to a new policy client
    event IdentityLinked(
        address indexed oldSigner,
        address indexed policyClientNew,
        address policyClientOld,
        bytes32 indexIdentifier,
        string data
    );

    /// error when someone tries to add a signer to an identity, but is not themselves a signer and did not provide a signature
    error InvalidSignerSelf();

    /// error when someone tries to add themselves as a signer, but does not provide a valid signature from an authorized signer
    error InvalidSignerAdd();

    /// error when someone tries to link an identity, but does not provide a valid signature from an authorized signer
    error InvalidSignerLink();

    /// error when someone tries to link an identity, but is not the owner of the new client and did not provide a signature
    error InvalidOwner();

    /// error when someone tries to link an identity, but does not provide a valid signature from the new client owner
    error InvalidOwnerLinkSignature();

    /// error when someone tries to link an identity, but does not provide a valid signature from the old client signer
    error InvalidSignerLinkSignature();

    /**
     * submits a new identity to the registry
     * @notice this function is callable only by the trusted owner
     *
     * @param _signer this is the user address who will control signing permissions for linking this data
     * @param _policyClient this is the address of the policy client to have the associated data, it is the top level lookup
     * @param _indexIdentifier this marks what type of data is associated
     * @param _identityData this is the actual data to be stored and to be looked up for the policy client during task execution
     */
    function submitIdentity(
        address _signer,
        address _policyClient,
        bytes32 _indexIdentifier,
        string memory _identityData
    ) external;

    /**
     * adds a new signer for an existing identity data record
     * @notice this function requires the caller to be a signer and trusts them if they are
     *
     * @param _policyClient this is the address of the policy client that has the associated data
     * @param _indexIdentifier this specifies what type of data is associated
     * @param _newSigner this is the new address to add as a signer for this pairing
     */
    function addSigner(
        address _policyClient,
        bytes32 _indexIdentifier,
        address _newSigner
    ) external;

    /**
     * adds the caller as a new signer for an existing identity data record
     * @notice uses the signature of an existing signer
     *
     * @param _policyClient this is the address of the policy client that has the associated data
     * @param _indexIdentifier this specifies what type of data is associated
     * @param _signature sig from an existing signer for the data
     */
    function addSelfAsSigner(
        address _policyClient,
        bytes32 _indexIdentifier,
        bytes memory _signature
    ) external;

    /**
     * function to link data if the msg.sender owns all elements of the system
     *
     * @param _policyClientOld the old policy client where the data was previously associated
     * @param _policyClientNew the new policy client where the data is to be associated
     * @param _indexIdentifier this specifies what type of data is associated
     */
    function linkIdentityAsSignerAndOwner(
        address _policyClientOld,
        address _policyClientNew,
        bytes32 _indexIdentifier
    ) external;

    /**
     * function to link existing data to a new NewtonPolicyClient as the signer for that data
     *
     * @param _policyClientOld the old policy client where the data was previously associated
     * @param _policyClientNew the new policy client where the data is to be associated
     * @param _indexIdentifier this specifies what type of data is associated
     * @param _newSigner the additional signer to add as the signer for the new linkage
     * @param _signature signature by the _oldSigner to prove that this linking should be allowed
     */
    function linkIdentityAsSigner(
        address _policyClientOld,
        address _policyClientNew,
        bytes32 _indexIdentifier,
        address _newSigner,
        bytes calldata _signature
    ) external;

    /**
     * function to link existing data to a new NewtonPolicyClient as the owner of that client
     *
     * @param _policyClientOld the old policy client where the data was previously associated
     * @param _policyClientNew the new policy client where the data is to be associated
     * @param _indexIdentifier this specifies what type of data is associated
     * @param _oldSigner the signer being used to authorize access to the existing identity
     * @param _signature signature by the _oldSigner to prove that this linking should be allowed
     */
    function linkIdentityAsOwner(
        address _policyClientOld,
        address _policyClientNew,
        bytes32 _indexIdentifier,
        address _oldSigner,
        bytes calldata _signature
    ) external;
}
