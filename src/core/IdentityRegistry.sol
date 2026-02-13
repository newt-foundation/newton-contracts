// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IIdentityRegistry} from "../interfaces/IIdentityRegistry.sol";
import {IPolicyClientRegistry} from "../interfaces/IPolicyClientRegistry.sol";

import {OwnableUpgradeable} from "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import {
    EIP712Upgradeable
} from "@openzeppelin-upgrades/contracts/utils/cryptography/EIP712Upgradeable.sol";
import {Nonces} from "../mixins/Nonces.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title Registry for identity data
///
/// @notice Relies on an admin address to add data for veracity
///
/// @dev Important terminology
/// @dev Signer: the eoa that has ownership over the identity data. No linkage can happen without their signature
/// @dev Identity Domain: a bytes32 hash that denotes the different types of identity data. Same across users. Defined and used offchain
/// @dev Identity Data: encrypted data from users, stored for use in task evaluation for identity requiring policies
/// @dev Policy Client: any policy client that wants to link user data. The usage of that data depends on the newton policy attached to that client
/// @dev Policy Client User (user): the address used by the Signer for the policy client. Usually an embedded wallet within the PolicyClient owner's domain
contract IdentityRegistry is OwnableUpgradeable, EIP712Upgradeable, Nonces, IIdentityRegistry {
    /// mapping that holds the encrypted identity.
    /// The owner eoa address maps to an identity domain identifier which maps to the encrypted data
    mapping(address => mapping(bytes32 => string)) public override identityData;
    /// mapping that holds the linking of the data to the policy clients
    /// the mapping is policy client address -> client user -> identity domain -> owner eoa whose data is linked/used
    /// the process for using this is to first look up the address whose data is linked to the user, and then look up the data in the identityData mapping
    mapping(address => mapping(address => mapping(bytes32 => address)))
        public
        override policyClientLinks;

    /// @notice PolicyClientRegistry used to enforce that only registered and active policy clients
    ///   can link identity data. Set during initialize()/initializeV2() and immutable thereafter.
    address public override policyClientRegistry;

    /// typehash for doing signTypedData for as the identityOwner to provide to the user for linkIdentityAsUser
    bytes32 public constant override LINK_SIGNER_TYPEHASH = keccak256(
        "linkIdentitySigner(address identityOwner,address policyClient,address clientUser,bytes32[] identityDomains,uint256 identityOwnerNonce,uint256 deadline)"
    );

    /// typehash for doing signTypedData for as the user to provide to the identityOwner for linkIdentityAsSigner
    bytes32 public constant override LINK_USER_TYPEHASH = keccak256(
        "linkIdentityUser(address identityOwner,address policyClient,address clientUser,bytes32[] identityDomains,uint256 clientUserNonce,uint256 deadline)"
    );

    /// a sanity check upper bound on the max number of links at once
    uint256 public constant MAX_LINKS = 50;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the identity registry
     * @param _admin The admin address that is the only address that can submit data
     * @param _policyClientRegistry The PolicyClientRegistry address for enforcing client registration during linking
     */
    function initialize(
        address _admin,
        address _policyClientRegistry
    ) external initializer {
        require(_policyClientRegistry != address(0), "policyClientRegistry required");
        __Ownable_init();
        __EIP712_init("IdentityRegistry", "1");
        _transferOwnership(_admin);
        policyClientRegistry = _policyClientRegistry;
    }

    /**
     * @notice Upgrade initializer for existing proxies deployed before PolicyClientRegistry existed.
     * @param _policyClientRegistry The PolicyClientRegistry address for enforcing client registration during linking
     * @dev Only callable once (reinitializer version 2). Use upgradeAndCall() during proxy upgrade.
     */
    function initializeV2(
        address _policyClientRegistry
    ) external reinitializer(2) {
        require(_policyClientRegistry != address(0), "policyClientRegistry required");
        policyClientRegistry = _policyClientRegistry;
    }

    /**
     * submits a new identity to the registry
     *
     * @inheritdoc IIdentityRegistry
     */
    function submitIdentity(
        address _identityOwner,
        bytes32 _identityDomain,
        string calldata _identityData
    ) external override onlyOwner {
        require(_identityOwner != address(0), InvalidIdentityAddress());
        require(_identityDomain != bytes32(0), InvalidIdentityDomain());

        // it's ok if this overwrites, users should be able to update their identity and the owner is trusted
        identityData[_identityOwner][_identityDomain] = _identityData;

        emit IdentityBound(_identityOwner, _identityDomain, _identityData);
    }

    /**
     * function to link data if the msg.sender owns all elements of the system
     *
     * @inheritdoc IIdentityRegistry
     */
    function linkIdentityAsSignerAndUser(
        address _policyClient,
        bytes32[] calldata _identityDomains
    ) external override {
        address identityOwner = msg.sender;
        address clientUser = msg.sender;

        uint256 numDomains = _identityDomains.length;
        require(numDomains > 0, NoEmptyDomainsArray());
        require(numDomains <= MAX_LINKS, TooManyDomainsAtOnce());

        for (uint256 i; i < numDomains; ++i) {
            _linkIdentity(identityOwner, _policyClient, clientUser, _identityDomains[i]);
        }
    }

    /**
     * function to link existing data to a NewtonPolicyClient as the identityOwner for that data
     *
     * @inheritdoc IIdentityRegistry
     */
    function linkIdentityAsSigner(
        address _policyClient,
        bytes32[] calldata _identityDomains,
        address _clientUser,
        bytes calldata _signature,
        uint256 _nonce,
        uint256 _deadline
    ) external override {
        address identityOwner = msg.sender;

        uint256 numDomains = _identityDomains.length;
        require(numDomains > 0, NoEmptyDomainsArray());
        require(numDomains <= MAX_LINKS, TooManyDomainsAtOnce());

        // check signature by the client user
        _confirmSignature(
            identityOwner,
            _policyClient,
            _clientUser,
            _identityDomains,
            _signature,
            _nonce,
            _deadline,
            LINK_USER_TYPEHASH,
            _clientUser
        );

        for (uint256 i; i < numDomains; ++i) {
            _linkIdentity(identityOwner, _policyClient, _clientUser, _identityDomains[i]);
        }
    }

    /**
     * function to link existing data to a NewtonPolicyClient as the user of that client
     *
     * @inheritdoc IIdentityRegistry
     */
    function linkIdentityAsUser(
        address _identityOwner,
        address _policyClient,
        bytes32[] calldata _identityDomains,
        bytes calldata _signature,
        uint256 _nonce,
        uint256 _deadline
    ) external override {
        address clientUser = msg.sender;

        uint256 numDomains = _identityDomains.length;
        require(numDomains > 0, NoEmptyDomainsArray());
        require(numDomains <= MAX_LINKS, TooManyDomainsAtOnce());

        // check signature by the identityOwner
        _confirmSignature(
            _identityOwner,
            _policyClient,
            clientUser,
            _identityDomains,
            _signature,
            _nonce,
            _deadline,
            LINK_SIGNER_TYPEHASH,
            _identityOwner
        );

        for (uint256 i; i < numDomains; ++i) {
            _linkIdentity(_identityOwner, _policyClient, clientUser, _identityDomains[i]);
        }
    }

    /**
     * function to link existing data to a NewtonPolicyClient as the user of that client
     *
     * @inheritdoc IIdentityRegistry
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
    ) external override {
        uint256 numDomains = _identityDomains.length;
        require(numDomains > 0, NoEmptyDomainsArray());
        require(numDomains <= MAX_LINKS, TooManyDomainsAtOnce());

        // check signature by the identityOwner
        _confirmSignature(
            _identityOwner,
            _policyClient,
            _clientUser,
            _identityDomains,
            _identityOwnerSignature,
            _identityOwnerNonce,
            _identityOwnerDeadline,
            LINK_SIGNER_TYPEHASH,
            _identityOwner
        );

        // check signature by the user
        _confirmSignature(
            _identityOwner,
            _policyClient,
            _clientUser,
            _identityDomains,
            _clientUserSignature,
            _clientUserNonce,
            _clientUserDeadline,
            LINK_USER_TYPEHASH,
            _clientUser
        );

        for (uint256 i; i < numDomains; ++i) {
            _linkIdentity(_identityOwner, _policyClient, _clientUser, _identityDomains[i]);
        }
    }

    /**
     * function to unlink existing links, only useable if msg.sender is the identity that is linked
     *
     * @inheritdoc IIdentityRegistry
     */
    function unlinkIdentityAsSigner(
        address _clientUser,
        address _policyClient,
        bytes32[] calldata _identityDomains
    ) external {
        address caller = msg.sender;
        uint256 numDomains = _identityDomains.length;
        require(numDomains > 0, NoEmptyDomainsArray());
        require(numDomains <= MAX_LINKS, TooManyDomainsAtOnce());

        for (uint256 i; i < numDomains; ++i) {
            _unlinkIdentity(caller, _policyClient, _clientUser, _identityDomains[i]);
        }
    }

    /**
     * internal function for confirming the signature by the identity data identityOwner
     *
     * @param _policyClient the policy client where the data is to be associated
     * @param _identityOwner the identityOwner being used to authorize access to the existing identity
     * @param _clientUser the user address to the new policy client being linked
     * @param _identityDomains the hash idenifier that denotes what the data is stored under
     * @param _signature signature by the _clientUser to prove that this linking should be allowed
     * @param _typehash the typehash for the signature
     * @param _requiredSigner the address that must have performed the signature
     */
    function _confirmSignature(
        address _identityOwner,
        address _policyClient,
        address _clientUser,
        bytes32[] calldata _identityDomains,
        bytes calldata _signature,
        uint256 _nonce,
        uint256 _deadline,
        bytes32 _typehash,
        address _requiredSigner
    ) internal {
        bytes32 typedData = keccak256(
            abi.encode(
                _typehash,
                _identityOwner,
                _policyClient,
                _clientUser,
                keccak256(abi.encode(_identityDomains)),
                _nonce,
                _deadline
            )
        );
        address recoveredSigner = ECDSA.recover(_hashTypedDataV4(typedData), _signature);
        require(recoveredSigner == _requiredSigner, InvalidSignature());
        _useCheckedNonce(_requiredSigner, _nonce);
        require(_deadline > block.timestamp, SignatureExpired());
    }

    /**
     * internal function for updating the storage after all authorization has been checked
     *
     * @param _identityOwner the identityOwner that owns the identity data in the other mapping
     * @param _policyClient the policy client where the data is to be associated
     * @param _clientUser the user of the policy client who will be submitting tasks
     * @param _identityDomain this specifies what type of data is associated
     */
    function _linkIdentity(
        address _identityOwner,
        address _policyClient,
        address _clientUser,
        bytes32 _identityDomain
    ) internal {
        // Enforce that the policy client is registered and active in the PolicyClientRegistry
        require(
            IPolicyClientRegistry(policyClientRegistry).isRegisteredClient(_policyClient),
            PolicyClientNotRegistered(_policyClient)
        );

        // update storage
        policyClientLinks[_policyClient][_clientUser][_identityDomain] = _identityOwner;

        emit IdentityLinked(_identityOwner, _policyClient, _clientUser, _identityDomain);
    }

    /**
     * internal function for clearing the storage of a link if the caller matches the stored value
     *
     * @param _caller the address that called unlinkIdentity, must be the linked identity for unlinking to succeed
     * @param _policyClient the policy client where the data is associated
     * @param _clientUser the user of the policy client whose linkage will be cleared
     * @param _identityDomain this specifies what type of associated data to unlink
     */
    function _unlinkIdentity(
        address _caller,
        address _policyClient,
        address _clientUser,
        bytes32 _identityDomain
    ) internal {
        require(
            policyClientLinks[_policyClient][_clientUser][_identityDomain] == _caller,
            InvalidUnlinker()
        );

        delete policyClientLinks[_policyClient][_clientUser][_identityDomain];

        emit IdentityUnlinked(_caller, _policyClient, _clientUser, _identityDomain);
    }
}
