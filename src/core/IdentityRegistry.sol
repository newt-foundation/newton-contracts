// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {INewtonPolicyClient} from "../interfaces/INewtonPolicyClient.sol";
import {IIdentityRegistry} from "../interfaces/IIdentityRegistry.sol";

import {OwnableUpgradeable} from "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import {
    EIP712Upgradeable
} from "@openzeppelin-upgrades/contracts/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title Registry for identity data
///
/// @notice Relies on an admin address to add data for veracity
contract IdentityRegistry is OwnableUpgradeable, EIP712Upgradeable, IIdentityRegistry {
    /// mapping that holds the encrypted identity.
    /// The policy client address maps to an identity index identifier which maps to the encrypted data
    mapping(address => mapping(bytes32 => string)) public override identityData;
    /// mapping that holds the ownership of the data for linking
    /// the bytes32 key is computed by taking keccak256(abi.encode(policyClient, indexIdentifier))
    /// this key is what's signed for the signature check
    /// the mapping holds approved addresses. switching uint256 to bool would allow for a hierarchical system if desired
    mapping(bytes32 => mapping(address => bool)) public override dataHashOwnership;

    // slither-disable-next-line gas-small-strings
    bytes32 public constant override SIGNER_ADD_TYPEHASH = keccak256(
        "addSelfAsSigner(address newSigner,address policyClient,bytes32 indexIdentifier)"
    );

    // slither-disable-next-line gas-small-strings
    bytes32 public constant override LINK_SIGNER_TYPEHASH = keccak256(
        "linkIdentitySigner(address oldPolicyClient,address newPolicyClient,address oldSigner,address newSigner,address newClientOwner,bytes32 indexIdentifier)"
    );

    // slither-disable-next-line gas-small-strings
    bytes32 public constant override LINK_OWNER_TYPEHASH = keccak256(
        "linkIdentityOwner(address oldPolicyClient,address newPolicyClient,address oldSigner,address newSigner,address newClientOwner,bytes32 indexIdentifier)"
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the identity registry
     * @param _admin The admin address that will own the contract
     */
    function initialize(
        address _admin
    ) external initializer {
        __Ownable_init();
        __EIP712_init("IdentityRegistry", "1");
        _transferOwnership(_admin);
    }

    /**
     * submits a new identity to the registry
     *
     * @inheritdoc IIdentityRegistry
     */
    function submitIdentity(
        address _signer,
        address _policyClient,
        bytes32 _indexIdentifier,
        string calldata _identityData
    ) external override onlyOwner {
        // it's ok if this overwrites, users should be able to update their identity and the owner is trusted
        identityData[_policyClient][_indexIdentifier] = _identityData;
        // this hash is unique because only one value can be stored in the mapping above
        bytes32 identityHash = keccak256(abi.encode(_policyClient, _indexIdentifier));
        // authorize the signer for linking this data to other policy clients
        dataHashOwnership[identityHash][_signer] = true;

        emit IdentityBound(_signer, _policyClient, _indexIdentifier, _identityData);
    }

    /**
     * adds a new signer for an existing identity data record
     *
     * @inheritdoc IIdentityRegistry
     */
    function addSigner(
        address _policyClient,
        bytes32 _indexIdentifier,
        address _newSigner
    ) external override {
        bytes32 identityHash = keccak256(abi.encode(_policyClient, _indexIdentifier));

        require(dataHashOwnership[identityHash][msg.sender], InvalidSignerSelf());

        dataHashOwnership[identityHash][_newSigner] = true;

        emit SignerAdded(_policyClient, msg.sender, _newSigner, _indexIdentifier);
    }

    /**
     * adds the caller as a new signer for an existing identity data record
     *
     * @inheritdoc IIdentityRegistry
     */
    function addSelfAsSigner(
        address _policyClient,
        bytes32 _indexIdentifier,
        bytes calldata _signature
    ) external override {
        // compute the hash identifier for the data
        bytes32 identityHash = keccak256(abi.encode(_policyClient, _indexIdentifier));

        // compute the typed hash of the adding event
        bytes32 typedData =
            keccak256(abi.encode(SIGNER_ADD_TYPEHASH, msg.sender, _policyClient, _indexIdentifier));

        address signer = ECDSA.recover(_hashTypedDataV4(typedData), _signature);

        require(dataHashOwnership[identityHash][signer], InvalidSignerAdd());
        dataHashOwnership[identityHash][msg.sender] = true;

        emit SignerAdded(_policyClient, signer, msg.sender, _indexIdentifier);
    }

    // see what condition to use for remove signer functions

    // do we need remove data functions too? or just rely on the admin to overwrite

    /**
     * function to link data if the msg.sender owns all elements of the system
     *
     * @inheritdoc IIdentityRegistry
     */
    function linkIdentityAsSignerAndOwner(
        address _policyClientOld,
        address _policyClientNew,
        bytes32 _indexIdentifier
    ) external override {
        address oldSigner = msg.sender;

        // check that the caller is the owner
        address newClientOwner = INewtonPolicyClient(_policyClientNew).getOwner();
        require(newClientOwner == msg.sender, InvalidOwner());
        // check that the caller is a signer
        bytes32 identityHashOld = keccak256(abi.encode(_policyClientOld, _indexIdentifier));
        require(dataHashOwnership[identityHashOld][oldSigner], InvalidSignerLink());

        _linkIdentity(oldSigner, _policyClientNew, _policyClientOld, _indexIdentifier);
    }

    /**
     * function to link existing data to a new NewtonPolicyClient as the signer for that data
     *
     * @inheritdoc IIdentityRegistry
     */
    function linkIdentityAsSigner(
        address _policyClientOld,
        address _policyClientNew,
        bytes32 _indexIdentifier,
        address _newSigner,
        bytes calldata _signature
    ) external override {
        address oldSigner = msg.sender;
        address newClientOwner = INewtonPolicyClient(_policyClientNew).getOwner();

        // check that the caller is a signer
        bytes32 identityHashOld = keccak256(abi.encode(_policyClientOld, _indexIdentifier));
        require(dataHashOwnership[identityHashOld][oldSigner], InvalidSignerLink());

        // check signature by the client owner
        _confirmOwnerSignature(
            _policyClientOld,
            _policyClientNew,
            oldSigner,
            _newSigner,
            newClientOwner,
            _indexIdentifier,
            _signature
        );

        _linkIdentity(oldSigner, _policyClientNew, _policyClientOld, _indexIdentifier);
    }

    /**
     * function to link existing data to a new NewtonPolicyClient as the owner of that client
     *
     * @inheritdoc IIdentityRegistry
     */
    function linkIdentityAsOwner(
        address _policyClientOld,
        address _policyClientNew,
        bytes32 _indexIdentifier,
        address _oldSigner,
        bytes calldata _signature
    ) external override {
        address newSigner = msg.sender;

        // check ownership of new client
        address newClientOwner = INewtonPolicyClient(_policyClientNew).getOwner();
        require(newClientOwner == msg.sender, InvalidOwner());

        // check signature by the old signer
        _confirmSignerSignature(
            _policyClientOld,
            _policyClientNew,
            _oldSigner,
            newSigner,
            newClientOwner,
            _indexIdentifier,
            _signature
        );

        _linkIdentity(_oldSigner, _policyClientNew, _policyClientOld, _indexIdentifier);
    }

    /**
     * internal function for confirming the signature by the _oldSigner
     *
     * @param _policyClientOld the old policy client where the data was previously associated
     * @param _policyClientNew the new policy client where the data is to be associated
     * @param _oldSigner the signer being used to authorize access to the existing identity
     * @param _newSigner signer to be added for the new policy client being linked
     * @param _newClientOwner the owner address to the new policy client being linked
     * @param _indexIdentifier the index that denotes what the data is stored under
     * @param _signature signature by the _oldSigner to prove that this linking should be allowed
     */
    function _confirmSignerSignature(
        address _policyClientOld,
        address _policyClientNew,
        address _oldSigner,
        address _newSigner,
        address _newClientOwner,
        bytes32 _indexIdentifier,
        bytes memory _signature
    ) internal view {
        bytes32 typedData = keccak256(
            abi.encode(
                LINK_SIGNER_TYPEHASH,
                _policyClientOld,
                _policyClientNew,
                _oldSigner,
                _newSigner,
                _newClientOwner,
                _indexIdentifier
            )
        );
        address signer = ECDSA.recover(_hashTypedDataV4(typedData), _signature);
        bytes32 identityHashOld = keccak256(abi.encode(_policyClientOld, _indexIdentifier));
        require(
            signer == _oldSigner && dataHashOwnership[identityHashOld][_oldSigner],
            InvalidSignerLinkSignature()
        );
    }

    /**
     * internal function for confirming the signature by the _newClientOwner
     *
     * @param _policyClientOld the old policy client where the data was previously associated
     * @param _policyClientNew the new policy client where the data is to be associated
     * @param _oldSigner the signer being used to authorize access to the existing identity
     * @param _newSigner signer to be added for the new policy client being linked
     * @param _newClientOwner the owner address to the new policy client being linked
     * @param _indexIdentifier the index that denotes what the data is stored under
     * @param _signature signature by the _newClientOwner to prove that this linking should be allowed
     */
    function _confirmOwnerSignature(
        address _policyClientOld,
        address _policyClientNew,
        address _oldSigner,
        address _newSigner,
        address _newClientOwner,
        bytes32 _indexIdentifier,
        bytes memory _signature
    ) internal view {
        bytes32 typedData = keccak256(
            abi.encode(
                LINK_OWNER_TYPEHASH,
                _policyClientOld,
                _policyClientNew,
                _oldSigner,
                _newSigner,
                _newClientOwner,
                _indexIdentifier
            )
        );
        address signer = ECDSA.recover(_hashTypedDataV4(typedData), _signature);
        require(
            signer == _newClientOwner
                && INewtonPolicyClient(_policyClientNew).getOwner() == _newClientOwner,
            InvalidOwnerLinkSignature()
        );
    }

    /**
     * internal function for updating the storage after all authorization has been checked
     *
     * @param _oldSigner also added as a signer for the new policy client
     * @param _policyClientNew the new policy client where the data is to be associated
     * @param _policyClientOld the old policy client where the data was previously associated, included just for the event
     * @param _indexIdentifier this specifies what type of data is associated
     */
    function _linkIdentity(
        address _oldSigner,
        address _policyClientNew,
        address _policyClientOld,
        bytes32 _indexIdentifier
    ) internal {
        // update storage
        string memory data = identityData[_policyClientOld][_indexIdentifier];
        identityData[_policyClientNew][_indexIdentifier] = data;
        bytes32 identityHashNew = keccak256(abi.encode(_policyClientNew, _indexIdentifier));
        dataHashOwnership[identityHashNew][_oldSigner] = true;

        emit IdentityLinked(_oldSigner, _policyClientNew, _policyClientOld, _indexIdentifier, data);
    }
}
