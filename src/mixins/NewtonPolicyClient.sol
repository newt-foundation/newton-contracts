// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {
    INewtonPolicyClient,
    INewtonPolicyClientDelegation
} from "../interfaces/INewtonPolicyClient.sol";
import {INewtonPolicyFactoryRegistry} from "../interfaces/INewtonPolicyFactory.sol";
import {SemVerMixin} from "./SemVerMixin.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";
import {PROTOCOL_VERSION} from "../libraries/ProtocolVersion.sol";
import {
    POLICY_SET_DOMAIN,
    MAX_POLICIES,
    MAX_POLICY_FIELD_BYTES
} from "../libraries/PolicyConstants.sol";

abstract contract NewtonPolicyClient is
    INewtonPolicyClient,
    INewtonPolicyClientDelegation,
    IERC5267,
    SemVerMixin
{
    /// @notice Stamps the implementation with the protocol version it was compiled
    ///         against so inheriting clients (e.g. vaults) expose `version()`. This
    ///         lets off-chain tooling detect a client/protocol version drift; a
    ///         client built before this change reverts on `version()`, which is
    ///         itself the drift signal. No constructor argument, so existing
    ///         inheritors require no change.
    constructor() SemVerMixin(PROTOCOL_VERSION) {}

    /// @notice Function to check if a contract implements an interface
    /// @param interfaceId The interface identifier to check
    /// @return True if the contract implements the interface, false otherwise
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId // 0x01ffc9a7
            || interfaceId == type(INewtonPolicyClient).interfaceId
            || interfaceId == type(INewtonPolicyClientDelegation).interfaceId
            || interfaceId == type(IERC5267).interfaceId;
    }

    // error for when a call is made by an account other than the owner
    error OnlyPolicyClientOwner();

    // modifier to restrict functions to only the owner
    modifier onlyPolicyClientOwner() {
        require(
            msg.sender == _getNewtonPolicyClientStorage().policyClientOwner, OnlyPolicyClientOwner()
        );
        _;
    }

    /// @notice Struct to contain stateful values for NewtonPolicyClient-type contracts
    /// @dev `_reservedSlot0`/`_reservedSlot1` were `policy`/`policyId` upstream. They keep their
    ///      names, types and position so an already-deployed proxy's storage layout does not
    ///      shift; the new `policyId` is appended rather than reusing `_reservedSlot1` so a
    ///      client that has upgraded but not yet called `setPolicies` reads zero -- which
    ///      matches no real set -- instead of a stale single-policy id that still looks live.
    /// @custom:storage-location erc7201:newton.storage.NewtonPolicyClient
    struct NewtonPolicyClientStorage {
        INewtonProverTaskManager policyTaskManager;
        address _reservedSlot0; // formerly policy
        bytes32 _reservedSlot1; // formerly policyId
        address policyClientOwner;
        PolicySpec[] policies;
        bytes32 policyId;
        uint64 policyRevision;
        // appended for delegated submission; append-only from here on
        mapping(address => bool) delegators;
        bool delegatorRequired;
        mapping(address => uint256) delegatorNonces;
        mapping(bytes32 => bool) spentIntents;
    }

    /// @notice EIP-1967 proxy storage slot for the NewtonPolicyClientStorage struct
    /// @dev keccak256(abi.encode(uint256(keccak256("newton.storage.NewtonPolicyClient")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _NEWTON_POLICY_CLIENT_STORAGE_SLOT =
        0xaa6954ac1e404d8f79e6eba698b90c3c7071936d683ce65dd13ddf463ffbcb00;

    function _getNewtonPolicyClientStorage()
        private
        pure
        returns (NewtonPolicyClientStorage storage $)
    {
        assembly {
            $.slot := _NEWTON_POLICY_CLIENT_STORAGE_SLOT
        }
    }

    function _initNewtonPolicyClient(
        address policyTaskManager,
        address policyClientOwner
    ) internal {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        $.policyTaskManager = INewtonProverTaskManager(policyTaskManager);
        $.policyClientOwner = policyClientOwner;

        emit PolicyClientInitialized(policyTaskManager, policyClientOwner);
    }

    /**
     * @notice Only callable by the owner. Used for external policy configuration.
     * @param policyClientOwner The new policy client owner.
     */
    function setPolicyClientOwner(
        address policyClientOwner
    ) public onlyPolicyClientOwner {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        address previousOwner = $.policyClientOwner;
        $.policyClientOwner = policyClientOwner;

        emit PolicyClientOwnerUpdated(previousOwner, policyClientOwner);
    }

    /**
     * @notice Initializer-only policy setup, tolerant of an empty list.
     * @dev A client deployed ahead of its policies is a legal state. `setPolicies` itself stays
     *      strict about a non-empty set; this wrapper is only for the deferred-configuration path.
     * @param policies The ordered policy specifications, or an empty list to defer configuration.
     */
    function _initPolicies(
        PolicySpec[] memory policies
    ) internal {
        if (policies.length != 0) {
            _setPolicies(policies);
        }
    }

    /**
     * @notice Internal implementation for replacing a client's complete policy set.
     * @param policies The new ordered policy set.
     * @return newPolicyId The identifier committing to this client, this exact ordered set, and
     *         the revision it was set at.
     * @dev Per-entry, requires: the policy was deployed by the task manager's configured factory
     *      (provenance -- not an arbitrary contract shaped like a policy) and a nonzero expiry.
     *      The one-rego-to-one-oracle invariant needs no check here: a policy carries its own
     *      single wasmCid, so it cannot declare more than one oracle.
     */
    function _setPolicies(
        PolicySpec[] memory policies
    ) internal returns (bytes32) {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();

        require(policies.length != 0, EmptyPolicySet());
        require(policies.length <= MAX_POLICIES, TooManyPolicies(policies.length, MAX_POLICIES));

        require(address($.policyTaskManager) != address(0), PolicyFactoryNotSet());
        address factory = $.policyTaskManager.policyFactory();
        require(factory != address(0), PolicyFactoryNotSet());

        for (uint256 i = 0; i < policies.length; ++i) {
            require(
                INewtonPolicyFactoryRegistry(factory).isPolicy(policies[i].policy),
                PolicyNotRegistered(policies[i].policy)
            );
            require(policies[i].config.expireAfter != 0, ZeroExpireAfter(i));
            require(
                policies[i].config.policyParams.length <= MAX_POLICY_FIELD_BYTES,
                PolicyParamsTooLarge(i, policies[i].config.policyParams.length)
            );
        }

        uint64 revision = $.policyRevision + 1;
        bytes32 newPolicyId = keccak256(
            abi.encode(POLICY_SET_DOMAIN, block.chainid, address(this), revision, policies)
        );
        bytes32 previous = $.policyId;

        delete $.policies;
        for (uint256 i = 0; i < policies.length; ++i) {
            $.policies.push(policies[i]);
        }
        $.policyRevision = revision;
        $.policyId = newPolicyId;

        emit PoliciesUpdated(previous, newPolicyId, revision, policies);

        return newPolicyId;
    }

    /**
     * @notice Only callable by the owner. Replaces the complete policy set atomically.
     * @param policies The new ordered policy set.
     * @return The identifier committing to this client, this exact ordered set, and the
     *         revision it was set at.
     */
    function setPolicies(
        PolicySpec[] calldata policies
    ) external virtual onlyPolicyClientOwner returns (bytes32) {
        return _setPolicies(policies);
    }

    function getPolicies() external view returns (PolicySpec[] memory) {
        return _policies();
    }

    function _policies() internal view returns (PolicySpec[] memory) {
        return _getNewtonPolicyClientStorage().policies;
    }

    function getPolicyId() external view returns (bytes32) {
        return _policyId();
    }

    function _policyId() internal view returns (bytes32) {
        return _getNewtonPolicyClientStorage().policyId;
    }

    function policyRevision() external view returns (uint64) {
        return _getNewtonPolicyClientStorage().policyRevision;
    }

    /**
     * @notice Retrieves the policyID, revision, and policy set in one call. A caller reading
     *         these across three separate `eth_call`s can have a `setPolicies` land between
     *         them and observe a mix of old and new state; this getter is atomic against that.
     */
    function getPolicySetSnapshot() external view returns (bytes32, uint64, PolicySpec[] memory) {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        return ($.policyId, $.policyRevision, $.policies);
    }

    function getNewtonPolicyTaskManager() external view returns (address) {
        return _getNewtonPolicyTaskManager();
    }

    function _getNewtonPolicyTaskManager() internal view returns (address) {
        return address(_getNewtonPolicyClientStorage().policyTaskManager);
    }

    function getOwner() external view returns (address) {
        return _getOwner();
    }

    function _getOwner() internal view returns (address) {
        return _getNewtonPolicyClientStorage().policyClientOwner;
    }

    bytes32 private constant _EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant _INTENT_TYPEHASH = keccak256(
        "Intent(address from,address to,uint256 value,bytes data,uint256 chainId,bytes functionSignature)"
    );
    bytes32 private constant _DELEGATOR_APPROVAL_TYPEHASH =
        keccak256("DelegatorApproval(uint256 nonce,uint256 deadline)");
    string private constant _EIP712_NAME = "NewtonPolicyClient";
    string private constant _EIP712_VERSION = "1";

    /// @dev Owner and delegator both consent: the owner submits, the delegator signed.
    function approveDelegator(
        address delegator,
        uint256 deadline,
        bytes calldata signature
    ) external onlyPolicyClientOwner {
        require(
            block.timestamp <= deadline, NewtonMessage.Unauthorized("Delegator approval expired")
        );
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        (address signer, ECDSA.RecoverError err) = ECDSA.tryRecover(
            _delegatorApprovalDigest($.delegatorNonces[delegator]++, deadline), signature
        );
        require(
            err == ECDSA.RecoverError.NoError && signer == delegator,
            NewtonMessage.Unauthorized("Invalid delegator approval")
        );
        $.delegators[delegator] = true;
        emit DelegatorUpdated(delegator, true);
    }

    function removeDelegator(
        address delegator
    ) external onlyPolicyClientOwner {
        _getNewtonPolicyClientStorage().delegators[delegator] = false;
        emit DelegatorUpdated(delegator, false);
    }

    function resignDelegator() external {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        $.delegators[msg.sender] = false;
        ++$.delegatorNonces[msg.sender];
        emit DelegatorUpdated(msg.sender, false);
    }

    function delegatorNonces(
        address delegator
    ) external view returns (uint256) {
        return _getNewtonPolicyClientStorage().delegatorNonces[delegator];
    }

    function delegatorApprovalDigest(
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return _delegatorApprovalDigest(nonce, deadline);
    }

    function _delegatorApprovalDigest(
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        return _hashTypedData(keccak256(abi.encode(_DELEGATOR_APPROVAL_TYPEHASH, nonce, deadline)));
    }

    function setDelegatorRequired(
        bool required
    ) external onlyPolicyClientOwner {
        _getNewtonPolicyClientStorage().delegatorRequired = required;
        emit DelegatorRequiredUpdated(required);
    }

    function isDelegator(
        address account
    ) external view returns (bool) {
        return _getNewtonPolicyClientStorage().delegators[account];
    }

    function delegatorRequired() external view returns (bool) {
        return _getNewtonPolicyClientStorage().delegatorRequired;
    }

    function isIntentSpent(
        bytes32 digest
    ) external view returns (bool) {
        return _getNewtonPolicyClientStorage().spentIntents[digest];
    }

    /// @dev Computed per call rather than cached: the mixin has no initializer of its own that
    ///      every client runs, and `address(this)` must be the proxy, not the implementation.
    function eip712Domain()
        public
        view
        virtual
        returns (bytes1, string memory, string memory, uint256, address, bytes32, uint256[] memory)
    {
        return (
            hex"0f",
            _EIP712_NAME,
            _EIP712_VERSION,
            block.chainid,
            address(this),
            bytes32(0),
            new uint256[](0)
        );
    }

    function intentDigest(
        NewtonMessage.Intent calldata intent
    ) external view returns (bytes32) {
        return _intentDigest(intent);
    }

    function _intentDigest(
        NewtonMessage.Intent memory intent
    ) internal view returns (bytes32) {
        return _hashTypedData(
            keccak256(
                abi.encode(
                    _INTENT_TYPEHASH,
                    intent.from,
                    intent.to,
                    intent.value,
                    keccak256(intent.data),
                    intent.chainId,
                    keccak256(intent.functionSignature)
                )
            )
        );
    }

    function _hashTypedData(
        bytes32 structHash
    ) internal view virtual returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(_EIP712_NAME)),
                keccak256(bytes(_EIP712_VERSION)),
                block.chainid,
                address(this)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// @dev `intent.from` submitting its own attestation passes unless the client requires a
    ///      delegator; with `delegatorRequired` false this is exactly the old sender check. Any
    ///      other caller must be an allowlisted delegator carrying `intent.from`'s signature.
    ///      `digest` is read only on the delegated path; callers skip hashing on self-submission.
    ///      A delegated digest is single-use, the intent carries no nonce of its own; callers spend
    ///      it only once the task manager allows, so a denied or challenged task leaves it unspent.
    function _checkIntentSender(
        bytes32 digest,
        address from,
        bytes memory signature
    ) internal view {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        if (msg.sender == from) {
            require(!$.delegatorRequired, NewtonMessage.Unauthorized("Delegator required"));
            return;
        }
        require(
            $.delegators[msg.sender], NewtonMessage.Unauthorized("Not authorized intent sender")
        );
        require(signature.length != 0, NewtonMessage.Unauthorized("Missing intent signature"));
        (address signer, ECDSA.RecoverError err) = ECDSA.tryRecover(digest, signature);
        require(
            err == ECDSA.RecoverError.NoError && signer == from,
            NewtonMessage.Unauthorized("Invalid intent signature")
        );
        require(!$.spentIntents[digest], NewtonMessage.Unauthorized("Intent already used"));
    }

    /**
     * @notice Validates the transaction by checking the policy evaluation task response.
     * @param attestation the attestation to validate
     * @return true if the attestation is valid, false otherwise
     * @dev This function validates the attestation by checking the policy ID and the intent sender.
     *      NOTE: Attestation is valid if the policy ID matches and the caller is the intent sender
     *      or a delegator carrying the intent sender's signature (see `_checkIntentSender`).
     *      If either of the conditions is not met, the function reverts with an Unauthorized error.
     */
    function _validateAttestation(
        NewtonMessage.Attestation memory attestation
    ) internal returns (bool) {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        require(
            attestation.policyId == $.policyId,
            NewtonMessage.Unauthorized("Policy ID does not match")
        );
        address from = attestation.intent.from;
        bytes32 digest = msg.sender == from ? bytes32(0) : _intentDigest(attestation.intent);
        _checkIntentSender(digest, from, attestation.intentSignature);
        require(
            attestation.intent.chainId == block.chainid,
            NewtonMessage.Unauthorized("Chain ID does not match")
        );
        bool valid = $.policyTaskManager.validateAttestation(attestation);
        if (valid && digest != bytes32(0)) {
            $.spentIntents[digest] = true;
            emit IntentSpent(digest, msg.sender);
        }
        return valid;
    }

    /**
     * @notice Validates an attestation directly by verifying signatures without waiting for respondToTask.
     * @param task the task to validate
     * @param taskResponse the task response containing policy evaluation result
     * @param signatureData ABI-encoded signature data (NonSignerStakesAndSignature or BN254Certificate)
     * @return true if the attestation is valid, false otherwise
     * @dev This function validates the attestation directly by checking the policy ID, intent sender, chain ID,
     *      and verifying signatures on-chain. Use this when you need immediate validation without waiting
     *      for the aggregator to call respondToTask.
     */
    function _validateAttestationDirect(
        INewtonProverTaskManager.Task calldata task,
        INewtonProverTaskManager.TaskResponse calldata taskResponse,
        bytes calldata signatureData
    ) internal returns (bool) {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        require(
            taskResponse.policyId == $.policyId,
            NewtonMessage.Unauthorized("Policy ID does not match")
        );
        address from = taskResponse.intent.from;
        bytes32 digest = msg.sender == from ? bytes32(0) : _intentDigest(taskResponse.intent);
        _checkIntentSender(digest, from, taskResponse.intentSignature);
        require(
            taskResponse.intent.chainId == block.chainid,
            NewtonMessage.Unauthorized("Chain ID does not match")
        );
        bool valid =
            $.policyTaskManager.validateAttestationDirect(task, taskResponse, signatureData);
        if (valid && digest != bytes32(0)) {
            $.spentIntents[digest] = true;
            emit IntentSpent(digest, msg.sender);
        }
        return valid;
    }
}
