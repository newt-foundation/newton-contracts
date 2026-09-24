// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {INewtonPolicyClient} from "../interfaces/INewtonPolicyClient.sol";
import {INewtonPolicyFactoryRegistry} from "../interfaces/INewtonPolicyFactory.sol";
import {SemVerMixin} from "./SemVerMixin.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";
import {PROTOCOL_VERSION} from "../libraries/ProtocolVersion.sol";
import {
    POLICY_SET_DOMAIN,
    MAX_POLICIES,
    MAX_POLICY_FIELD_BYTES
} from "../libraries/PolicyConstants.sol";

abstract contract NewtonPolicyClient is INewtonPolicyClient, SemVerMixin {
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
            || interfaceId == type(INewtonPolicyClient).interfaceId;
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
    ) external onlyPolicyClientOwner returns (bytes32) {
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

    /**
     * @notice Validates the transaction by checking the policy evaluation task response.
     * @param attestation the attestation to validate
     * @return true if the attestation is valid, false otherwise
     * @dev This function validates the attestation by checking the policy ID and the intent sender.
     *      NOTE: Attestation is valid if the policy ID matches and the intent sender is the caller.
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
        require(
            attestation.intent.from == msg.sender,
            NewtonMessage.Unauthorized("Not authorized intent sender")
        );
        require(
            attestation.intent.chainId == block.chainid,
            NewtonMessage.Unauthorized("Chain ID does not match")
        );
        return $.policyTaskManager.validateAttestation(attestation);
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
        require(
            taskResponse.intent.from == msg.sender,
            NewtonMessage.Unauthorized("Not authorized intent sender")
        );
        require(
            taskResponse.intent.chainId == block.chainid,
            NewtonMessage.Unauthorized("Chain ID does not match")
        );
        return $.policyTaskManager.validateAttestationDirect(task, taskResponse, signatureData);
    }
}
