// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {INewtonProverTaskManager} from "../interfaces/INewtonProverTaskManager.sol";
import {INewtonPolicyClient} from "../interfaces/INewtonPolicyClient.sol";
import {NewtonPolicy} from "../core/NewtonPolicy.sol";
import {NewtonMessage} from "../core/NewtonMessage.sol";
import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";

abstract contract NewtonPolicyClient is INewtonPolicyClient {
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
    /// @custom:storage-location erc7201:newton.storage.NewtonPolicyClient
    struct NewtonPolicyClientStorage {
        INewtonProverTaskManager policyTaskManager;
        address policy;
        bytes32 policyId;
        address policyClientOwner;
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
        address policy,
        address policyClientOwner
    ) internal {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        $.policyTaskManager = INewtonProverTaskManager(policyTaskManager);
        $.policy = policy;
        $.policyClientOwner = policyClientOwner;
    }

    /**
     * @notice Only callable by the owner. Used for external policy configuration.
     * @param policyClientOwner The new policy client owner.
     */
    function setPolicyClientOwner(
        address policyClientOwner
    ) external onlyPolicyClientOwner {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        $.policyClientOwner = policyClientOwner;
    }

    /**
     * @notice Sets a policy for the calling address to the policyID from on chain.
     * @param policyConfig The policy configuration.
     * @return policyId The policyID associated with the calling address.
     * @dev This function enables clients to define execution rules or parameters for tasks they submit.
     *      The policy governs how tasks submitted by the caller are executed, ensuring compliance with predefined rules.
     */
    function _setPolicy(
        INewtonPolicy.PolicyConfig memory policyConfig
    ) internal returns (bytes32) {
        NewtonPolicyClientStorage storage $ = _getNewtonPolicyClientStorage();
        bytes32 policyId = NewtonPolicy($.policy).setPolicy(policyConfig);
        $.policyId = policyId;
        return policyId;
    }

    /**
     * @notice Same as _setPolicy, but only callable by the owner. Used for external policy configuration.
     * @param policyConfig The policy configuration.
     * @return policyId The policyID associated with the calling address.
     */
    function setPolicy(
        INewtonPolicy.PolicyConfig memory policyConfig
    ) external onlyPolicyClientOwner returns (bytes32) {
        return _setPolicy(policyConfig);
    }

    function getPolicyAddress() external view returns (address) {
        return _getPolicyAddress();
    }

    function _getPolicyAddress() internal view returns (address) {
        return _getNewtonPolicyClientStorage().policy;
    }

    function getPolicyConfig() external view returns (INewtonPolicy.PolicyConfig memory) {
        return _getPolicyConfig();
    }

    function _getPolicyConfig() internal view returns (INewtonPolicy.PolicyConfig memory) {
        return NewtonPolicy(_getNewtonPolicyClientStorage().policy).getPolicyConfig(_getPolicyId());
    }

    function getPolicyId() external view returns (bytes32) {
        return _getPolicyId();
    }

    function _getPolicyId() internal view returns (bytes32) {
        return _getNewtonPolicyClientStorage().policyId;
    }

    function getNewtonPolicyTaskManager() external view returns (address) {
        return _getNewtonPolicyTaskManager();
    }

    function _getNewtonPolicyTaskManager() internal view returns (address) {
        return address(_getNewtonPolicyClientStorage().policyTaskManager);
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
}
