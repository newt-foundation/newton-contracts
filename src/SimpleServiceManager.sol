// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import {Ownable2StepUpgradeable} from "openzeppelin-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "openzeppelin-upgradeable/proxy/utils/Initializable.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Task, SignatureWithSaltAndExpiry} from "./interfaces/IPredicateManager.sol";
import {ISimpleServiceManager} from "./interfaces/ISimpleServiceManager.sol";

contract SimpleServiceManager is ISimpleServiceManager, Initializable, Ownable2StepUpgradeable {
    /**
     * @notice Emitted when a policy is set for a client
     */
    event SetPolicy(address indexed client, string indexed policyID);

    /**
     * @notice Emitted when a task is successfully validated
     */
    event TaskValidated(
        address indexed msgSender,
        address indexed target,
        uint256 indexed value,
        string policyID,
        string taskId,
        uint256 expireByTime
    );

    /// @notice Tracks spent task IDs to prevent replay attacks
    mapping(string => bool) public spentTaskIDs;

    /// @notice List of all deployed policy IDs
    string[] public deployedPolicyIDs;

    /**
     * @notice Initializes the contract and transfers ownership.
     * @param _owner Address to set as the contract owner.
     */
    function initialize(
        address _owner
    ) external initializer {
        __Ownable2Step_init();
        __Ownable_init(_owner);
    }

    /**
     * @notice Returns all deployed policy IDs
     * @return Array of deployed policy IDs
     */
    function getDeployedPolicyIDs() external view returns (string[] memory) {
        return deployedPolicyIDs;
    }

    /**
     * @notice Sets a policy for the calling contract (msg.sender)
     * @dev Associates a client contract with a specific policy ID. The policy must be previously registered.
     * @param _policyID Identifier of a registered policy to associate with the caller
     */
    function setPolicy(
        string memory _policyID
    ) external {
        require(bytes(_policyID).length > 0, "Predicate.setPolicy: policy ID cannot be empty");
        require(bytes(idToPolicy[_policyID]) > 0, "Predicate.setPolicy: policy ID not registered");
        clientToPolicyID[msg.sender] = _policyID;
        emit SetPolicy(msg.sender, _policyID);
    }

    /**
     * @notice Overrides the policy for a specific client address
     * @param _policyID is the unique identifier for the policy
     * @param _clientAddress is the address of the client for which the policy is being overridden
     */
    function overrideClientPolicyID(string memory _policyID, address _clientAddress) external onlyOwner {
        require(bytes(_policyID).length > 0, "Predicate.setPolicy: policy ID cannot be empty");
        clientToPolicyID[_clientAddress] = _policyID;
        emit SetPolicy(_clientAddress, _policyID);
    }

    /**
     * @notice Computes a secure task hash with validation-time context
     * @param _task The task parameters to hash
     * @return bytes32 The keccak256 digest including validation context
     */
    function hashTaskSafe(
        Task calldata _task
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                _task.taskId,
                _task.msgSender,
                msg.sender,
                _task.value,
                _task.encodedSigAndArgs,
                _task.policyID,
                _task.expireByTime
            )
        );
    }

    /**
     * @notice Verifies zk proof of the Newton Single Transaction Model
     * @param _task the params of the task
     */
    function verify(
        Task calldata _task,
        bytes memory input,
        bytes memory proof
    ) external returns (bool isVerified) {
        require(block.timestamp <= _task.expireByTime, "SimpleServiceManager.verify: transaction expired");
        require(!spentTaskIDs[_task.taskId], "SimpleServiceManager.verify: task ID already spent");

        emit TaskValidated(
            _task.msgSender,
            _task.target,
            _task.value,
            _task.policyID,
            _task.taskId,
            _task.expireByTime
        );

        spentTaskIDs[_task.taskId] = true;
        return true;
    }
}
