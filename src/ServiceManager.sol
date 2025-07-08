// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import {Ownable2StepUpgradeable} from "openzeppelin-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "openzeppelin-upgradeable/proxy/utils/Initializable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {INewtonManager, Task, SignatureWithSaltAndExpiry} from "./interfaces/INewtonManager.sol";

contract ServiceManager is INewtonManager, Initializable, Ownable2StepUpgradeable {
    error ServiceManager__Unauthorized();
    error ServiceManager__ArrayLengthMismatch();

    mapping(string => string) public idToPolicy;
    mapping(string => bool) public spentTaskIds;
    string[] public deployedPolicyIDs;

    mapping(string => bytes32) public policyIdToVkey;
    mapping(address => string) public clientToPolicyID;

    event SetPolicy(address indexed client, string indexed policyID);
    event DeployedPolicy(string indexed policyID, string policy);

    event TaskValidated(
        address indexed msgSender,
        address indexed target,
        uint256 indexed value,
        string policyID,
        string taskId,
        uint256 expireByTime
    );

    function initialize(
        address _owner
    ) external initializer {
        __Ownable2Step_init();
        __Ownable_init(_owner);
    }

    /**
     * @notice Deploys a policy for which clients can use
     * @param _policyID is a unique identifier
     * @param _policy is set of formatted rules
     */
    function deployPolicy(
        string memory _policyID,
        string memory _policy
    ) external onlyOwner {
        require(bytes(idToPolicy[_policyID]).length == 0, "Newton.deployPolicy: policy exists");
        require(bytes(_policy).length > 0, "Newton.deployPolicy: policy string cannot be empty");
        idToPolicy[_policyID] = _policy;
        deployedPolicyIDs.push(_policyID);
        emit DeployedPolicy(_policyID, _policy);
    }

    /**
     * @notice Gets array of deployed policies
     * @return array of deployed policies
     */
    function getDeployedPolicies() external view returns (string[] memory) {
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
        require(bytes(_policyID).length > 0, "Newton.setPolicy: policy ID cannot be empty");
        require(bytes(idToPolicy[_policyID]).length > 0, "Newton.setPolicy: policy ID not registered");
        clientToPolicyID[msg.sender] = _policyID;
        emit SetPolicy(msg.sender, _policyID);
    }

    /**
     * @notice Overrides the policy for a specific client address
     * @param _policyID is the unique identifier for the policy
     * @param _clientAddress is the address of the client for which the policy is being overridden
     */
    function overrideClientPolicyID(string memory _policyID, address _clientAddress) external onlyOwner {
        require(bytes(_policyID).length > 0, "Newton.setPolicy: policy ID cannot be empty");
        require(idToPolicy[_policyID] > 0, "Newton.setPolicy: policy ID not registered");
        clientToPolicyID[_clientAddress] = _policyID;
        emit SetPolicy(_clientAddress, _policyID);
    }

    /**
     * @notice Performs the hashing of an STM task
     * @param _task parameters of the task
     * @return the keccak256 digest of the task
     */
    function hashTaskWithExpiry(
        Task calldata _task
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                _task.taskId,
                _task.msgSender,
                _task.target,
                _task.value,
                _task.encodedSigAndArgs,
                _task.policyID,
                _task.expireByTime
            )
        );
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
        require(block.timestamp <= _task.expireByTime, "ServiceManager.verify: transaction expired");
        require(!spentTaskIds[_task.taskId], "ServiceManager.verify: task ID already spent");

        bytes32 messageHash = hashTaskSafe(_task);

        emit TaskValidated(
            _task.msgSender,
            _task.target,
            _task.value,
            _task.policyID,
            _task.taskId,
            _task.expireByTime
        );

        spentTaskIds[_task.taskId] = true;
        return true;
    }
}
