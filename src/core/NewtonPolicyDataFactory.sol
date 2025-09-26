// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {NewtonMessage} from "./NewtonMessage.sol";
import {INewtonPolicyData} from "../interfaces/INewtonPolicyData.sol";
import {NewtonPolicyData} from "./NewtonPolicyData.sol";
import {ChainLib} from "../libraries/ChainLib.sol";

contract NewtonPolicyDataFactory is OwnableUpgradeable {
    address public implementation;
    ProxyAdmin public proxyAdmin;

    mapping(address => NewtonMessage.VerificationInfo) public policyDataVerifications;
    mapping(address => bool) public verifiers;

    event PolicyDataVerificationUpdated(
        address policyData, NewtonMessage.VerificationInfo verificationInfo
    );
    event PolicyDataDeployed(address policyData, INewtonPolicyData.PolicyDataInfo policyDataInfo);
    event VerifierAdded(address verifier);
    event VerifierRemoved(address verifier);

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address owner
    ) public initializer {
        __Ownable_init();
        _transferOwnership(owner);
        implementation = address(new NewtonPolicyData());
        proxyAdmin = new ProxyAdmin();
        verifiers[owner] = true;
    }

    /* ERRORS */
    error OnlyNewtonPolicyData();
    error InterfaceNotSupported();
    error OnlyVerifiers();

    /* Modifiers */
    modifier onlyNewtonPolicyData() {
        require(msg.sender.code.length > 0, OnlyNewtonPolicyData());

        bytes4 interfaceId = type(INewtonPolicyData).interfaceId;

        (bool success, bytes memory result) = msg.sender.staticcall(
            abi.encodeWithSelector(IERC165.supportsInterface.selector, interfaceId)
        );

        require(
            success && result.length == 32 && abi.decode(result, (bool)), InterfaceNotSupported()
        );

        _;
    }

    modifier onlyVerifiers() {
        require(msg.sender == owner() || verifiers[msg.sender], OnlyVerifiers());
        _;
    }

    function deployPolicyData(
        string memory _wasmCid,
        string memory _wasmArgs,
        uint32 _expireAfter,
        string memory _metadataCid,
        address _owner
    ) external returns (address policyDataAddr) {
        bytes memory initData = abi.encodeWithSelector(
            NewtonPolicyData.initialize.selector,
            address(this),
            _wasmCid,
            _wasmArgs,
            _expireAfter,
            _metadataCid,
            _owner
        );

        bytes32 salt = keccak256(
            abi.encodePacked(address(this), _wasmCid, _wasmArgs, _expireAfter, _metadataCid, _owner)
        );

        bytes memory bytecode = abi.encodePacked(
            type(TransparentUpgradeableProxy).creationCode,
            abi.encode(implementation, address(proxyAdmin), initData)
        );

        address proxy;
        assembly {
            proxy := create2(0, add(bytecode, 32), mload(bytecode), salt)
            if iszero(proxy) { revert(0, 0) }
        }

        policyDataAddr = proxy;

        ChainLib.requireSupportedChain();
        if (ChainLib.isMainnet()) {
            policyDataVerifications[policyDataAddr] =
                NewtonMessage.VerificationInfo(address(0), false, 0);
        } else {
            // set policy verification to default true for testnet
            policyDataVerifications[policyDataAddr] =
                NewtonMessage.VerificationInfo(owner(), true, block.timestamp);
        }

        emit PolicyDataDeployed(
            policyDataAddr,
            INewtonPolicyData.PolicyDataInfo(
                policyDataAddr, _owner, _metadataCid, _wasmCid, _wasmArgs, _expireAfter
            )
        );
    }

    function computePolicyDataAddress(
        string memory _wasmCid,
        string memory _wasmArgs,
        uint32 _expireAfter,
        string memory _metadataCid,
        address _owner
    ) public view returns (address predicted) {
        bytes memory initData = abi.encodeWithSelector(
            NewtonPolicyData.initialize.selector,
            address(this),
            _wasmCid,
            _wasmArgs,
            _expireAfter,
            _metadataCid,
            _owner
        );

        bytes32 salt = keccak256(
            abi.encodePacked(address(this), _wasmCid, _wasmArgs, _expireAfter, _metadataCid, _owner)
        );

        bytes memory bytecode = abi.encodePacked(
            type(TransparentUpgradeableProxy).creationCode,
            abi.encode(implementation, address(proxyAdmin), initData)
        );

        predicted = Create2.computeAddress(salt, keccak256(bytecode));
    }

    function setPolicyDataVerified(address policyDataAddr, bool verified) external onlyVerifiers {
        policyDataVerifications[policyDataAddr] =
            NewtonMessage.VerificationInfo(msg.sender, verified, block.timestamp);
        emit PolicyDataVerificationUpdated(policyDataAddr, policyDataVerifications[policyDataAddr]);
    }

    function getPolicyDataVerificationInfo(
        address policyDataAddr
    ) external view returns (NewtonMessage.VerificationInfo memory) {
        return policyDataVerifications[policyDataAddr];
    }

    function addVerifier(
        address verifier
    ) external onlyOwner {
        verifiers[verifier] = true;
        emit VerifierAdded(verifier);
    }

    function removeVerifier(
        address verifier
    ) external onlyOwner {
        verifiers[verifier] = false;
        emit VerifierRemoved(verifier);
    }
}
