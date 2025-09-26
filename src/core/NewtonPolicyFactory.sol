// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {NewtonMessage} from "./NewtonMessage.sol";
import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";
import {NewtonPolicy} from "./NewtonPolicy.sol";
import {ChainLib} from "../libraries/ChainLib.sol";

contract NewtonPolicyFactory is OwnableUpgradeable {
    address public implementation;
    ProxyAdmin public proxyAdmin;

    mapping(address => bool) public verifiers;
    mapping(address => NewtonMessage.VerificationInfo) public policyVerifications;

    event PolicyDeployed(address policy, INewtonPolicy.PolicyInfo policyInfo);
    event PolicyVerificationUpdated(
        address policy, NewtonMessage.VerificationInfo verificationInfo
    );
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
        implementation = address(new NewtonPolicy());
        proxyAdmin = new ProxyAdmin();
        verifiers[owner] = true;
    }

    /* ERRORS */
    error OnlyNewtonPolicy();
    error InterfaceNotSupported();
    error OnlyVerifiers();

    /* Modifiers */
    modifier onlyNewtonPolicy() {
        require(msg.sender.code.length > 0, OnlyNewtonPolicy());

        bytes4 interfaceId = type(INewtonPolicy).interfaceId;

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

    function deployPolicy(
        string memory _entrypoint,
        string memory _policyCid,
        string memory _schemaCid,
        address[] memory _policyData,
        string memory _metadataCid,
        address _owner
    ) external returns (address policyAddr) {
        bytes memory initData = abi.encodeWithSelector(
            NewtonPolicy.initialize.selector,
            address(this),
            _entrypoint,
            _policyCid,
            _schemaCid,
            _policyData,
            _metadataCid,
            _owner
        );

        bytes32 salt = keccak256(
            abi.encodePacked(
                address(this),
                _entrypoint,
                _policyCid,
                _schemaCid,
                _policyData,
                _metadataCid,
                _owner
            )
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

        policyAddr = proxy;

        ChainLib.requireSupportedChain();
        if (ChainLib.isMainnet()) {
            policyVerifications[policyAddr] = NewtonMessage.VerificationInfo(address(0), false, 0);
        } else {
            // set policy verification to default true for testnet
            policyVerifications[policyAddr] =
                NewtonMessage.VerificationInfo(owner(), true, block.timestamp);
        }

        emit PolicyDeployed(
            policyAddr,
            INewtonPolicy.PolicyInfo(
                policyAddr, _owner, _metadataCid, _policyCid, _schemaCid, _entrypoint, _policyData
            )
        );
    }

    function computePolicyAddress(
        string memory _entrypoint,
        string memory _policyCid,
        string memory _schemaCid,
        address[] memory _policyData,
        string memory _metadataCid,
        address _owner
    ) public view returns (address predicted) {
        bytes memory initData = abi.encodeWithSelector(
            NewtonPolicy.initialize.selector,
            address(this),
            _entrypoint,
            _policyCid,
            _schemaCid,
            _policyData,
            _metadataCid,
            _owner
        );

        bytes32 salt = keccak256(
            abi.encodePacked(
                address(this),
                _entrypoint,
                _policyCid,
                _schemaCid,
                _policyData,
                _metadataCid,
                _owner
            )
        );

        bytes memory bytecode = abi.encodePacked(
            type(TransparentUpgradeableProxy).creationCode,
            abi.encode(implementation, address(proxyAdmin), initData)
        );

        predicted = Create2.computeAddress(salt, keccak256(bytecode));
    }

    function setPolicyVerification(address policyAddr, bool verified) external onlyVerifiers {
        policyVerifications[policyAddr] =
            NewtonMessage.VerificationInfo(msg.sender, verified, block.timestamp);
        emit PolicyVerificationUpdated(policyAddr, policyVerifications[policyAddr]);
    }

    function getPolicyVerificationInfo(
        address policyAddr
    ) external view returns (NewtonMessage.VerificationInfo memory) {
        return policyVerifications[policyAddr];
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
