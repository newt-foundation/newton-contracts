// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {NewtonMessage} from "./NewtonMessage.sol";
import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";
import {NewtonPolicy} from "./NewtonPolicy.sol";
import {ChainLib} from "../libraries/ChainLib.sol";
import {SemVerMixin} from "../mixins/SemVerMixin.sol";

contract NewtonPolicyFactory is OwnableUpgradeable, SemVerMixin {
    using EnumerableSet for EnumerableSet.AddressSet;

    error Create2Failed();

    address public implementation;
    ProxyAdmin public proxyAdmin;

    mapping(address => NewtonMessage.VerificationInfo) public policyVerifications;
    mapping(address => address[]) public ownersToPolicies;

    EnumerableSet.AddressSet private _verifiers;
    EnumerableSet.AddressSet private _policyOwners;

    event PolicyDeployed(
        address policy, INewtonPolicy.PolicyInfo policyInfo, string implementationVersion
    );
    event ImplementationUpdated(
        address indexed oldImplementation, address indexed newImplementation
    );
    event PolicyVerificationUpdated(
        address policy, NewtonMessage.VerificationInfo verificationInfo
    );
    event VerifierAdded(address indexed verifier);
    event VerifierRemoved(address indexed verifier);
    event OwnershipTransferredWithVerifierUpdate(
        address indexed previousOwner, address indexed newOwner
    );

    constructor(
        string memory _version
    ) SemVerMixin(_version) {
        _disableInitializers();
    }

    function initialize(
        address owner
    ) public initializer {
        __Ownable_init();
        _transferOwnership(owner);
        implementation = address(new NewtonPolicy());
        proxyAdmin = new ProxyAdmin();
        _verifiers.add(owner);
    }

    /* ERRORS */
    error OnlyVerifiers();
    error InvalidImplementationAddress();

    /* Modifiers */
    modifier onlyVerifiers() {
        require(msg.sender == owner() || _verifiers.contains(msg.sender), OnlyVerifiers());
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
        }
        require(proxy != address(0), Create2Failed());

        policyAddr = proxy;

        ChainLib.requireSupportedChain();
        if (ChainLib.isMainnet()) {
            policyVerifications[policyAddr] = NewtonMessage.VerificationInfo(address(0), false, 0);
        } else {
            // set policy verification to default true for testnet
            policyVerifications[policyAddr] =
                NewtonMessage.VerificationInfo(owner(), true, block.timestamp);
        }

        ownersToPolicies[_owner].push(policyAddr);
        _policyOwners.add(_owner);

        emit PolicyDeployed(
            policyAddr,
            INewtonPolicy.PolicyInfo(
                policyAddr, _owner, _metadataCid, _policyCid, _schemaCid, _entrypoint, _policyData
            ),
            version()
        );
    }

    /// @notice Updates the policy implementation used for newly deployed policy proxies.
    /// @dev `upgradeContracts()` upgrades the factory proxy but does not re-run `initialize()`.
    ///      Without this setter, the factory continues using the *old* `implementation` stored in
    ///      storage, which can cause interface-id mismatches across deployments.
    function setImplementation(
        address newImplementation
    ) external onlyOwner {
        require(newImplementation.code.length > 0, InvalidImplementationAddress());
        address old = implementation;
        implementation = newImplementation;
        emit ImplementationUpdated(old, newImplementation);
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

    function setPolicyVerification(
        address policyAddr,
        bool verified
    ) external onlyVerifiers {
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
        if (_verifiers.add(verifier)) {
            emit VerifierAdded(verifier);
        }
    }

    function removeVerifier(
        address verifier
    ) external onlyOwner {
        if (_verifiers.remove(verifier)) {
            emit VerifierRemoved(verifier);
        }
    }

    function getAllPoliciesByOwner(
        address owner
    ) external view returns (address[] memory) {
        return ownersToPolicies[owner];
    }

    function getAllVerifiers() external view returns (address[] memory) {
        return _verifiers.values();
    }

    function getAllPolicyOwners() external view returns (address[] memory) {
        return _policyOwners.values();
    }

    function isVerifier(
        address verifier
    ) external view returns (bool) {
        return _verifiers.contains(verifier);
    }

    /**
     * @dev Override transferOwnership to remove verifier privileges from the old owner
     * This addresses FIND-013: Old owner retains verifier privileges after ownership transfer
     */
    function transferOwnership(
        address newOwner
    ) public override onlyOwner {
        address previousOwner = owner();

        if (_verifiers.remove(previousOwner)) {
            emit VerifierRemoved(previousOwner);
        }

        _transferOwnership(newOwner);

        if (_verifiers.add(newOwner)) {
            emit VerifierAdded(newOwner);
        }

        emit OwnershipTransferredWithVerifierUpdate(previousOwner, newOwner);
    }
}
