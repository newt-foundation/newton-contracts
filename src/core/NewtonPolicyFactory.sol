// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {NewtonMessage} from "./NewtonMessage.sol";
import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";
import {NewtonPolicy} from "./NewtonPolicy.sol";
import {ChainLib} from "../libraries/ChainLib.sol";
import {SemVerMixin} from "../mixins/SemVerMixin.sol";
import {AdminMixin} from "../mixins/AdminMixin.sol";

contract NewtonPolicyFactory is AdminMixin, SemVerMixin {
    using EnumerableSet for EnumerableSet.AddressSet;

    error Create2Failed();

    address public implementation;
    ProxyAdmin public proxyAdmin;

    /// @dev DEPRECATED (policy verification removed). Retained (name and slot unchanged) to
    ///      preserve the storage layout of already-deployed factory proxies. No longer read or
    ///      written by the protocol.
    mapping(address => NewtonMessage.VerificationInfo) private policyVerifications;
    mapping(address => address[]) public ownersToPolicies;

    /// @dev DEPRECATED (verifier management removed). Retained to preserve storage layout.
    EnumerableSet.AddressSet private _verifiers;
    EnumerableSet.AddressSet private _policyOwners;

    /// @dev DEPRECATED (default policy verification removed). Retained to preserve storage layout.
    bool private defaultPolicyVerified;

    event PolicyDeployed(
        address policy, INewtonPolicy.PolicyInfo policyInfo, string implementationVersion
    );
    event ImplementationUpdated(
        address indexed oldImplementation, address indexed newImplementation
    );

    constructor(
        string memory _version
    ) SemVerMixin(_version) {
        _disableInitializers();
    }

    error InvalidOwnerAddress();

    function initialize(
        address owner
    ) public initializer {
        require(owner != address(0), InvalidOwnerAddress());
        __Ownable_init();
        _transferOwnership(owner);
        implementation = address(new NewtonPolicy());
        proxyAdmin = new ProxyAdmin();
    }

    function initializeV2(
        address admin
    ) external onlyOwner reinitializer(2) {
        _initializeAdmin(admin);
    }

    /* ERRORS */
    error InvalidImplementationAddress();

    function deployPolicy(
        string memory _entrypoint,
        string memory _policyCid,
        string memory _schemaCid,
        address[] memory _policyData,
        string memory _metadataCid,
        address _owner,
        bytes32 _policyCodeHash
    ) external returns (address policyAddr) {
        bytes memory initData = abi.encodeWithSelector(
            NewtonPolicy.initialize.selector,
            address(this),
            _entrypoint,
            _policyCid,
            _schemaCid,
            _policyData,
            _metadataCid,
            _owner,
            _policyCodeHash
        );

        bytes32 salt = keccak256(
            abi.encodePacked(
                address(this),
                _entrypoint,
                _policyCid,
                _schemaCid,
                _policyData,
                _metadataCid,
                _owner,
                _policyCodeHash
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

        ownersToPolicies[_owner].push(policyAddr);
        _policyOwners.add(_owner);

        emit PolicyDeployed(
            policyAddr,
            INewtonPolicy.PolicyInfo(
                policyAddr,
                _owner,
                _metadataCid,
                _policyCid,
                _schemaCid,
                _entrypoint,
                _policyData,
                _policyCodeHash
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
        address _owner,
        bytes32 _policyCodeHash
    ) public view returns (address predicted) {
        bytes memory initData = abi.encodeWithSelector(
            NewtonPolicy.initialize.selector,
            address(this),
            _entrypoint,
            _policyCid,
            _schemaCid,
            _policyData,
            _metadataCid,
            _owner,
            _policyCodeHash
        );

        bytes32 salt = keccak256(
            abi.encodePacked(
                address(this),
                _entrypoint,
                _policyCid,
                _schemaCid,
                _policyData,
                _metadataCid,
                _owner,
                _policyCodeHash
            )
        );

        bytes memory bytecode = abi.encodePacked(
            type(TransparentUpgradeableProxy).creationCode,
            abi.encode(implementation, address(proxyAdmin), initData)
        );

        predicted = Create2.computeAddress(salt, keccak256(bytecode));
    }

    function getAllPoliciesByOwner(
        address owner
    ) external view returns (address[] memory) {
        return ownersToPolicies[owner];
    }

    function getAllPolicyOwners() external view returns (address[] memory) {
        return _policyOwners.values();
    }
}
