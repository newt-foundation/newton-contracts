// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {NewtonMessage} from "./NewtonMessage.sol";
import {INewtonPolicyData} from "../interfaces/INewtonPolicyData.sol";
import {NewtonPolicyData} from "./NewtonPolicyData.sol";
import {ChainLib} from "../libraries/ChainLib.sol";
import {SemVerMixin} from "../mixins/SemVerMixin.sol";

contract NewtonPolicyDataFactory is OwnableUpgradeable, SemVerMixin {
    using EnumerableSet for EnumerableSet.AddressSet;

    address public implementation;
    ProxyAdmin public proxyAdmin;

    mapping(address => NewtonMessage.VerificationInfo) public policyDataVerifications;
    mapping(address => address[]) public ownersToPolicyData;
    address[] public policyDataOwners;

    EnumerableSet.AddressSet private _verifiers;

    /// @notice Struct used for salt generation to ensure consistent encoding
    struct SaltData {
        address factory;
        string wasmCid;
        string secretsSchemaCid;
        uint32 expireAfter;
        string metadataCid;
        address owner;
    }

    event PolicyDataVerificationUpdated(
        address policyData, NewtonMessage.VerificationInfo verificationInfo
    );
    event PolicyDataDeployed(
        address policyData,
        INewtonPolicyData.PolicyDataInfo policyDataInfo,
        string implementationVersion
    );
    event ImplementationUpdated(
        address indexed oldImplementation, address indexed newImplementation
    );
    event VerifierAdded(address indexed verifier);
    event VerifierRemoved(address indexed verifier);

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
        implementation = address(new NewtonPolicyData());
        proxyAdmin = new ProxyAdmin();
        _verifiers.add(owner);
    }

    /* ERRORS */
    error OnlyNewtonPolicyData();
    error InterfaceNotSupported();
    error OnlyVerifiers();
    error InvalidImplementationAddress();

    /* Modifiers */
    modifier onlyNewtonPolicyData() {
        require(msg.sender.code.length > 0, OnlyNewtonPolicyData());

        bytes4 interfaceId = type(INewtonPolicyData).interfaceId;

        (bool success, bytes memory result) = msg.sender
            .staticcall(abi.encodeWithSelector(IERC165.supportsInterface.selector, interfaceId));

        require(
            success && result.length == 32 && abi.decode(result, (bool)), InterfaceNotSupported()
        );

        _;
    }

    modifier onlyVerifiers() {
        require(msg.sender == owner() || _verifiers.contains(msg.sender), OnlyVerifiers());
        _;
    }

    function deployPolicyData(
        string memory _wasmCid,
        string memory _secretsSchemaCid,
        uint32 _expireAfter,
        string memory _metadataCid,
        address _owner
    ) external returns (address policyDataAddr) {
        bytes memory initData = abi.encodeWithSelector(
            NewtonPolicyData.initialize.selector,
            address(this),
            _wasmCid,
            _secretsSchemaCid,
            _expireAfter,
            _metadataCid,
            _owner
        );

        SaltData memory saltData = SaltData({
            factory: address(this),
            wasmCid: _wasmCid,
            secretsSchemaCid: _secretsSchemaCid,
            expireAfter: _expireAfter,
            metadataCid: _metadataCid,
            owner: _owner
        });

        bytes32 salt = keccak256(
            abi.encodePacked(
                saltData.factory,
                saltData.wasmCid,
                saltData.secretsSchemaCid,
                saltData.expireAfter,
                saltData.metadataCid,
                saltData.owner
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

        if (ownersToPolicyData[_owner].length == 0) {
            policyDataOwners.push(_owner);
        }
        ownersToPolicyData[_owner].push(policyDataAddr);

        emit PolicyDataDeployed(
            policyDataAddr,
            INewtonPolicyData.PolicyDataInfo(
                policyDataAddr, _owner, _metadataCid, _wasmCid, _secretsSchemaCid, _expireAfter
            ),
            version()
        );
    }

    /// @notice Updates the policy-data implementation used for newly deployed policy-data proxies.
    /// @dev `upgradeContracts()` upgrades the factory proxy but does not re-run `initialize()`.
    ///      Without this setter, the factory continues using the *old* `implementation` stored in
    ///      storage.
    function setImplementation(
        address newImplementation
    ) external onlyOwner {
        require(newImplementation.code.length > 0, InvalidImplementationAddress());
        address old = implementation;
        implementation = newImplementation;
        emit ImplementationUpdated(old, newImplementation);
    }

    function computePolicyDataAddress(
        string memory _wasmCid,
        string memory _secretsSchemaCid,
        uint32 _expireAfter,
        string memory _metadataCid,
        address _owner
    ) public view returns (address predicted) {
        bytes memory initData = abi.encodeWithSelector(
            NewtonPolicyData.initialize.selector,
            address(this),
            _wasmCid,
            _secretsSchemaCid,
            _expireAfter,
            _metadataCid,
            _owner
        );

        SaltData memory saltData = SaltData({
            factory: address(this),
            wasmCid: _wasmCid,
            secretsSchemaCid: _secretsSchemaCid,
            expireAfter: _expireAfter,
            metadataCid: _metadataCid,
            owner: _owner
        });

        bytes32 salt = keccak256(
            abi.encodePacked(
                saltData.factory,
                saltData.wasmCid,
                saltData.secretsSchemaCid,
                saltData.expireAfter,
                saltData.metadataCid,
                saltData.owner
            )
        );

        bytes memory bytecode = abi.encodePacked(
            type(TransparentUpgradeableProxy).creationCode,
            abi.encode(implementation, address(proxyAdmin), initData)
        );

        predicted = Create2.computeAddress(salt, keccak256(bytecode));
    }

    function setPolicyDataVerified(
        address policyDataAddr,
        bool verified
    ) external onlyVerifiers {
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

    function getAllPolicyDataByOwner(
        address owner
    ) external view returns (address[] memory) {
        return ownersToPolicyData[owner];
    }

    function getAllPolicyDataOwners() external view returns (address[] memory) {
        return policyDataOwners;
    }

    function getAllVerifiers() external view returns (address[] memory) {
        return _verifiers.values();
    }

    function isVerifier(
        address verifier
    ) external view returns (bool) {
        return _verifiers.contains(verifier);
    }
}
