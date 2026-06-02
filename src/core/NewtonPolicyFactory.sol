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

    mapping(address => NewtonMessage.VerificationInfo) public policyVerifications;
    mapping(address => address[]) public ownersToPolicies;

    EnumerableSet.AddressSet private _verifiers;
    EnumerableSet.AddressSet private _policyOwners;

    /// @notice Verification status applied to newly deployed policies by default.
    /// @dev Set in `initialize()` to `!isMainnet()` (testnet/local verified, mainnet unverified),
    ///      matching the original chain-id behavior. On a proxy upgrade this slot reads `false`
    ///      for pre-existing factories (uninitialized), which preserves the mainnet default and
    ///      lets a mainnet "stagef" deployment opt into `true` via `setDefaultPolicyVerified`.
    bool public defaultPolicyVerified;

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
    event DefaultPolicyVerifiedUpdated(bool verified);
    event OwnershipTransferredWithVerifierUpdate(
        address indexed previousOwner, address indexed newOwner
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
        _verifiers.add(owner);
        // Preserve the original chain-id default: testnet/local verify policies on deploy,
        // mainnet does not. Mainnet "stagef" can opt in afterwards via setDefaultPolicyVerified.
        defaultPolicyVerified = !ChainLib.isMainnet();
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
        if (defaultPolicyVerified) {
            policyVerifications[policyAddr] =
                NewtonMessage.VerificationInfo(owner(), true, block.timestamp);
        } else {
            policyVerifications[policyAddr] = NewtonMessage.VerificationInfo(address(0), false, 0);
        }

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

    /// @notice Set the verification status assigned to newly deployed policies.
    /// @dev Does not affect already-deployed policies; use `setPolicyVerification` for those.
    function setDefaultPolicyVerified(
        bool verified
    ) external onlyAdmin {
        defaultPolicyVerified = verified;
        emit DefaultPolicyVerifiedUpdated(verified);
    }

    function setPolicyVerification(
        address policyAddr,
        bool verified
    ) external onlyAdmin {
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
    ) external onlyAdmin {
        if (_verifiers.add(verifier)) {
            emit VerifierAdded(verifier);
        }
    }

    function removeVerifier(
        address verifier
    ) external onlyAdmin {
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
     * Revokes verifier privileges from the old owner on ownership transfer
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
