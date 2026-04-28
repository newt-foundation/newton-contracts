// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin-upgrades/contracts/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts/interfaces/IERC165.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "./NewtonPolicyDataFactory.sol";
import "../interfaces/INewtonPolicyData.sol";
import "../interfaces/INewtonPolicy.sol";
import {SemVerMixin} from "../mixins/SemVerMixin.sol";
import {PROTOCOL_VERSION} from "../libraries/ProtocolVersion.sol";

contract NewtonPolicyData is
    Initializable,
    OwnableUpgradeable,
    ERC165Upgradeable,
    INewtonPolicyData,
    SemVerMixin
{
    constructor() SemVerMixin(PROTOCOL_VERSION) {
        _disableInitializers();
    }

    /* STORAGE */
    address public factory;
    string private _wasmCid;
    string private _secretsSchemaCid;
    uint32 private _expireAfter;
    string private _metadataCid;

    /* ERRORS */
    error OnlyNewtonPolicy();
    error InterfaceNotSupported();
    error InvalidSignature();
    error SignatureVerificationFailed();
    error InvalidPolicyData(bytes data);
    error InvalidExpireAfter();
    error InvalidSecretsSchemaCid();

    /* EVENTS */
    event PolicyDataMetadataCidUpdated(string metadataCid);
    event SecretsSchemaCidUpdated(string secretsSchemaCid);

    /* Modifiers */
    modifier onlyNewtonPolicy() {
        require(msg.sender.code.length > 0, OnlyNewtonPolicy());

        bytes4 interfaceId = type(INewtonPolicy).interfaceId;

        (bool success, bytes memory result) = msg.sender
            .staticcall(abi.encodeWithSelector(IERC165.supportsInterface.selector, interfaceId));

        require(
            success && result.length == 32 && abi.decode(result, (bool)), InterfaceNotSupported()
        );

        _;
    }

    function initialize(
        address _factory,
        string calldata wasmCid,
        string calldata secretsSchemaCid,
        uint32 expireAfter,
        string calldata metadataCid,
        address _owner
    ) public initializer {
        __Ownable_init();
        _transferOwnership(_owner);
        __ERC165_init();
        factory = _factory;
        _wasmCid = wasmCid;
        _secretsSchemaCid = secretsSchemaCid;
        require(expireAfter > 0, InvalidExpireAfter());
        require(bytes(secretsSchemaCid).length > 0, InvalidSecretsSchemaCid());
        _expireAfter = expireAfter;
        _metadataCid = metadataCid;
    }

    function getMetadataCid() public view returns (string memory) {
        return _metadataCid;
    }

    function setMetadataCid(
        string calldata metadataCid
    ) public onlyOwner {
        _metadataCid = metadataCid;
        emit PolicyDataMetadataCidUpdated(metadataCid);
    }

    function getWasmCid() public view returns (string memory) {
        return _wasmCid;
    }

    function getSecretsSchemaCid() public view returns (string memory) {
        return _secretsSchemaCid;
    }

    function setSecretsSchemaCid(
        string calldata secretsSchemaCid
    ) public onlyOwner {
        require(bytes(secretsSchemaCid).length > 0, InvalidSecretsSchemaCid());
        _secretsSchemaCid = secretsSchemaCid;
        emit SecretsSchemaCidUpdated(secretsSchemaCid);
    }

    function getExpireAfter() public view returns (uint32) {
        return _expireAfter;
    }

    function isPolicyDataVerified() external view returns (bool) {
        return
            NewtonPolicyDataFactory(factory).getPolicyDataVerificationInfo(address(this)).verified;
    }

    /// @inheritdoc SemVerMixin
    function version()
        public
        view
        override(INewtonPolicyData, SemVerMixin)
        returns (string memory)
    {
        return super.version();
    }

    /// @notice Function to check if a contract implements an interface
    /// @param interfaceId The interface identifier to check
    /// @return True if the contract implements the interface, false otherwise
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165Upgradeable, IERC165) returns (bool) {
        return
            interfaceId == type(INewtonPolicyData).interfaceId
                || super.supportsInterface(interfaceId);
    }
}
