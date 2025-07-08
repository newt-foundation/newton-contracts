// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin-upgrades/contracts/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts/interfaces/IERC165.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import {NewtonPolicyFactory} from "./NewtonPolicyFactory.sol";
import {INewtonPolicyClient} from "../interfaces/INewtonPolicyClient.sol";
import {INewtonPolicy} from "../interfaces/INewtonPolicy.sol";

contract NewtonPolicy is Initializable, OwnableUpgradeable, ERC165Upgradeable, INewtonPolicy {
    /* STORAGE */
    address public factory;
    string public policyUri;
    string public schemaUri;
    string public entrypoint;
    address[] public policyData;
    string public metadataUri;

    // mapping of policyId to per policy config
    mapping(bytes32 => INewtonPolicy.PolicyConfig) private _policyIdToConfig;

    // mapping of client to policyId
    mapping(address => bytes32) public clientToPolicyId;

    /* ERRORS */
    error OnlyPolicyClient();
    error InterfaceNotSupported();

    /* Modifiers */
    modifier onlyPolicyClient() {
        require(msg.sender.code.length > 0, OnlyPolicyClient());

        bytes4 interfaceId = type(INewtonPolicyClient).interfaceId;

        (bool success, bytes memory result) = msg.sender.staticcall(
            abi.encodeWithSelector(IERC165.supportsInterface.selector, interfaceId)
        );

        require(
            success && result.length == 32 && abi.decode(result, (bool)), InterfaceNotSupported()
        );

        _;
    }

    function initialize(
        address _factory,
        string calldata _entrypoint,
        string calldata _policyUri,
        string calldata _schemaUri,
        address[] calldata _policyData,
        string calldata _metadataUri,
        address _owner
    ) public initializer {
        __Ownable_init();
        _transferOwnership(_owner);
        __ERC165_init();
        factory = _factory;
        policyUri = _policyUri;
        schemaUri = _schemaUri;
        policyData = _policyData;
        entrypoint = _entrypoint;
        metadataUri = _metadataUri;
    }

    // function to set policy for the msg.sender (client)
    function setPolicy(
        INewtonPolicy.PolicyConfig calldata policyConfig
    ) public onlyPolicyClient returns (bytes32) {
        bytes32 policyId = keccak256(
            abi.encode(
                msg.sender,
                address(this),
                owner(),
                policyUri,
                schemaUri,
                entrypoint,
                policyConfig,
                policyData,
                block.timestamp
            )
        );

        _policyIdToConfig[policyId] = policyConfig;
        clientToPolicyId[msg.sender] = policyId;

        emit PolicySet(
            msg.sender,
            policyId,
            SetPolicyInfo(
                policyId,
                address(this),
                owner(),
                policyUri,
                schemaUri,
                entrypoint,
                policyConfig,
                policyData
            )
        );

        return policyId;
    }

    function getPolicyId(
        address client
    ) public view returns (bytes32) {
        return clientToPolicyId[client];
    }

    function getMetadataUri() public view returns (string memory) {
        return metadataUri;
    }

    function setMetadataUri(
        string calldata _metadataUri
    ) public onlyOwner {
        metadataUri = _metadataUri;
        emit PolicyMetadataUriUpdated(_metadataUri);
    }

    function getEntrypoint() public view returns (string memory) {
        return entrypoint;
    }

    function getPolicyUri() public view returns (string memory) {
        return policyUri;
    }

    function getSchemaUri() public view returns (string memory) {
        return schemaUri;
    }

    function getPolicyData() public view returns (address[] memory) {
        return policyData;
    }

    function getPolicyConfig(
        bytes32 policyId
    ) public view returns (INewtonPolicy.PolicyConfig memory) {
        return _policyIdToConfig[policyId];
    }

    function isPolicyVerified() public view returns (bool) {
        return NewtonPolicyFactory(factory).getPolicyVerificationInfo(address(this)).verified;
    }

    /// @notice Function to check if a contract implements an interface
    /// @param interfaceId The interface identifier to check
    /// @return True if the contract implements the interface, false otherwise
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165Upgradeable, IERC165) returns (bool) {
        return
            interfaceId == type(INewtonPolicy).interfaceId || super.supportsInterface(interfaceId);
    }
}
