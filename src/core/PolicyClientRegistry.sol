// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {IPolicyClientRegistry} from "../interfaces/IPolicyClientRegistry.sol";
import {INewtonPolicyClient} from "../interfaces/INewtonPolicyClient.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import {SemVerMixin} from "../mixins/SemVerMixin.sol";

/// @title PolicyClientRegistry
/// @notice On-chain registry for Newton policy client contracts. Enables enumeration
///         of all policy clients owned by a given address and provides an on-chain
///         lookup for active policy client status (used by IdentityRegistry).
contract PolicyClientRegistry is OwnableUpgradeable, SemVerMixin, IPolicyClientRegistry {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Mapping from client address to its registration record
    mapping(address => ClientRecord) private _clients;

    /// @notice Reverse index: owner address to set of client addresses
    mapping(address => EnumerableSet.AddressSet) private _ownerClients;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        string memory _version
    ) SemVerMixin(_version) {
        _disableInitializers();
    }

    /// @notice Initialize the registry (proxy pattern)
    /// @param _admin The admin address (receives ownership)
    function initialize(
        address _admin
    ) external initializer {
        __Ownable_init();
        _transferOwnership(_admin);
    }

    /// @inheritdoc IPolicyClientRegistry
    function registerClient(
        address client
    ) external {
        require(
            IERC165(client).supportsInterface(type(INewtonPolicyClient).interfaceId),
            NotPolicyClient(client)
        );
        require(_clients[client].registeredAt == 0, ClientAlreadyRegistered(client));

        _clients[client] =
            ClientRecord({owner: msg.sender, active: true, registeredAt: uint64(block.timestamp)});
        _ownerClients[msg.sender].add(client);

        emit ClientRegistered(client, msg.sender);
    }

    /// @inheritdoc IPolicyClientRegistry
    function deactivateClient(
        address client
    ) external {
        _requireClientOwner(client);
        require(_clients[client].active, ClientNotRegistered(client));

        _clients[client].active = false;

        emit ClientDeactivated(client, msg.sender);
    }

    /// @inheritdoc IPolicyClientRegistry
    function activateClient(
        address client
    ) external {
        _requireClientOwner(client);
        require(!_clients[client].active, ClientAlreadyRegistered(client));

        _clients[client].active = true;

        emit ClientActivated(client, msg.sender);
    }

    /// @inheritdoc IPolicyClientRegistry
    function setClientOwner(
        address client,
        address newOwner
    ) external {
        _requireClientOwner(client);
        require(newOwner != address(0), InvalidOwnerAddress());

        address oldOwner = msg.sender;

        _clients[client].owner = newOwner;
        _ownerClients[oldOwner].remove(client);
        _ownerClients[newOwner].add(client);

        emit ClientOwnerChanged(client, oldOwner, newOwner);
    }

    /// @inheritdoc IPolicyClientRegistry
    function getClientRecord(
        address client
    ) external view returns (ClientRecord memory) {
        require(_clients[client].registeredAt != 0, ClientNotRegistered(client));
        return _clients[client];
    }

    /// @inheritdoc IPolicyClientRegistry
    function getClientsByOwner(
        address owner
    ) external view returns (address[] memory) {
        return _ownerClients[owner].values();
    }

    /// @inheritdoc IPolicyClientRegistry
    function isRegisteredClient(
        address client
    ) external view returns (bool) {
        return _clients[client].registeredAt != 0 && _clients[client].active;
    }

    /// @inheritdoc IPolicyClientRegistry
    function getClientCount(
        address owner
    ) external view returns (uint256) {
        return _ownerClients[owner].length();
    }

    /// @notice Reverts if the caller is not the registered owner of the client
    function _requireClientOwner(
        address client
    ) private view {
        require(_clients[client].registeredAt != 0, ClientNotRegistered(client));
        require(_clients[client].owner == msg.sender, NotClientOwner(client, msg.sender));
    }
}
