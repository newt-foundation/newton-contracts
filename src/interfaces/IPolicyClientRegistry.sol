// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

/// @title IPolicyClientRegistry
/// @notice Registry for tracking Newton policy client contracts and their owners.
///         Enables enumeration of all policy clients owned by a given address.
interface IPolicyClientRegistry {
    /// @notice Metadata record for a registered policy client
    struct ClientRecord {
        address owner;
        bool active;
        uint64 registeredAt;
    }

    // Events

    /// @notice Emitted when a new policy client is registered
    event ClientRegistered(address indexed client, address indexed owner);

    /// @notice Emitted when a policy client is deactivated
    event ClientDeactivated(address indexed client, address indexed owner);

    /// @notice Emitted when a policy client is reactivated
    event ClientActivated(address indexed client, address indexed owner);

    /// @notice Emitted when a policy client's owner is changed
    event ClientOwnerChanged(
        address indexed client, address indexed oldOwner, address indexed newOwner
    );

    // Errors

    /// @notice The client address does not implement INewtonPolicyClient (ERC-165 check)
    error NotPolicyClient(address client);

    /// @notice The client is already registered
    error ClientAlreadyRegistered(address client);

    /// @notice The client is not registered
    error ClientNotRegistered(address client);

    /// @notice The caller is not the registered owner of the client
    error NotClientOwner(address client, address caller);

    /// @notice The new owner address is the zero address
    error InvalidOwnerAddress();

    // Functions

    /// @notice Register a policy client. The caller becomes the registered owner.
    /// @param client The address of the policy client contract (must implement INewtonPolicyClient)
    function registerClient(
        address client
    ) external;

    /// @notice Deactivate a registered policy client. Only callable by the registered owner.
    /// @param client The address of the policy client to deactivate
    function deactivateClient(
        address client
    ) external;

    /// @notice Reactivate a previously deactivated policy client. Only callable by the registered owner.
    /// @param client The address of the policy client to reactivate
    function activateClient(
        address client
    ) external;

    /// @notice Transfer ownership of a registered client record. Only callable by the current registered owner.
    /// @param client The address of the policy client
    /// @param newOwner The address of the new owner
    function setClientOwner(
        address client,
        address newOwner
    ) external;

    /// @notice Get the record for a registered client
    /// @param client The address of the policy client
    /// @return The client record
    function getClientRecord(
        address client
    ) external view returns (ClientRecord memory);

    /// @notice Get all policy client addresses owned by an address
    /// @param owner The owner address to query
    /// @return An array of policy client addresses
    function getClientsByOwner(
        address owner
    ) external view returns (address[] memory);

    /// @notice Check if a client is registered and active
    /// @param client The address to check
    /// @return True if registered and active
    function isRegisteredClient(
        address client
    ) external view returns (bool);

    /// @notice Get the number of clients owned by an address
    /// @param owner The owner address to query
    /// @return The number of registered clients
    function getClientCount(
        address owner
    ) external view returns (uint256);
}
