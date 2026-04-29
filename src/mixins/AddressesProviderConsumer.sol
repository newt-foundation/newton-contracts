// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

import {INewtonAddressesProvider} from "../interfaces/INewtonAddressesProvider.sol";
import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";
import {IPolicyClientRegistry} from "../interfaces/IPolicyClientRegistry.sol";
import {IStateRootCommittable} from "../interfaces/IStateRootCommittable.sol";
import {IViewBN254CertificateVerifier} from "../interfaces/IViewBN254CertificateVerifier.sol";

/// @title AddressesProviderConsumer
///
/// @notice Mixin for contracts that resolve dependencies from NewtonAddressesProvider.
///         All addresses are cached as immutables at construction time — zero runtime
///         gas overhead compared to passing individual addresses in the constructor.
///
/// @dev Contracts inherit this mixin and use whichever fields they need. The full set
///      is resolved from the provider so that adding a new dependency to an existing
///      contract requires no constructor signature change — just start using the field.
///
///      Fields are typed where an interface exists (IOperatorRegistry, IPolicyClientRegistry)
///      and plain address otherwise. Contracts needing the raw address can cast:
///      `address(operatorRegistry)`.
abstract contract AddressesProviderConsumer {
    /// @notice The provider this contract resolved its dependencies from.
    ///         Stored for on-chain verification — callers can confirm which
    ///         provider was used at deploy time.
    INewtonAddressesProvider public immutable addressesProvider;

    address public immutable taskManager;
    IOperatorRegistry public immutable operatorRegistry;
    address public immutable challengeVerifier;
    address public immutable attestationValidator;
    IPolicyClientRegistry public immutable policyClientRegistry;
    address public immutable regoVerifier;
    IViewBN254CertificateVerifier public immutable viewBN254CertificateVerifier;
    address public immutable serviceManager;
    address public immutable socketRegistry;
    address public immutable batchTaskManager;
    IStateRootCommittable public immutable stateCommitRegistry;

    constructor(
        INewtonAddressesProvider _provider
    ) {
        addressesProvider = _provider;
        taskManager = _provider.getTaskManager();
        operatorRegistry = IOperatorRegistry(_provider.getOperatorRegistry());
        challengeVerifier = _provider.getChallengeVerifier();
        attestationValidator = _provider.getAttestationValidator();
        policyClientRegistry = IPolicyClientRegistry(_provider.getPolicyClientRegistry());
        regoVerifier = _provider.getRegoVerifier();
        viewBN254CertificateVerifier =
            IViewBN254CertificateVerifier(_provider.getViewBN254CertificateVerifier());
        serviceManager = _provider.getServiceManager();
        socketRegistry = _provider.getSocketRegistry();
        batchTaskManager = _provider.getBatchTaskManager();
        stateCommitRegistry = IStateRootCommittable(_provider.getStateCommitRegistry());
    }
}
