// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

/// @notice Read-only provenance check for policies deployed by a NewtonPolicyFactory.
///         Lets a policy client verify, at composition time, that an address it is
///         about to add to its policy set is a real policy this factory deployed --
///         not an arbitrary contract shaped like one.
interface INewtonPolicyFactoryRegistry {
    function isPolicy(
        address policy
    ) external view returns (bool);
}
