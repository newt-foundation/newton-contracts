// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

/// @dev Domain separator for the policy-set id hash. Prevents a policy-set
///      commitment from colliding with a hash computed for an unrelated purpose
///      over the same encoded fields.
bytes32 constant POLICY_SET_DOMAIN = keccak256("newton.policy.set");

/// @dev Upper bound on the number of policies a client may compose into one set.
///      Bounds the loop in `_setPolicies` and everywhere a policy set is iterated
///      at task admission or challenge time, so gas scales with a known constant
///      rather than an integrator-chosen length.
uint256 constant MAX_POLICIES = 8;

/// @dev Upper bound, in bytes, on a single user-controlled policy field
///      (e.g. `policyParams`, a WASM input entry). Without this a policy client
///      or task submitter can size these arbitrarily, since they are copied into
///      calldata and storage before any policy logic runs.
uint256 constant MAX_POLICY_FIELD_BYTES = 65536;

/// @dev Upper bound, in bytes, on the aggregate policy-related payload of a
///      single task (summed across all per-policy fields). Caps total task
///      admission cost independent of how the per-field bytes are distributed
///      across the policy set.
uint256 constant MAX_TASK_POLICY_BYTES = 262144;

/// @dev Upper bound, in bytes, on the aggregate policy payload of a task *response*.
///      The response carries everything admission bounded (`policyParams`, oracle
///      inputs) plus two fields admission cannot see: the resolved Rego module and the
///      oracle output. Sized as the admission budget plus the worst case for those two,
///      so a task that passed `requirePolicyDataBounds` can never fail this — admission
///      mechanically implies settlement, and no submitter burns an evaluation round on a
///      response-only bounds revert.
uint256 constant MAX_RESPONSE_POLICY_BYTES =
    MAX_TASK_POLICY_BYTES + MAX_POLICIES * 2 * MAX_POLICY_FIELD_BYTES;
