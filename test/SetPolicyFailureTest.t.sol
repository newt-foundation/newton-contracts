// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/* solhint-disable no-console */

import "forge-std/Test.sol";
import "forge-std/console.sol";
import {NewtonPolicy} from "../src/core/NewtonPolicy.sol";
import {NewtonPolicyFactory} from "../src/core/NewtonPolicyFactory.sol";
import {INewtonPolicy} from "../src/interfaces/INewtonPolicy.sol";
import {INewtonPolicyClient} from "../src/interfaces/INewtonPolicyClient.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

// Mock contract that does NOT implement INewtonPolicyClient (should fail)
contract InvalidCaller {
    function supportsInterface(
        bytes4 interfaceId
    ) external pure returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
        // Deliberately NOT supporting INewtonPolicyClient
    }

    function callSetPolicy(
        address policyContract,
        INewtonPolicy.PolicyConfig memory config
    ) external returns (bytes32) {
        return NewtonPolicy(policyContract).setPolicy(config);
    }
}

// Mock contract that implements INewtonPolicyClient (should succeed)
contract ValidCaller {
    function supportsInterface(
        bytes4 interfaceId
    ) external pure returns (bool) {
        return interfaceId == type(IERC165).interfaceId
            || interfaceId == type(INewtonPolicyClient).interfaceId;
    }

    function callSetPolicy(
        address policyContract,
        INewtonPolicy.PolicyConfig memory config
    ) external returns (bytes32) {
        return NewtonPolicy(policyContract).setPolicy(config);
    }
}

contract SetPolicyFailureTest is Test {
    NewtonPolicy public policy;
    NewtonPolicyFactory public factory;
    address public owner = address(0x123);

    // The exact policy data from the failed transaction
    bytes public constant POLICY_PARAMS =
        hex"7b0a20202261646d696e223a2022307866333966643665353161616438386636663463653661623838323732373963666666623932323636222c0a202022616c6c6f7765645f616374696f6e73223a207b0a20202020223331333337223a207b0a2020202020202261646472657373223a2022307838663836343033613464653062623537393166613436623865373935633534373934326665346366222c0a2020202020202266756e6374696f6e5f6e616d65223a2022627579222c0a202020202020226d61785f6c696d6974223a20313030303030303030303030303030303030300a202020207d2c0a20202020223131313535313131223a207b0a2020202020202261646472657373223a2022307838663836343033613464653062623537393166613436623865373935633534373934326665346366222c0a2020202020202266756e6374696f6e5f6e616d65223a2022627579222c0a202020202020226d61785f6c696d6974223a20313030303030303030303030303030303030300a202020207d0a20207d2c0a202022746f6b656e5f77686974656c697374223a207b0a20202020223331333337223a207b0a2020202020202261646472657373223a2022307838663836343033613464653062623537393166613436623865373935633534373934326665346366222c0a202020202020226d61785f6c696d6974223a20313030303030303030303030303030303030302c0a2020202020202273796d626f6c223a20224e455754220a202020207d2c0a20202020223131313535313131223a207b0a2020202020202261646472657373223a2022307832396632443430423036303532303433363461663534454336373762443032326441343235643033222c0a202020202020226d61785f6c696d6974223a20313030303030303030303030303030303030302c0a2020202020202273796d626f6c223a202257425443220a202020207d0a20207d0a7d0a";
    uint32 public constant EXPIRE_AFTER = 100;

    function setUp() public {
        // For this test, we don't need a real factory, just a mock address
        address mockFactory = address(0x999);

        // Deploy policy contract
        policy = new NewtonPolicy();

        // Initialize policy
        address[] memory policyData = new address[](0);
        policy.initialize(
            mockFactory,
            "test-entrypoint",
            "test-policy-uri",
            "test-schema-uri",
            policyData,
            "test-metadata-uri",
            owner
        );

        console.log("=== Setup Complete ===");
        console.log("Policy contract deployed at:", address(policy));
        console.log("Owner:", owner);
    }

    function testDirectCallFromEOAFails() public {
        console.log("\n=== Test 1: Direct call from EOA should fail ===");

        INewtonPolicy.PolicyConfig memory config =
            INewtonPolicy.PolicyConfig({policyParams: POLICY_PARAMS, expireAfter: EXPIRE_AFTER});

        // This should fail because msg.sender (test contract) is not a proper policy client
        vm.expectRevert();
        policy.setPolicy(config);

        console.log("SUCCESS: Direct EOA call failed as expected");
    }

    function testCallFromInvalidContractFails() public {
        console.log("\n=== Test 2: Call from invalid contract should fail ===");

        InvalidCaller invalidCaller = new InvalidCaller();
        console.log("Invalid caller deployed at:", address(invalidCaller));

        INewtonPolicy.PolicyConfig memory config =
            INewtonPolicy.PolicyConfig({policyParams: POLICY_PARAMS, expireAfter: EXPIRE_AFTER});

        // This should fail with InterfaceNotSupported error
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("InterfaceNotSupported()"))));
        invalidCaller.callSetPolicy(address(policy), config);

        console.log("SUCCESS: Invalid contract call failed as expected");
    }

    function testCallFromValidContractSucceeds() public {
        console.log("\n=== Test 3: Call from valid contract should succeed ===");

        ValidCaller validCaller = new ValidCaller();
        console.log("Valid caller deployed at:", address(validCaller));

        INewtonPolicy.PolicyConfig memory config =
            INewtonPolicy.PolicyConfig({policyParams: POLICY_PARAMS, expireAfter: EXPIRE_AFTER});

        // This should succeed
        bytes32 policyId = validCaller.callSetPolicy(address(policy), config);

        console.log("SUCCESS: Valid contract call succeeded");
        console.log("Policy ID:", vm.toString(policyId));

        // Verify the policy was stored
        assertNotEq(policyId, bytes32(0), "Policy ID should not be zero");

        // Check that the policy was registered for the caller
        bytes32 storedPolicyId = policy.getPolicyId(address(validCaller));
        assertEq(storedPolicyId, policyId, "Stored policy ID should match returned ID");
    }

    function testManualModifierChecks() public {
        console.log("\n=== Test 4: Manual modifier validation ===");

        // Check the modifier logic step by step
        bytes4 policyClientInterfaceId = type(INewtonPolicyClient).interfaceId;
        console.log("INewtonPolicyClient interface ID:");
        console.logBytes4(policyClientInterfaceId);

        // Test EOA-like caller (this test contract)
        console.log("\n--- Testing EOA-like caller ---");
        _checkModifierLogic(address(this));

        // Test invalid contract
        InvalidCaller invalidCaller = new InvalidCaller();
        console.log("\n--- Testing invalid contract ---");
        _checkModifierLogic(address(invalidCaller));

        // Test valid contract
        ValidCaller validCaller = new ValidCaller();
        console.log("\n--- Testing valid contract ---");
        _checkModifierLogic(address(validCaller));
    }

    function _checkModifierLogic(
        address caller
    ) internal view {
        console.log("Checking caller:", caller);

        // Check 1: msg.sender.code.length > 0
        uint256 codeSize = caller.code.length;
        console.log("  Code size:", codeSize);

        if (codeSize == 0) {
            console.log("  FAIL: Line 36 - require(msg.sender.code.length > 0, OnlyPolicyClient())");
            return;
        }
        console.log("  PASS: Line 36 - Caller has code");

        // Check 2: supportsInterface
        bytes4 interfaceId = type(INewtonPolicyClient).interfaceId;

        try IERC165(caller).supportsInterface(interfaceId) returns (bool result) {
            console.log("  supportsInterface call result:", result);
            if (!result) {
                console.log("  FAIL: Line 44-46 - Interface not supported");
            } else {
                console.log("  PASS: Line 44-46 - Interface supported");
            }
        } catch {
            console.log("  FAIL: Line 44-46 - supportsInterface call failed");
        }
    }

    function testShowExactErrorLocation() public {
        console.log("\n=== Test 5: Identify exact error location ===");

        // Test scenario 1: EOA call (should fail at line 36)
        console.log("--- Scenario 1: Direct call (line 36 check) ---");
        INewtonPolicy.PolicyConfig memory config =
            INewtonPolicy.PolicyConfig({policyParams: POLICY_PARAMS, expireAfter: EXPIRE_AFTER});

        try policy.setPolicy(config) {
            console.log("UNEXPECTED: Call succeeded");
        } catch (bytes memory errorData) {
            _decodeAndLogError(errorData, "Direct call from test contract");
        }

        // Test scenario 2: Invalid contract call (should fail at line 44-46)
        console.log("\n--- Scenario 2: Invalid contract (line 44-46 check) ---");
        InvalidCaller invalidCaller = new InvalidCaller();

        try invalidCaller.callSetPolicy(address(policy), config) {
            console.log("UNEXPECTED: Call succeeded");
        } catch (bytes memory errorData) {
            _decodeAndLogError(errorData, "Invalid contract call");
        }
    }

    function _decodeAndLogError(bytes memory errorData, string memory scenario) internal pure {
        console.log("Error in scenario:", scenario);
        if (errorData.length >= 4) {
            bytes4 errorSelector = bytes4(errorData);
            console.log("Error selector:");
            console.logBytes4(errorSelector);

            bytes4 onlyPolicyClientSelector = bytes4(keccak256("OnlyPolicyClient()"));
            bytes4 interfaceNotSupportedSelector = bytes4(keccak256("InterfaceNotSupported()"));

            if (errorSelector == onlyPolicyClientSelector) {
                console.log("IDENTIFIED ERROR: OnlyPolicyClient() - FAILED AT LINE 36");
                console.log("  File: NewtonPolicy.sol");
                console.log("  Line: 36");
                console.log("  Code: require(msg.sender.code.length > 0, OnlyPolicyClient());");
                console.log("  Reason: Caller has no code (is an EOA or externally owned account)");
            } else if (errorSelector == interfaceNotSupportedSelector) {
                console.log("IDENTIFIED ERROR: InterfaceNotSupported() - FAILED AT LINE 44-46");
                console.log("  File: NewtonPolicy.sol");
                console.log("  Lines: 44-46");
                console.log(
                    "  Code: require(success && result.length == 32 && abi.decode(result, (bool)), InterfaceNotSupported());"
                );
                console.log(
                    "  Reason: Caller contract doesn't implement INewtonPolicyClient interface"
                );
            } else {
                console.log("UNKNOWN ERROR: Selector not recognized");
            }
        } else {
            console.log("ERROR: Invalid error data length");
        }
    }
}
