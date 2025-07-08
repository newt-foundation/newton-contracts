// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

/**
 * @title TaskEvaluationLib
 * @dev Library for task evaluation and result processing
 */
library TaskEvaluationLib {
    /**
     * @dev Evaluates the result of a task execution
     * @param evaluationResult The result data to evaluate
     * @return bool True if the result indicates success/true
     */
    function evaluateResult(
        bytes memory evaluationResult
    ) external pure returns (bool) {
        uint256 length = evaluationResult.length;

        // Case 1: ABI-encoded bool true (32 bytes)
        if (length == 32) {
            uint256 val;
            assembly {
                val := mload(add(evaluationResult, 32))
            }
            return val == 1;
        }

        // Case 2: ABI-encoded "true" string (96+ bytes)
        if (length >= 96) {
            uint256 strLen;
            assembly {
                strLen := mload(add(evaluationResult, 64))
            }
            if (strLen == 4) {
                bytes32 strData;
                assembly {
                    strData := mload(add(evaluationResult, 96))
                }
                return strData == 0x7472756500000000000000000000000000000000000000000000000000000000;
            }
        }

        return false;
    }
}
