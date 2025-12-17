// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {MockToken} from "../mock/MockToken.sol";
import {ChainLib} from "../../src/libraries/ChainLib.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";

library FundOperator {
    function fundOperator(
        address erc20,
        address operator,
        uint256 amount
    ) internal {
        ChainLib.requireSupportedChain();
        if (ChainLib.isMainnet()) {
            require(IERC20(erc20).transfer(operator, amount), "ERC20 transfer failed");
        } else {
            MockToken tokenContract = MockToken(erc20);
            tokenContract.mint(operator, amount);
        }
    }
}
