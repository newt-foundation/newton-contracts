// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

library ChainLib {
    function isMainnet() internal view returns (bool) {
        return block.chainid == 1 // Ethereum mainnet
            || block.chainid == 10 // Optimism mainnet
            || block.chainid == 42161 // Arbitrum One mainnet
            || block.chainid == 137 // Polygon mainnet
            || block.chainid == 8453; // Base mainnet
    }

    function isTestnet() internal view returns (bool) {
        return block.chainid == 11155111 // Sepolia testnet
            || block.chainid == 17000 // Holesky testnet
            || block.chainid == 84532 // Base Sepolia testnet
            || block.chainid == 11155420 // Optimism Sepolia testnet
            || block.chainid == 421614 // Arbitrum One Sepolia testnet
            || block.chainid == 80002; // Polygon Amoy testnet
    }

    function isLocal() internal view returns (bool) {
        return block.chainid == 31337; // Hardhat localnet
    }
}
