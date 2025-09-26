// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.27;

library ChainLib {
    error ChainNotSupported(uint256 chainId);

    // NOTE: make sure to use with requireSupportedChain modifier
    function isMainnet() internal view returns (bool) {
        uint256 chainId = block.chainid;
        return chainId == 1 // Ethereum mainnet
            || chainId == 10 // Optimism mainnet
            || chainId == 42161 // Arbitrum One mainnet
            || chainId == 137 // Polygon mainnet
            || chainId == 8453; // Base mainnet
    }

    // NOTE: make sure to use with requireSupportedChain modifier
    function isTestnet() internal view returns (bool) {
        uint256 chainId = block.chainid;
        return chainId == 11155111 // Sepolia testnet
            || chainId == 17000 // Holesky testnet
            || chainId == 84532 // Base Sepolia testnet
            || chainId == 11155420 // Optimism Sepolia testnet
            || chainId == 421614 // Arbitrum One Sepolia testnet
            || chainId == 80002; // Polygon Amoy testnet
    }

    // NOTE: make sure to use with requireSupportedChain modifier
    function isLocal() internal view returns (bool) {
        return block.chainid == 31337;
    }

    function isSupportedChain() internal view returns (bool) {
        return isMainnet() || isTestnet() || isLocal();
    }

    function requireSupportedChain() internal view {
        require(isSupportedChain(), ChainNotSupported(block.chainid));
    }
}
