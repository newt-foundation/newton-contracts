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
            || chainId == 84532 // Base Sepolia testnet
            || chainId == 11155420 // Optimism Sepolia testnet
            || chainId == 421614 // Arbitrum One Sepolia testnet
            || chainId == 80002; // Polygon Amoy testnet
    }

    // NOTE: make sure to use with requireSupportedChain modifier
    function isLocal() internal view returns (bool) {
        return block.chainid == 31337 || block.chainid == 31338;
    }

    /// @notice Returns true if the chain is a local chain
    /// @dev Static version for use with explicit chain ID parameter
    function isLocalStatic(
        uint256 chainId
    ) internal pure returns (bool) {
        return chainId == 31337 || chainId == 31338;
    }

    function isSupportedChain() internal view returns (bool) {
        return isMainnet() || isTestnet() || isLocal();
    }

    function requireSupportedChain() internal view {
        require(isSupportedChain(), ChainNotSupported(block.chainid));
    }

    // =============================================================
    //                    SOURCE CHAIN DETECTION
    // =============================================================

    /// @notice Returns true if the chain is a source chain (has EigenLayer core contracts)
    /// @dev Source chains are Ethereum mainnet, Sepolia testnet, and local anvil.
    ///      These chains have EigenLayer's AllocationManager, KeyRegistrar, etc.
    function isSourceChain() internal view returns (bool) {
        uint256 chainId = block.chainid;
        return chainId == 1 // Ethereum mainnet
            || chainId == 11155111 // Sepolia testnet
            || chainId == 31337; // Local anvil (for testing)
    }

    /// @notice Returns true if the chain is a source chain (has EigenLayer core contracts)
    /// @dev Static version for use with explicit chain ID parameter
    function isSourceChain(
        uint256 chainId
    ) internal pure returns (bool) {
        return chainId == 1 // Ethereum mainnet
            || chainId == 11155111 // Sepolia testnet
            || chainId == 31337; // Local anvil (for testing)
    }

    /// @notice Returns true if the chain requires Newton-managed CrossChainRegistry
    /// @dev These are destination chains where EigenLayer's Generator doesn't operate.
    ///      EigenLayer-supported destinations (Base) use EigenLayer's CrossChainRegistry instead.
    function requiresNewtonCrossChainRegistry() internal view returns (bool) {
        return !isSourceChain() && isSupportedChain() && !isEigenLayerSupportedDestination();
    }

    /// @notice Returns true if the chain requires Newton-managed CrossChainRegistry
    /// @dev Static version for use with explicit chain ID parameter.
    ///      EigenLayer-supported destinations (Base) use EigenLayer's CrossChainRegistry instead.
    function requiresNewtonCrossChainRegistry(
        uint256 chainId
    ) internal pure returns (bool) {
        return !isSourceChain(chainId) && isSupportedChainStatic(chainId)
            && !isEigenLayerSupportedDestination(chainId);
    }

    // =============================================================
    //                  EIGENLAYER DESTINATION SUPPORT
    // =============================================================

    /// @notice Returns true if the chain is an EigenLayer-supported destination
    /// @dev EigenLayer's Generator service only operates on Base and Base Sepolia.
    ///      These chains have permissionless GlobalTableRoot confirmation via Generator.
    ///      All other destinations require owner-controlled updates (ECDSAOperatorTableUpdater).
    function isEigenLayerSupportedDestination() internal view returns (bool) {
        return isEigenLayerSupportedDestination(block.chainid);
    }

    /// @notice Returns true if the chain is an EigenLayer-supported destination
    /// @dev Static version for use with explicit chain ID parameter
    function isEigenLayerSupportedDestination(
        uint256 chainId
    ) internal pure returns (bool) {
        return chainId == 8453 // Base mainnet
            || chainId == 84532; // Base Sepolia testnet
    }

    /// @notice Returns true if the chain requires ECDSA-based operator table updates
    /// @dev Non-EL destinations and local chains need ECDSAOperatorTableUpdater
    ///      because EigenLayer's Generator service is not available.
    function requiresECDSAOperatorTableUpdater() internal view returns (bool) {
        return requiresECDSAOperatorTableUpdater(block.chainid);
    }

    /// @notice Returns true if the chain requires ECDSA-based operator table updates
    /// @dev Static version for use with explicit chain ID parameter
    function requiresECDSAOperatorTableUpdater(
        uint256 chainId
    ) internal pure returns (bool) {
        // Local chains always use ECDSA for testing flexibility
        if (chainId == 31337 || chainId == 31338) {
            return true;
        }
        // Non-EL supported destinations need ECDSA (no Generator available)
        return !isEigenLayerSupportedDestination(chainId) && !isSourceChain(chainId);
    }

    /// @notice Static version of isSupportedChain for use with explicit chain ID
    function isSupportedChainStatic(
        uint256 chainId
    ) internal pure returns (bool) {
        return isMainnetStatic(chainId) || isTestnetStatic(chainId) || isLocalStatic(chainId);
    }

    /// @notice Static version of isMainnet
    function isMainnetStatic(
        uint256 chainId
    ) internal pure returns (bool) {
        return chainId == 1 // Ethereum mainnet
            || chainId == 10 // Optimism mainnet
            || chainId == 42161 // Arbitrum One mainnet
            || chainId == 137 // Polygon mainnet
            || chainId == 8453; // Base mainnet
    }

    /// @notice Static version of isTestnet
    function isTestnetStatic(
        uint256 chainId
    ) internal pure returns (bool) {
        return chainId == 11155111 // Sepolia testnet
            || chainId == 84532 // Base Sepolia testnet
            || chainId == 11155420 // Optimism Sepolia testnet
            || chainId == 421614 // Arbitrum One Sepolia testnet
            || chainId == 80002; // Polygon Amoy testnet
    }

    // =============================================================
    //                   SOURCE CHAIN ID DERIVATION
    // =============================================================

    /// @notice Returns the source chain ID for the current chain
    /// @dev Used by destination chains to determine which source chain to read deployments from.
    ///      - Source chains return themselves
    ///      - Local destination (31338) returns local source (31337)
    ///      - Testnet destinations return Sepolia (11155111)
    ///      - Mainnet destinations return Ethereum (1)
    function getSourceChainId() internal view returns (uint256) {
        return getSourceChainId(block.chainid);
    }

    /// @notice Returns the source chain ID for a given chain
    /// @dev Static version for use with explicit chain ID parameter
    /// @param chainId The chain ID to derive source chain for
    /// @return sourceChainId The corresponding source chain ID
    function getSourceChainId(
        uint256 chainId
    ) internal pure returns (uint256 sourceChainId) {
        // Source chains return themselves
        if (isSourceChain(chainId)) {
            return chainId;
        }

        // Local destination (31338) derives from local source (31337)
        if (chainId == 31338) {
            return 31337;
        }

        // Testnet destinations derive from Sepolia
        if (isTestnetStatic(chainId)) {
            return 11155111;
        }

        // Mainnet destinations derive from Ethereum
        if (isMainnetStatic(chainId)) {
            return 1;
        }

        // Unsupported chain - revert
        revert ChainNotSupported(chainId);
    }
}
