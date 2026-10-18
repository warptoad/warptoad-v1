// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev everything about a chain that Warptoad and the wrapper factories need to know about themselves
struct ChainInfo {
    uint64 gigaIndex; // leaf index of this chain in the giga tree
    string chainSymbol; // ex "eth", ends up in wrapper symbols: wtUSDC@eth
    string chainName; // ex "Ethereum", ends up in wrapper names: Wrapped Warptoad USD Coin Ethereum
}

interface IChainConfig {
    /// @notice the entry for `block.chainid`, reverts on an unknown chain
    function info() external view returns (ChainInfo memory);

    /// @notice `info().gigaIndex`
    function gigaIndex() external view returns (uint64);
}
