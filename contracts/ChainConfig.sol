// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IChainConfig, ChainInfo} from "./interfaces/IChainConfig.sol";

/**
 * @title ChainConfig
 * @notice chainId => ChainInfo lookup, read by Warptoad and the wrapper factories in their constructors so none of
 * them need chain specific constructor args. That keeps their init code identical on every chain, which is what
 * lets CREATE2 put them on the same address everywhere.
 * @dev deploy this with CREATE2 and the exact same table on every chain, otherwise its own address differs and
 * everything downstream does too. The table is provided by the constructor, see `chainConfigArgs` in src/config.ts.
 * A chain missing from the table makes `info()` revert, so a deploy on an unlisted chain fails loudly instead of
 * silently getting gigaIndex 0
 */
contract ChainConfig is IChainConfig {
    mapping(uint256 chainId => ChainInfo) private infos;

    error LengthMismatch(uint256 chainIds, uint256 infos);
    error EmptyChainName(uint256 chainId);
    error DuplicateChainId(uint256 chainId);
    error UnknownChain(uint256 chainId);

    constructor(uint256[] memory _chainIds, ChainInfo[] memory _infos) {
        if (_chainIds.length != _infos.length)
            revert LengthMismatch(_chainIds.length, _infos.length);
        for (uint256 i = 0; i < _chainIds.length; i++) {
            // an empty name doubles as the "unknown" sentinel in `info`
            if (bytes(_infos[i].chainName).length == 0)
                revert EmptyChainName(_chainIds[i]);
            if (bytes(infos[_chainIds[i]].chainName).length != 0)
                revert DuplicateChainId(_chainIds[i]);
            infos[_chainIds[i]] = _infos[i];
        }
    }

    function info() public view returns (ChainInfo memory) {
        ChainInfo memory _info = infos[block.chainid];
        if (bytes(_info.chainName).length == 0)
            revert UnknownChain(block.chainid);
        return _info;
    }

    function gigaIndex() external view returns (uint64) {
        return info().gigaIndex;
    }

    /// @notice the entry for any chain, for off-chain tooling. Reverts on an unknown chain
    function infoOf(uint256 _chainId) external view returns (ChainInfo memory) {
        ChainInfo memory _info = infos[_chainId];
        if (bytes(_info.chainName).length == 0) revert UnknownChain(_chainId);
        return _info;
    }
}
