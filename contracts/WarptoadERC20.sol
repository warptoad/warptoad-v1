// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title WarptoadERC20
 * @notice The wrapped representation of a single ERC-20, minted 1:1 against
 * collateral held by the {Warptoad} vault that deployed it.
 *
 * Supply is controlled exclusively by that vault: it mints on wrap and burns on
 * unwrap, so total supply always equals the collateral the vault is holding.
 */
contract WarptoadERC20 is ERC20 {
    /// @notice The vault that deployed this token and is allowed to mint and burn it.
    address public immutable warptoad;

    /// @notice The token this one is a wrapped representation of.
    address public immutable underlying;

    uint8 private immutable _decimals;

    error OnlyWarptoad(address caller);

    modifier onlyWarptoad() {
        if (msg.sender != warptoad) {
            revert OnlyWarptoad(msg.sender);
        }
        _;
    }

    constructor(address _underlying, string memory _name, string memory _symbol, uint8 _underlyingDecimals)
        ERC20(_name, _symbol)
    {
        warptoad = msg.sender;
        underlying = _underlying;
        _decimals = _underlyingDecimals;
    }

    /// @dev Mirrors the underlying so wrapped balances render at the same scale.
    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    function mint(address to, uint256 value) external onlyWarptoad {
        _mint(to, value);
    }

    /**
     * @dev Burns without an allowance check. The vault is immutable code that only
     * ever burns from the account unwrapping its own balance.
     */
    function burn(address from, uint256 value) external onlyWarptoad {
        _burn(from, value);
    }
}
