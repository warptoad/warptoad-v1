// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";


contract WrapperERC20 is ERC20 {
    /// @notice The vault that deployed this token and is allowed to mint and burn it.
    address public immutable factory;

    /// @notice The token this one is a wrapped representation of.
    address public immutable underlying;

    uint64 public immutable originGigaIndex;

    uint8 private immutable _decimals;

    error OnlyFactory(address inCorrectCaller);

    modifier onlyFactory() {
        if (msg.sender != factory) {
            revert OnlyFactory(msg.sender);
        }
        _;
    }

    constructor(address _underlying, uint64 _originGigaIndex, string memory _name, string memory _symbol, uint8 _underlyingDecimals)
        ERC20(_name, _symbol)
    {
        originGigaIndex = _originGigaIndex;
        factory = msg.sender;
        underlying = _underlying;
        _decimals = _underlyingDecimals;
    }

    /// @dev Mirrors the underlying so wrapped balances render at the same scale.
    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    function mint(address to, uint256 value) external onlyFactory {
        _mint(to, value);
    }

    /**
     * @dev Burns without an allowance check. The vault is immutable code that only
     * ever burns from the account unwrapping its own balance.
     */
    function burn(address from, uint256 value) external onlyFactory {
        _burn(from, value);
    }
}
