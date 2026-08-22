// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {ERC1155Holder} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {WarptoadERC20} from "./WarptoadERC20.sol";
import {WarptoadERC1155} from "./WarptoadERC1155.sol";
import {TokenMetadata} from "./libraries/TokenMetadata.sol";

contract Warptoad is ERC1155Holder, ReentrancyGuard {
    using SafeERC20 for IERC20;

    string symbolPreFix;
    string namePreFix;
    string chainSymbol;
    string chainName;

    /// @notice Wrapper token deployed for an underlying ERC-20, or zero if never wrapped.
    mapping(address underlying => address wrapper) public erc20WrapperOf;

    /// @notice Wrapper collection deployed for an underlying ERC-1155, or zero if never wrapped.
    mapping(address underlying => address wrapper) public erc1155WrapperOf;

    /// @notice Underlying a wrapper redeems for. Non-zero exactly for tokens this vault deployed.
    mapping(address wrapper => address underlying) public underlyingOf;

    event ERC20WrapperCreated(address indexed underlying, address indexed wrapper);
    event ERC1155WrapperCreated(address indexed underlying, address indexed wrapper);
    event ERC20Wrapped(address indexed underlying, address indexed wrapper, address indexed to, uint256 amount);
    event ERC20Unwrapped(address indexed underlying, address indexed wrapper, address indexed to, uint256 amount);
    event ERC1155Wrapped(
        address indexed underlying, address indexed wrapper, address indexed to, uint256 id, uint256 amount
    );
    event ERC1155Unwrapped(
        address indexed underlying, address indexed wrapper, address indexed to, uint256 id, uint256 amount
    );

    /// @dev Thrown when unwrapping a token this vault did not issue, or issued for the other standard.
    error NotAWrapper(address token);
    error ZeroAmount();
    error ZeroAddress();

    constructor(
        string memory _symbolPreFix,
        string memory _namePreFix,
        string memory _chainSymbol,
        string memory _chainName
    ) {
        symbolPreFix = _symbolPreFix;
        namePreFix = _namePreFix;
        chainSymbol = _chainSymbol;
        chainName = _chainName;
    }

    // Takes a symbol like USDC -> wtUSDC@eth for example on L1
    function _getTokenSymbol(string memory _baseTokenSymbol) private view returns (string memory) {
        return string.concat(symbolPreFix, _baseTokenSymbol, "@", chainSymbol);
    }

    // Takes a name like "USD Coin " -> "Wrapped Warptoad USD Coin Ethereum"  for example on L1
    function _getTokenName(string memory _baseTokenName) private view returns (string memory) {
        return string.concat("Wrapped ", namePreFix, " ", _baseTokenName, " ", chainName);
    }

    // --- ERC-20 ---------------------------------------------------------------

    /**
     * `_amount` is deposited here and `_to` receives wrapped token as claim on this deposit
     * @notice Creates a new wrapper token contract from a openzeppelin clone factory 
     * if it does not exist yet
     * @return wrapper The wrapper token minted.
     * @return minted Amount minted, which can differ from _amount on some tokens 
     * like fee on transfer tokens.
     */
    function wrapERC20(address _token, uint256 _amount, address _to)
        external
        nonReentrant
        returns (address wrapper, uint256 minted)
    {
        wrapper = _getOrCreateERC20Wrapper(_token);

        // Check before balance to deal with fee on transfer tokens causing insolvency
        uint256 balanceBefore = IERC20(_token).balanceOf(address(this));
        IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
        minted = IERC20(_token).balanceOf(address(this)) - balanceBefore;

        WarptoadERC20(wrapper).mint(_to, minted);
        emit ERC20Wrapped(_token, wrapper, _to, minted);
    }

    /**
     * @notice Burns `_amount` of `_wrapper` from the caller and releases the same
     * amount of underlying collateral to `_to`.
     * @return token The underlying released.
     */
    function unwrapERC20(address _wrapper, uint256 _amount, address _to)
        external
        nonReentrant
        returns (address token)
    {
        token = underlyingOf[_wrapper];
        if (token == address(0) || erc20WrapperOf[token] != _wrapper) revert NotAWrapper(_wrapper);

        WarptoadERC20(_wrapper).burn(msg.sender, _amount);
        IERC20(token).safeTransfer(_to, _amount);

        emit ERC20Unwrapped(token, _wrapper, _to, _amount);
    }

    /**
     * automatically deploy a wrapper contract clone if it does not exist yet
     * @param _token which underlying to wrap
     */
    function _getOrCreateERC20Wrapper(address _token) private returns (address wrapper) {
        wrapper = erc20WrapperOf[_token];
        if (wrapper != address(0)) return wrapper;

        // deploy the contract
        wrapper = address(
            new WarptoadERC20(
                _token,
                _getTokenName(TokenMetadata.nameOf(_token)),
                _getTokenSymbol(TokenMetadata.symbolOf(_token)),
                TokenMetadata.decimalsOf(_token)
            )
        );

        erc20WrapperOf[_token] = wrapper;
        underlyingOf[wrapper] = _token;
        emit ERC20WrapperCreated(_token, wrapper);
    }

    // --- ERC-1155 -------------------------------------------------------------

    /**
     * `_amount` of the `_id` is deposited here and _to receives wrapped token as claim on this deposit
     * @notice Creates a new wrapper token contract from a openzeppelin clone factory 
     * if it does not exist yet
     * @return wrapper The wrapper collection minted.
     */
    function wrapERC1155(address _collection, uint256 _id, uint256 _amount, address _to)
        external
        nonReentrant
        returns (address wrapper)
    {
        wrapper = _getOrCreateERC1155Wrapper(_collection);

        IERC1155(_collection).safeTransferFrom(msg.sender, address(this), _id, _amount, "");
        WarptoadERC1155(wrapper).mint(_to, _id, _amount);

        emit ERC1155Wrapped(_collection, wrapper, _to, _id, _amount);
    }

    /**
     * @notice Burns `_amount` of `_wrapper`'s token `_id` from the caller and
     * releases the underlying collateral to `_to`.
     * @return collection The underlying collection released.
     */
    function unwrapERC1155(address _wrapper, uint256 _id, uint256 _amount, address _to)
        external
        nonReentrant
        returns (address collection)
    {
        collection = underlyingOf[_wrapper];
        if (collection == address(0) || erc1155WrapperOf[collection] != _wrapper) revert NotAWrapper(_wrapper);

        WarptoadERC1155(_wrapper).burn(msg.sender, _id, _amount);
        IERC1155(collection).safeTransferFrom(address(this), _to, _id, _amount, "");

        emit ERC1155Unwrapped(collection, _wrapper, _to, _id, _amount);
    }

    /**
     * @dev ERC-1155 has no standard name/symbol, so both are read best-effort from
     * the collection and fall back to its address.
     */
    function _getOrCreateERC1155Wrapper(address _collection) private returns (address wrapper) {
        wrapper = erc1155WrapperOf[_collection];
        if (wrapper != address(0)) return wrapper;

        wrapper = address(
            new WarptoadERC1155(
                _collection,
                _getTokenName(TokenMetadata.nameOf(_collection)),
                _getTokenSymbol(TokenMetadata.symbolOf(_collection))
            )
        );

        erc1155WrapperOf[_collection] = wrapper;
        underlyingOf[wrapper] = _collection;
        emit ERC1155WrapperCreated(_collection, wrapper);
    }
}
