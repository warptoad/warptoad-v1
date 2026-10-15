// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {WrapperERC20} from "./WrapperERC20.sol";
import {TokenMetadata} from "./libraries/TokenMetadata.sol";
import {IWrapperFactory} from "./interfaces/IWrapperFactory.sol";

import {keccak31Byte} from "./Warptoad.sol";

// TODO rename wrapper factory in warptoad.sol and i protocol to token factory or token minter.
// you can also make a warptoad native token so you never need to deal with wrapping
// this contract obviously is a wrapper tho!
event Wrapped(
    address indexed underlying,
    address wrapper,
    address indexed to,
    uint256 amount
);
event UnWrapped(
    address indexed underlying,
    address wrapper,
    address indexed to,
    uint256 amount
);

/**
 * this guy stores underlying tokens and creates new wrapper tokens
 * @title
 * @author
 * @notice WARNING ONLY DEPLOY WITH CREATE2
 * To unshield the token crosschain, an immutableWrapperFactory needs to be there on the other chain
 * at the SAME ADDRESS. With CREATE2 this is easy to ensure.
 * With regular CREATE from EOA it's easy to fuck up,
 * regular CREATE from contract and bad actors can STEAL FUNDS.
 * Exactly like in the wintermute incident on optmism, but then here every user will be effected
 */
contract WrapperFactory is IWrapperFactory, ReentrancyGuard {
    using SafeERC20 for IERC20;

    mapping(address wrapper => address underlying) underlyings;
    mapping(address underlying => address wrapper) wrappers;

    string symbolPreFix;
    string namePreFix;
    string public chainSymbol;
    string public chainName;

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
    // Maybe wt:USDC@eth, wt:USDC:eth
    function _formatTokenSymbol(
        string memory _baseTokenSymbol
    ) private view returns (string memory) {
        return string.concat(symbolPreFix, _baseTokenSymbol, "@", chainSymbol);
    }

    // Takes a name like "USD Coin " -> "Wrapped Warptoad USD Coin Ethereum"  for example on L1
    function _formatTokenName(
        string memory _baseTokenName
    ) private view returns (string memory) {
        return
            string.concat(
                "Wrapped ",
                namePreFix,
                " ",
                _baseTokenName,
                " ",
                chainName
            );
    }

    function _deploy(address _underlying) private returns (address) {
        // TODO switch statement?
        address wrapper = address(
            new WrapperERC20(
                _underlying,
                _formatTokenName(TokenMetadata.nameOf(_underlying)),
                _formatTokenSymbol(TokenMetadata.symbolOf(_underlying)),
                TokenMetadata.decimalsOf(_underlying)
            )
        );
        underlyings[wrapper] = _underlying;
        wrappers[_underlying] = wrapper;
        return wrapper;
    }

    function _deposit(
        address _underlying,
        address _from,
        uint256 _amount
    ) private {
        IERC20(_underlying).safeTransferFrom(_from, address(this), _amount);
    }

    function _withdraw(
        address _underlying,
        address _to,
        uint256 _amount
    ) private {
        IERC20(_underlying).safeTransfer(_to, _amount);
    }

    function _mint(address _wrapper, address _to, uint256 _amount) private {
        WrapperERC20(_wrapper).mint(_to, _amount);
    }

    function _burn(address _wrapper, address _from, uint256 _amount) private {
        WrapperERC20(_wrapper).burn(_from, _amount);
    }

    // WARNING fee on transfer tokens and rebase tokens dont work here and will be INSOLVENT
    function wrap(
        address _underlying,
        uint256 _amount,
        address _to
    ) external nonReentrant returns (address) {
        address _wrapper = wrappers[_underlying];
        if (_wrapper == address(0)) {
            _wrapper = _deploy(_underlying);
        }
        _deposit(_underlying, msg.sender, _amount);
        _mint(_wrapper, _to, _amount );

        emit Wrapped(_underlying, _wrapper, _to, _amount);
        return _wrapper;
    }

    function unWrap(
        address _wrapper,
        uint256 _amount,
        address _to
    ) external nonReentrant returns (address) {
        address _underlying = underlyings[_wrapper];
        require(
            _underlying != address(0),
            "no underlying token found for this wrapper"
        );

        _burn(_wrapper, msg.sender, _amount);
        _withdraw(_underlying, _to, _amount);

        emit UnWrapped(_underlying, _wrapper, _to, _amount);
        return _underlying;
    }

    function _decodeArgs(bytes memory _wrapperArgs) public returns (address,address, uint256) {
        // Some tokens are deployed to the same address on multiple chains.
        // And since the accounting of our wrapperFactory only stores underlying tokens on one chain,
        // only checking `_underlying` address can cause unexpected scenerarios where users cant unwrap!

        // so we differentiate on which gigaIndex a token was wrapped to enforce "only unwrap on one chain (aka gigaIndex)"
        // that is what`_wrappingOrginIndex` is for. I does not doxx where a user came from and shielded.

        // TODO shrink _wrappingOrginIndex to smaller size then 256

        // both _wrappeer and _underlying here to save on a expensive mapping lookup!
        (address _wrapper, address _underlying, uint256 _wrappingOrginIndex) = abi.decode(_wrapperArgs, (address,address, uint256));
        return (_wrapper, _underlying,_wrappingOrginIndex);
    }

    function _hashArgs(bytes memory _wrapperArgs) public returns (uint256) {
        return keccak31Byte(_wrapperArgs);
    }

    function shield(
        uint256 _amount,
        uint256 _expectedArgHash,
        uint256 ,
        bytes memory _wrapperArgs
    ) external  {
        require(_hashArgs(_wrapperArgs) == _expectedArgHash, "_wrapperArgs mismatch with _expectedArgHash");
        (address _wrapper, , uint256 _wrappingOrginIndex) = _decodeArgs(_wrapperArgs);
        _burn(_wrapper, msg.sender, _amount);
    }

    function unShield(
        address _recipient,
        uint256 _amount,
        uint256 _expectedArgHash,
        uint256 _commitmentHash,
        bytes memory _wrapperArgs
    ) external {
        // wrapper does not exist it always means it was bridged. And the orginal underlying is on another chain
    }
    // TODO make sure to not rely on underlying token is in here to unwrap
    // since some tokens have the same address on multiple chains
    // otherwise you have a accounting headache
    // unshield()
}
